#include "PacketFilter.h"
#include "LogDevice.h"

int check_special_cases(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, __u8 protocol, struct sk_buff *skb){
	struct tcphdr *tcp_header;
	if((src_ip & 0xFF000000) == 0x7F000000 && (dst_ip & 0xFF000000) == 0x7F000000){ /*loopback packet*/
		return 1;
	}
	if(protocol == PROT_OTHER){ /*non TCP/UDP/ICMP packet*/
		return 1;
	}

	if(protocol == PROT_TCP){ /*checking for xmas packet*/
		tcp_header = tcp_hdr(skb);
		if(tcp_header->urg && tcp_header->fin && tcp_header->psh){
			return -1;
		}
	}
	return 0;
}

int stateless_filter(direction_t packet_direction, __be32 packet_src_ip, __be32 packet_dst_ip, __be16 packet_src_port, __be16 packet_dst_port, __u8 packet_protocol, ack_t packet_ack, log_row_t *log_row){
	rule_t *rule_table;
	int i;
	rule_table = get_rule_table();
	// print packet info
	// printk(KERN_INFO "Packet info: src_ip: %u, dst_ip: %u, src_port: %hu, dst_port: %hu, protocol: %hhu, ack: %hhu\n", packet_src_ip, packet_dst_ip, packet_src_port, packet_dst_port, packet_protocol, packet_ack);
	// printk(KERN_INFO "Packet direction: %d\n", packet_direction);
	for(i = 0; i < get_rule_table_size(); i++){
		if(check_for_match(rule_table + i, packet_direction, packet_src_ip, packet_dst_ip, packet_src_port, packet_dst_port, packet_protocol, packet_ack)){
			log_it(log_row, i, (rule_table + i)->action);
			return (rule_table + i)->action;
		}
	}
	log_it(log_row, REASON_NO_MATCHING_RULE, NF_DROP);
	return NF_DROP;
}

unsigned int filter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
	struct iphdr *ip_header;
	struct tcphdr *tcp_header;
	struct udphdr *udp_header;
	log_row_t log_row;
	tcp_packet_t packet_type;
	rule_t *rule_table;
	proxy_entry_t *proxy_conn;

	direction_t packet_direction;
	__be32	packet_src_ip;
	__be32	packet_dst_ip;
	__be16	packet_src_port; 			  
	__be16	packet_dst_port; 			 
	__u8	packet_protocol; 			
	ack_t	packet_ack;

	if(!skb){
		return NF_ACCEPT;
	}

	set_packet_direction(skb, &packet_direction, state);
	ip_header = ip_hdr(skb);
	packet_src_ip = ip_header->saddr;
	packet_dst_ip = ip_header->daddr;
	packet_protocol = ip_header->protocol;
	set_packet_src_and_dst_ports(skb, &packet_src_port, &packet_dst_port);
	set_log_address_and_protocol(&log_row, packet_src_ip, packet_dst_ip, packet_src_port, packet_dst_port, packet_protocol);
	if(packet_protocol == PROT_TCP){
		tcp_header = tcp_hdr(skb);
		packet_ack = tcp_header->ack ? ACK_YES : ACK_NO;
	}

	int special_case = check_special_cases(packet_src_ip, packet_dst_ip, packet_src_port, packet_dst_port, packet_protocol, skb);
	if(special_case == 1){
		return NF_ACCEPT;
	}
	if(special_case == -1){
		log_it(&log_row, REASON_XMAS_PACKET, NF_DROP);
		return NF_DROP;
	}

	if(is_rule_table_valid() == 0 || get_rule_table_size() == 0){
		log_it(&log_row, REASON_FW_INACTIVE, NF_ACCEPT);
		return NF_ACCEPT;
	}

	if(packet_protocol != PROT_TCP){
		return stateless_filter(packet_direction, packet_src_ip, packet_dst_ip, packet_src_port, packet_dst_port, packet_protocol, packet_ack, &log_row);
	}

	__u8 action = validate_TCP_packet(tcp_header, packet_src_ip, packet_dst_ip, packet_src_port, packet_dst_port, packet_direction, &log_row);

	// we need to check if the packet is a proxy packet
	proxy_conn = find_proxy_connection(packet_src_ip, packet_src_port, packet_dst_ip, packet_dst_port);
	if(proxy_conn != NULL){
		reroute_packet(skb, proxy_conn->proxy_port, packet_direction);
	}

	if(action == NF_ACCEPT){
		printk(KERN_INFO "4: Packet accepted\n");
	}
	else{
		printk(KERN_INFO "4: Packet dropped\n");
	}

	return action;
}

void set_packet_direction(struct sk_buff *skb, direction_t *direction, const struct nf_hook_state *state){
	char *in_device_name = state->in->name;
	char *out_device_name = state->out->name;

	if(strcmp(in_device_name, IN_NET_DEVICE_NAME) == 0 && strcmp(out_device_name, OUT_NET_DEVICE_NAME) == 0){
		*direction = DIRECTION_OUT;
	}
	else if(strcmp(in_device_name, OUT_NET_DEVICE_NAME) == 0 && strcmp(out_device_name, IN_NET_DEVICE_NAME) == 0){
		*direction = DIRECTION_IN;
	}
	else{
		*direction = 0;
	}
}

void set_packet_src_and_dst_ports(struct sk_buff *skb, __be16 *src_port, __be16 *dst_port){
	struct tcphdr *tcp_header;
	struct udphdr *udp_header;

	if(ip_hdr(skb)->protocol == PROT_TCP){
		tcp_header = tcp_hdr(skb);
		*src_port = ntohs(tcp_header->source);
		*dst_port = ntohs(tcp_header->dest);
	}
	else if(ip_hdr(skb)->protocol == PROT_UDP){
		udp_header = udp_hdr(skb);
		*src_port = ntohs(udp_header->source);
		*dst_port = ntohs(udp_header->dest);
	}
	else{ // ICMP Protocol
		*src_port = 0;
		*dst_port = 0;
	}
}

int check_for_match(rule_t *rule, direction_t packet_direction, __be32 packet_src_ip, __be32 packet_dst_ip, __be16 packet_src_port, __be16 packet_dst_port, __u8 packet_protocol, ack_t packet_ack){
	if(!(rule->direction & packet_direction)){
		return 0;
	}
	if((rule->src_ip & rule->src_prefix_mask) != (packet_src_ip & rule->src_prefix_mask)){
		return 0;
	}
	if((rule->dst_ip & rule->dst_prefix_mask) != (packet_dst_ip & rule->dst_prefix_mask)){
		return 0;
	}
	if(rule->src_port != PORT_ANY && (rule->src_port != PORT_ABOVE_1023 || packet_src_port <= 1023) && rule->src_port != packet_src_port){
		return 0;
	}
	if(rule->dst_port != PORT_ANY && (rule->dst_port != PORT_ABOVE_1023 || packet_dst_port <= 1023) && rule->dst_port != packet_dst_port){
		return 0;
	}
	if(rule->protocol != PROT_ANY && rule->protocol != packet_protocol){
		return 0;
	}
	if(!(rule->ack & packet_ack)){
		return 0;
	}
	return 1;
}

tcp_packet_t get_packet_type(struct tcphdr *tcp_header){
	if(tcp_header->syn && !tcp_header->ack){
		return TCP_SYN;
	}
	if(tcp_header->syn && tcp_header->ack){
		return TCP_SYN_ACK;
	}
	if(tcp_header->fin && !tcp_header->ack){
		return TCP_FIN;
	}
	if(tcp_header->fin && tcp_header->ack){
		return TCP_FIN_ACK;
	}
	if(tcp_header->rst && !tcp_header->ack){
		return TCP_RST;
	}
	if(tcp_header->rst && tcp_header->ack){
		return TCP_RST_ACK;
	}
	if(tcp_header->ack){
		return TCP_ACK;
	}
	return TCP_UNKNOWN;
}

__u8 validate_TCP_packet(struct tcphdr *tcp_header, __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, direction_t packet_direction ,log_row_t *log_row){
	tcp_state_t state;
	tcp_packet_t packet_type;
	struct connection_entry *entry;
	__u8 action;

	entry = find_connection(src_ip, dst_ip, src_port, dst_port);
	if(entry == NULL){
		if(packet_type == TCP_SYN){
			if(stateless_filter(packet_direction, src_ip, dst_ip, src_port, dst_port, PROT_TCP, ACK_NO, log_row) == NF_DROP){
				return NF_DROP;
			}
			// check if the connection needs to be proxied (if the destination port is a HTTP port)
			if(create_proxy_connection(src_ip, dst_ip, src_port, dst_port, packet_direction)){
				return NF_ACCEPT;
			}
			add_connection(src_ip, dst_ip, src_port, dst_port, TCP_STATE_INIT);
			add_connection(dst_ip, src_ip, dst_port, src_port, TCP_STATE_INIT);
			state = TCP_STATE_INIT;
		}
		else{
			action = NF_DROP;
			log_it(log_row, REASON_UNMATCHING_STATE, action);
			return action;
		}
	}
	else{
		state = entry->connection_data.state;
	}
	packet_type = get_packet_type(tcp_header);
	printk(KERN_INFO "1: Packet type: %d\n", packet_type);
	printk(KERN_INFO "2: Connection state: %d\n", state);
	if(packet_direction == DIRECTION_OUT){
		printk(KERN_INFO "3: client to server\n");
	}
	else{
		printk(KERN_INFO "3: server to client\n");
	}
	switch(state){
		case TCP_STATE_CLOSED:
			if(packet_type == TCP_RST || packet_type == TCP_RST_ACK){
				action = NF_ACCEPT;
				log_it(log_row, REASON_MATCHING_STATE, action);
				// we remove the connection from the connection table in both sides
				remove_connection(src_ip, dst_ip, src_port, dst_port);
				remove_connection(dst_ip, src_ip, dst_port, src_port);
				return action;
			}
			else{
				action = NF_DROP;
				log_it(log_row, REASON_UNMATCHING_STATE, action);
				remove_connection(src_ip, dst_ip, src_port, dst_port);
				remove_connection(dst_ip, src_ip, dst_port, src_port);
				return action;
			}
			break;
		case TCP_STATE_INIT:
			if(packet_type == TCP_SYN){
				if(packet_direction == DIRECTION_IN){ // we are not allowing SYN packets from the outside
					action = NF_DROP;
					log_it(log_row, REASON_UNMATCHING_STATE, action);
					return action;
				}
				update_connection_state(src_ip, dst_ip, src_port, dst_port, TCP_STATE_SYN_SENT);
				update_connection_state(dst_ip, src_ip, dst_port, src_port, TCP_STATE_LISTEN);
				action = NF_ACCEPT;
				//should I log? feels redundant...
				return action;
			}
			action = NF_DROP;
			log_it(log_row, REASON_UNMATCHING_STATE, action);
			return action;
			break;
		case TCP_STATE_SYN_SENT: // this is a client only state
			if(packet_type == TCP_RST || packet_type == TCP_RST_ACK){
				// if we receive an RST packet we need to switch to closed states
				update_connection_state(src_ip, dst_ip, src_port, dst_port, TCP_STATE_CLOSED);
				update_connection_state(dst_ip, src_ip, dst_port, src_port, TCP_STATE_CLOSED);
				action = NF_ACCEPT;
				log_it(log_row, REASON_MATCHING_STATE, action);
				return action;
			}
			else if(packet_type == TCP_ACK){
				// if the client sends an ACK packet we need to switch to established states
				update_connection_state(src_ip, dst_ip, src_port, dst_port, TCP_STATE_ESTABLISHED);
				update_connection_state(dst_ip, src_ip, dst_port, src_port, TCP_STATE_ESTABLISHED);
				action = NF_ACCEPT;
				log_it(log_row, REASON_MATCHING_STATE, action);
				return action;
			}
			else{
				action = NF_DROP;
				log_it(log_row, REASON_UNMATCHING_STATE, action);
				return action;
			}
			break;
		case TCP_STATE_LISTEN: // this is a server only state
			if(packet_type == TCP_RST || packet_type == TCP_RST_ACK){
				// if we receive an RST packet we need to switch to closed states
				update_connection_state(src_ip, dst_ip, src_port, dst_port, TCP_STATE_CLOSED);
				update_connection_state(dst_ip, src_ip, dst_port, src_port, TCP_STATE_CLOSED);
				action = NF_ACCEPT;
				log_it(log_row, REASON_MATCHING_STATE, action);
				return action;
			}
			else if(packet_type == TCP_SYN_ACK){
				// if the server sends a SYN-ACK packet we need to switch to SYN_RECV state
				update_connection_state(src_ip, dst_ip, src_port, dst_port, TCP_STATE_SYN_RECV);
				action = NF_ACCEPT;
				log_it(log_row, REASON_MATCHING_STATE, action);
				return action;
			}
			else{
				action = NF_DROP;
				log_it(log_row, REASON_UNMATCHING_STATE, action);
				return action;
			}
			break;
		case TCP_STATE_SYN_RECV: // this is a server only state, should not send any packets in this state
			if(packet_type == TCP_RST || packet_type == TCP_RST_ACK){
				// if we receive an RST packet we need to switch to closed states
				update_connection_state(src_ip, dst_ip, src_port, dst_port, TCP_STATE_CLOSED);
				update_connection_state(dst_ip, src_ip, dst_port, src_port, TCP_STATE_CLOSED);
				action = NF_ACCEPT;
				log_it(log_row, REASON_MATCHING_STATE, action);
				return action;
			}
			else{
				action = NF_DROP;
				log_it(log_row, REASON_UNMATCHING_STATE, action);
				return action;
			}
			break;
		case TCP_STATE_ESTABLISHED:
			if(packet_type == TCP_RST || packet_type == TCP_RST_ACK){
				// if we receive an RST packet we need to switch to closed states
				update_connection_state(src_ip, dst_ip, src_port, dst_port, TCP_STATE_CLOSED);
				update_connection_state(dst_ip, src_ip, dst_port, src_port, TCP_STATE_CLOSED);
				action = NF_ACCEPT;
				log_it(log_row, REASON_MATCHING_STATE, action);
				return action;
			}
			else if(packet_type == TCP_FIN || packet_type == TCP_FIN_ACK){
				// if we receive a FIN packet we need to switch to FIN_WAIT1 state
				update_connection_state(src_ip, dst_ip, src_port, dst_port, TCP_STATE_FIN_WAIT1);
				update_connection_state(dst_ip, src_ip, dst_port, src_port, TCP_STATE_CLOSE_WAIT);
				action = NF_ACCEPT;
				log_it(log_row, REASON_MATCHING_STATE, action);
				return action;
			}
			else{
				action = NF_ACCEPT;
				log_it(log_row, REASON_MATCHING_STATE, action);
				return action;
			}
			break;
		case TCP_STATE_FIN_WAIT1:
			if(packet_type == TCP_RST || packet_type == TCP_RST_ACK){
				// if we receive an RST packet we need to switch to closed states
				update_connection_state(src_ip, dst_ip, src_port, dst_port, TCP_STATE_CLOSED);
				update_connection_state(dst_ip, src_ip, dst_port, src_port, TCP_STATE_CLOSED);
				action = NF_ACCEPT;
				log_it(log_row, REASON_MATCHING_STATE, action);
				return action;
			}
			// COMPLETE IF NECESSARY
			break;
		case TCP_STATE_FIN_WAIT2:
			if(packet_type == TCP_RST || packet_type == TCP_RST_ACK){
				// if we receive an RST packet we need to switch to closed states
				update_connection_state(src_ip, dst_ip, src_port, dst_port, TCP_STATE_CLOSED);
				update_connection_state(dst_ip, src_ip, dst_port, src_port, TCP_STATE_CLOSED);
				action = NF_ACCEPT;
				log_it(log_row, REASON_MATCHING_STATE, action);
				return action;
			}
			else if(packet_type == TCP_ACK){
				// if we receive an ACK packet we need to remove the connection from the connection table
				remove_connection(src_ip, dst_ip, src_port, dst_port);
				remove_connection(dst_ip, src_ip, dst_port, src_port);
				action = NF_ACCEPT;
				log_it(log_row, REASON_MATCHING_STATE, action);
				return action;
			}
			else{
				action = NF_DROP;
				log_it(log_row, REASON_UNMATCHING_STATE, action);
				return action;
			}
			break;
		case TCP_STATE_CLOSE_WAIT:
			if(packet_type == TCP_RST || packet_type == TCP_RST_ACK){
				// if we receive an RST packet we need to switch to closed states
				update_connection_state(src_ip, dst_ip, src_port, dst_port, TCP_STATE_CLOSED);
				update_connection_state(dst_ip, src_ip, dst_port, src_port, TCP_STATE_CLOSED);
				action = NF_ACCEPT;
				log_it(log_row, REASON_MATCHING_STATE, action);
				return action;
			}
			else if(packet_type == TCP_FIN){
				// if we receive a FIN packet we need to wait for an ACK from both sides
				update_connection_state(src_ip, dst_ip, src_port, dst_port, TCP_STATE_CLOSING);
				update_connection_state(dst_ip, src_ip, dst_port, src_port, TCP_STATE_CLOSING);
				action = NF_ACCEPT;
				log_it(log_row, REASON_MATCHING_STATE, action);
				return action;
			}
			else if(packet_type == TCP_FIN_ACK){
				// that means that the other side has already sent a FIN packet and this side acknowledged it and sent a FIN of its own
				// we need to wait for an ACK from the other side
				update_connection_state(src_ip, dst_ip, src_port, dst_port, TCP_STATE_LAST_ACK);
				update_connection_state(dst_ip, src_ip, dst_port, src_port, TCP_STATE_FIN_WAIT2);
				action = NF_ACCEPT;
				log_it(log_row, REASON_MATCHING_STATE, action);
				return action;
			}
			else if(packet_type == TCP_ACK){
				// that means that the other side has already sent a FIN packet and this side acknowledged it
				// a FIN packet is still needed from this side
				// Hence no state change
				action = NF_ACCEPT;
				log_it(log_row, REASON_MATCHING_STATE, action);
				return action;
			}
			else{
				action = NF_DROP;
				log_it(log_row, REASON_UNMATCHING_STATE, action);
				return action;
			}
			break;
		case TCP_STATE_LAST_ACK:
		// COMPLETE IF NECESSARY
			break;
		case TCP_STATE_TIME_WAIT:
		// COMPLETE IF NECESSARY
			break;
		case TCP_STATE_CLOSING: // this states means that both sides sent a FIN packet and we are waiting for an ACK from both sides
			if(packet_type == TCP_ACK){
				// this side acknowledged the FIN packet from the other side
				update_connection_state(src_ip, dst_ip, src_port, dst_port, TCP_STATE_TIME_WAIT);
				// if the other side already sent an ACK packet we can remove the connection from the connection table
				// this is abuse of notation because the FSM moves to time_wait state upon receiving an ACK packet and not sending, but it is what it is
				if(get_connection_state(dst_ip, src_ip, dst_port, src_port) == TCP_STATE_TIME_WAIT){
					remove_connection(src_ip, dst_ip, src_port, dst_port);
					remove_connection(dst_ip, src_ip, dst_port, src_port);
				}
				action = NF_ACCEPT;
				log_it(log_row, REASON_MATCHING_STATE, action);
				return action;
			}
			else{
				action = NF_DROP;
				log_it(log_row, REASON_UNMATCHING_STATE, action);
				return action;
			}
			break;
		case TCP_STATE_PROXY: // we don't inspect TCP FSM rules when the connection is a proxy connection
			action = NF_ACCEPT;
			log_it(log_row, REASON_PROXY_CONN, action);
			return action;
			break;
		default:
			action = NF_DROP;
			log_it(log_row, REASON_UNMATCHING_STATE, action);
			return action;
	}
	action = NF_DROP;
	log_it(log_row, REASON_UNMATCHING_STATE, action);
	return action;
}
