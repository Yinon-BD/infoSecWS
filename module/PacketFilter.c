#include "PacketFilter.h"
#include "LogDevice.h"

unsigned int filter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
	struct iphdr *ip_header;
	struct tcphdr *tcp_header;
	struct udphdr *udp_header;
	log_row_t log_row;
	tcp_packet_t packet_type;
	rule_t *rule_table;

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

	if(((ip_header->saddr) & 0xFF000000) == 0x7F000000 && ((ip_header->daddr) & 0xFF000000) == 0x7F000001){ /*loopback packet*/
		return NF_ACCEPT;
	}

	if(ip_header->protocol == PROT_OTHER){ /*non TCP/UDP/ICMP packet*/
		return NF_ACCEPT;
	}

	if(ip_header->protocol == PROT_TCP){
		tcp_header = tcp_hdr(skb);
		if(!tcp_header) return NF_ACCEPT;
		if(tcp_header->urg && tcp_header->fin && tcp_header->psh){ /*XMAS packet*/
			log_it(&log_row, REASON_XMAS_PACKET, NF_DROP);
			return NF_DROP;
		}
		
	}

	if(is_rule_table_valid() == 0 || get_rule_table_size() == 0){
		log_it(&log_row, REASON_FW_INACTIVE, NF_ACCEPT);
		return NF_ACCEPT;
	}

	rule_table = get_rule_table();
	int i;
	for(i = 0; i < get_rule_table_size(); i++){
		// we want to add the dynamic connection table logic for a TCP packet
		if(packet_protocol == PROT_TCP){
			tcp_header = tcp_hdr(skb);
			packet_type = get_packet_type(tcp_header);
			// if the packet is a SYN packet we need to check for a match in the stateless rules first
			if(packet_type == TCP_SYN && check_for_match(rule_table + i, packet_direction, packet_src_ip, packet_dst_ip, packet_src_port, packet_dst_port, packet_protocol, packet_ack)){
				log_it(&log_row, i, (rule_table + i)->action);
				// if the action is ACCEPT we add the connection to the connection table
				if((rule_table + i)->action == NF_ACCEPT){
					add_connection(packet_src_ip, packet_dst_ip, packet_src_port, packet_dst_port, TCP_STATE_SYN_SENT);
					add_connection(packet_dst_ip, packet_src_ip, packet_dst_port, packet_src_port, TCP_STATE_LISTEN);
				}
				return (rule_table + i)->action;
			}
			// if the packet is a SYN-ACK packet we need to check for a match in the stateful rules
			// the packet would be accepted if there is a connection in the connection table with flipped src and dst in state TCP_STATE_SYN_SENT
			else if(packet_type == TCP_SYN_ACK){
				if(get_connection_state(packet_dst_ip, packet_src_ip, packet_dst_port, packet_src_port) == TCP_STATE_SYN_SENT){
					log_it(&log_row, 1, NF_ACCEPT); // the reason is not important here, the log is already existent
					add_connection(packet_src_ip, packet_dst_ip, packet_src_port, packet_dst_port, TCP_STATE_SYN_RECV);
					return NF_ACCEPT;
				}
				log_it(&log_row, REASON_UNMATCHING_STATE, NF_DROP);
				return NF_DROP;
			}
			else if
		}
		else if(check_for_match(rule_table + i, packet_direction, packet_src_ip, packet_dst_ip, packet_src_port, packet_dst_port, packet_protocol, packet_ack)){
			log_it(&log_row, i, (rule_table + i)->action);
			return (rule_table + i)->action;
		}
	}
	// if no match was found we log the packet and drop it
	log_it(&log_row, REASON_NO_MATCHING_RULE, NF_DROP);
	return NF_DROP;
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
		*src_port = tcp_header->source;
		*dst_port = tcp_header->dest;
	}
	else if(ip_hdr(skb)->protocol == PROT_UDP){
		udp_header = udp_hdr(skb);
		*src_port = udp_header->source;
		*dst_port = udp_header->dest;
	}
	else{
		*src_port = 0;
		*dst_port = 0;
	}
}

int check_for_match(rule_t *rule, direction_t packet_direction, __be32 packet_src_ip, __be32 packet_dst_ip, __be16 packet_src_port, __be16 packet_dst_port, __u8 packet_protocol, ack_t packet_ack){
	if(rule->direction != DIRECTION_ANY && rule->direction != packet_direction){
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
	if(rule->ack != ACK_ANY && rule->ack != packet_ack){
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

__u8 validate_TCP_packet(struct tcphdr *tcp_header, __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, log_row_t *log_row){ // logic for non SYN packets
	tcp_state_t state;
	tcp_packet_t packet_type;
	__u8 action;

	state = get_connection_state(src_ip, dst_ip, src_port, dst_port);
	packet_type = get_packet_type(tcp_header);
	switch(state){
		case TCP_STATE_CLOSED:
			if(packet_type == TCP_RST || packet_type == TCP_RST_ACK){
				action = NF_ACCEPT;
				log_it(log_row, 1, action);
				// we remove the connection from the connection table in both sides
				remove_connection(src_ip, dst_ip, src_port, dst_port);
				remove_connection(dst_ip, src_ip, dst_port, src_port);
				return action;
			}
			else{
				action = NF_DROP;
				log_it(log_row, REASON_UNMATCHING_STATE, action);
				return action;
			}
			break;
		case TCP_STATE_SYN_SENT: // this is a client only state
			if(packet_type == TCP_RST || packet_type == TCP_RST_ACK){
				// if we receive an RST packet we need to switch to closed states
				close_connection(src_ip, dst_ip, src_port, dst_port);
				close_connection(dst_ip, src_ip, dst_port, src_port);
				action = NF_ACCEPT;
				log_it(log_row, 1, action);
				return action;
			}
			else if(packet_type == TCP_ACK){
				// if the client sends an ACK packet we need to switch to established states
				update_connection_state(src_ip, dst_ip, src_port, dst_port, TCP_STATE_ESTABLISHED);
				update_connection_state(dst_ip, src_ip, dst_port, src_port, TCP_STATE_ESTABLISHED);
				action = NF_ACCEPT;
				log_it(log_row, 1, action);
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
				close_connection(src_ip, dst_ip, src_port, dst_port);
				close_connection(dst_ip, src_ip, dst_port, src_port);
				action = NF_ACCEPT;
				log_it(log_row, 1, action);
				return action;
			}
			else if(packet_type == TCP_SYN_ACK){
				// if the server sends a SYN-ACK packet we need to switch to SYN_RECV state
				update_connection_state(src_ip, dst_ip, src_port, dst_port, TCP_STATE_SYN_RECV);
				action = NF_ACCEPT;
				log_it(log_row, 1, action);
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
				close_connection(src_ip, dst_ip, src_port, dst_port);
				close_connection(dst_ip, src_ip, dst_port, src_port);
				action = NF_ACCEPT;
				log_it(log_row, 1, action);
				return action;
			}
			else{
				action = NF_DROP;
				log_it(log_row, REASON_UNMATCHING_STATE, action);
				return action;
			}
			break;
		case TCP_STATE_ESTABLISHED
	}
	
}