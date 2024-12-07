#include "PacketFilter.h"

unsigned int filter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
	struct iphdr *ip_header;
	struct tcphdr *tcp_header;
	struct udphdr *udp_header;

	direction_t packet_direction;
	__be32	packet_src_ip;
	__be32	packet_dst_ip;
	__be16	packet_src_port; 			// number of port or 0 for any or port 1023 for any port number > 1023  
	__be16	packet_dst_port; 			// number of port or 0 for any or port 1023 for any port number > 1023 
	__u8	packet_protocol; 			// values from: prot_t
	ack_t	packet_ack;

	if(!skb){
		return NF_ACCEPT;
	}

	set_packet_direction(skb, &direction, state);
	ip_header = ip_hdr(skb);
	packet_src_ip = ip_header->saddr;
	packet_dst_ip = ip_header->daddr;
	packet_protocol = ip_header->protocol;
	set_packet_src_and_dst_ports(skb, &packet_src_port, &packet_dst_port);
	if(packet_protocol == PROT_TCP){
		tcp_header = tcp_hdr(skb);
		packet_ack = tcp_header->ack ? ACK_YES : ACK_NO;
	}

	if(ip_header->saddr == 0x7F000001 && ip_header->daddr == 0x7F000001){ /*loopback packet*/
		return NF_ACCEPT;
	}

	if(ip_header->protocol == PROT_OTHER){ /*non TCP/UDP/ICMP packet*/
		return NF_ACCEPT;
	}

	if(ip_header->protocol == PROT_TCP){
		tcp_header = tcp_hdr(skb);
		if(!tcp_header) return NF_ACCEPT;
		if(tcp_header->urg && tcp_header->fin && tcp_header->psh){ /*XMAS packet*/
			log_it(REASON_XMAS_PACKET, NF_DROP);
			return NF_DROP;
		}
		
	}

	if(is_valid_rule_table() == 0 || get_rule_table_size() == 0){
		log_it(REASON_FW_INACTIVE, NF_ACCEPT);
		return NF_ACCEPT;
	}

	rule_t *rule_table = get_rule_table();
	int i;
	for(i = 0; i < get_rule_table_size(); i++){
		if(check_for_match(rule_table + i, packet_direction, packet_src_ip, packet_dst_ip, packet_src_port, packet_dst_port, packet_protocol, packet_ack)){
			log_it(i, (rule_table + i)->action);
			return (rule_table + i)->action;
		}
	}
	// if no match was found we log the packet and drop it
	log_it(REASON_NO_MATCHING_RULE, NF_DROP);
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