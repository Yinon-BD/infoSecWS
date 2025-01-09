#ifndef _FILTER_H_
#define _FILTER_H_

#include "fw.h"
#include "RuleTable.h"
#include "ConnectionTable.h"
#include "ProxyDevice.h"

// the function that will be called by netfilter hook
unsigned int filter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
void set_packet_direction(struct sk_buff *skb, direction_t *direction, const struct nf_hook_state *state);
void set_packet_src_and_dst_ports(struct sk_buff *skb, __be16 *src_port, __be16 *dst_port);
int check_for_match(rule_t *rule, direction_t packet_direction, __be32 packet_src_ip, __be32 packet_dst_ip, __be16 packet_src_port, __be16 packet_dst_port, __u8 packet_protocol, ack_t packet_ack);
__u8 validate_TCP_packet(struct tcphdr *tcp_header, __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, direction_t packet_direction, log_row_t *log_row);
int stateless_filter(direction_t packet_direction, __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, __u8 protocol, ack_t ack, log_row_t *log_row);
tcp_packet_t get_packet_type(struct tcphdr *tcp_header);
int check_special_cases(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, __u8 protocol, struct sk_buff *skb);

#endif // _FILTER_H_
