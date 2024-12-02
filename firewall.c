#include <linux/netfilter.h>
#include <linux/in.h>

#include "fw.h"

#define INTERNAL_NAME "enp0s8"
#define EXTERNAL_NAME "enp0s9"
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yinon Ben David");

static struct nf_hook_ops *nfho = NULL;

rule_t rule_table[MAX_RULES];
int active_rules = 0;

/*
rule_t loopback_rule = {
	.rule_name = "loopback",
	.direction = DIRECTION_ANY,
	.src_ip = 0x7F000001,
	.src_prefix_mask = 0xFF000000,
	.src_prefix_size = 8,

	.dst_ip = 0x7F000001,
	.dst_prefix_mask = 0xFF000000,
	.dst_prefix_size = 8,

	.src_port = 0,
	.dst_port = 0,

	.protocol = PROT_ANY,
	.ack = ACK_ANY,
	.action = NF_ACCEPT
};
*/

static unsigned int judge(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
	
	struct iphdr *ip_header;
	struct tcphdr *tcp_header;
	struct udphdr *udp_header;

	if(!skb){
		return NF_ACCEPT;
	}

	ip_header = ip_hdr(skb);

	if(ip_header->saddr == 0x7F000001 && ip_header->daddr == 0x7F000001){ /*loopback packet*/
		return NF_ACCEPT;
	}

	if(ip_header->protocol == PROT_OTHER){ /*non TCP/UDP/ICMP packet*/
		return NF_ACCEPT;
	}

	if(ip_header->protocol == PROT_TCP){
		tcp_header = (struct tcphdr *)((__u8 *)ip_header + (ip_header->ihl * 4));
		if(!tcp_header) return NF_ACCEPT;
		
	}

	//extracting fields for the rule table...
	int next_action = verdict(state->in->name, ip_header->saddr, ip_header->daddr, )
	return NF_ACCEPT;
}

static int __init direction_checker(void){
	nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);

	nfho -> hook = judge;
	nfho -> hooknum = NF_INET_FORWARD;
	nfho -> pf = NFPROTO_IPV4;
	nfho -> priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, nfho);
	return 0;
}

static void __exit direction_checker_exit(void){
	nf_unregister_net_hook(&init_net, nfho);
	kfree(nfho);
}

module_init(direction_checker);
module_exit(direction_checker_exit);