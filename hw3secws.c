#include <linux/netfilter.h>
#include <linux/in.h>

#include "fw.h"
#include "RuleTable.h"
#include "PacketFilter.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yinon Ben David");

static struct nf_hook_ops *nfho = NULL;

static int __init direction_checker(void){
	nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);

	nfho -> hook = filter;
	nfho -> hooknum = NF_INET_FORWARD;
	nfho -> pf = NFPROTO_IPV4;
	nfho -> priority = NF_IP_PRI_FIRST;
	if(nf_register_net_hook(&init_net, nfho) != 0){
		return -1;
	}
	return 0;
}

static void __exit direction_checker_exit(void){
	nf_unregister_net_hook(&init_net, nfho);
	kfree(nfho);
}

module_init(direction_checker);
module_exit(direction_checker_exit);