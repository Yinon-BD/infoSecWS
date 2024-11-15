//trying

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/in.h>

/* creating 3 hooks for 3 desired hookpoints */
static struct nf_hook_ops *nfho_in = NULL;
static struct nf_hook_ops *nfho_out = NULL;
static struct nf_hook_ops *nfho_through = NULL;

static unsigned int packet_drop(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){

	if(!skb){
		return NF_ACCEPT;
	}

	if(state->hook == NF_INET_LOCAL_IN || state->hook == NF_INET_LOCAL_OUT){ /*should always get inside the if statement*/
		printk(KERN_INFO "*** Packet Dropped ***\n");
		return NF_DROP;
	}

	printk(KERN_INFO "*** Packet Accepted ***\n");
	return NF_ACCEPT;
}

static unsigned int packet_accept(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){

	if(!skb){
		return NF_ACCEPT;
	}
	printk(KERN_INFO "*** Packet Accepted ***\n");
	return NF_ACCEPT;
}

static int __init ip_blocker_init(void){
	nfho_in = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	nfho_out = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	nfho_through = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);

	/*fiiling hooks' fields*/

	nfho_in -> hook = packet_drop;
	nfho_in -> hooknum = NF_INET_LOCAL_IN;
	nfho_in -> pf = NFPROTO_IPV4;
	nfho_in -> priority = NF_IP_PRI_FIRST;

	nfho_out -> hook = packet_drop;
	nfho_out -> hooknum = NF_INET_LOCAL_OUT;
	nfho_out -> pf = NFPROTO_IPV4;
	nfho_out -> priority = NF_IP_PRI_FIRST;

	nfho_through -> hook = packet_accept;
	nfho_through -> hooknum = NF_INET_FORWARD;
	nfho_through -> pf = NFPROTO_IPV4;
	nfho_through -> priority = NF_IP_PRI_FIRST;

	nf_register_net_hook(&init_net, nfho_in);
	nf_register_net_hook(&init_net, nfho_out);
	nf_register_net_hook(&init_net, nfho_through);
	return 0;
}

static void __exit ip_blocker_exit(void){
	/* unregisters the hooks and frees the space the hooks take*/
	
	nf_unregister_net_hook(&init_net, nfho_in);
	nf_unregister_net_hook(&init_net, nfho_out);
	nf_unregister_net_hook(&init_net, nfho_through);
	kfree(nfho_in);
	kfree(nfho_out);
	kfree(nfho_through);
}

module_init(ip_blocker_init);
module_exit(ip_blocker_exit);
