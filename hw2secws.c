//trying

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/ip.h>
#include <linux/in.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yinon Ben David");

/* creating 3 hooks for 3 desired hookpoints */
static struct nf_hook_ops *nfho_in = NULL;
static struct nf_hook_ops *nfho_out = NULL;
static struct nf_hook_ops *nfho_through = NULL;

static int major_number;
static struct class* sysfs_class = NULL;
static struct device* sysfs_device = NULL;

static unsigned int accept_counter = 0;
static unsigned int drop_counter = 0;

static struct file_operations fops = {
	.owner = THIS_MODULE
};

ssize_t display_acc(struct device *dev, struct device_attribute *attr, char *buf) {
	return scnprintf(buf, PAGE_SIZE, "%u\n", accept_counter);
}

ssize_t modify_acc(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
	int temp;
	if (sscanf(buf, "%u", &temp) == 1)
		accept_counter = 0;
	return count;
}

ssize_t display_drop(struct device *dev, struct device_attribute *attr, char *buf) {
	return scnprintf(buf, PAGE_SIZE, "%u\n",drop_counter);
}

ssize_t modify_drop(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
	int temp;
	if (sscanf(buf, "%u", &temp) == 1)
		drop_counter = 0;
	return count;
}

static DEVICE_ATTR(acc_attr, S_IWUSR | S_IRUGO, display_acc, modify_acc);
static DEVICE_ATTR(drop_attr, S_IWUSR | S_IRUGO, display_drop, modify_drop);

static unsigned int packet_drop(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){

	if(!skb){
		return NF_ACCEPT;
	}

	if(state->hook == NF_INET_LOCAL_IN || state->hook == NF_INET_LOCAL_OUT){ /*should always get inside the if statement*/
		printk(KERN_INFO "*** Packet Dropped ***\n");
		drop_counter++;
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
	accept_counter++;
	return NF_ACCEPT;
}

static int __init ip_blocker_init(void){
	nfho_in = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	nfho_out = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	nfho_through = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);

	/*filing hooks' fields*/

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

	/* creating the device and system attributes*/
	major_number = register_chrdev(0, "PacketCounterDevice", &fops);

	if(major_number < 0) {
		nf_unregister_net_hook(&init_net, nfho_in);
		nf_unregister_net_hook(&init_net, nfho_out);
		nf_unregister_net_hook(&init_net, nfho_through);
		kfree(nfho_in);
		kfree(nfho_out);
		kfree(nfho_through);
		return -1;
	}

	sysfs_class = class_create(THIS_MODULE, "PacketCounterClass");

	if(IS_ERR(sysfs_class)){
		nf_unregister_net_hook(&init_net, nfho_in);
		nf_unregister_net_hook(&init_net, nfho_out);
		nf_unregister_net_hook(&init_net, nfho_through);
		kfree(nfho_in);
		kfree(nfho_out);
		kfree(nfho_through);
		unregister_chrdev(major_number, "PacketCounterDevice");
		return -1;
	}

	sysfs_device = device_create(sysfs_class, NULL, MKDEV(major_number, 0), NULL, "PacketCounterClass" "_" "PacketCounterDevice");

	if(IS_ERR(sysfs_device)){
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "PacketCounterDevice");
		nf_unregister_net_hook(&init_net, nfho_in);
		nf_unregister_net_hook(&init_net, nfho_out);
		nf_unregister_net_hook(&init_net, nfho_through);
		kfree(nfho_in);
		kfree(nfho_out);
		kfree(nfho_through);
		return -1;
	}

	if(device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_acc_attr.attr)){
		device_destroy(sysfs_class, MKDEV(major_number, 0));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "PacketCounterDevice");
		nf_unregister_net_hook(&init_net, nfho_in);
		nf_unregister_net_hook(&init_net, nfho_out);
		nf_unregister_net_hook(&init_net, nfho_through);
		kfree(nfho_in);
		kfree(nfho_out);
		kfree(nfho_through);
		return -1;
	}

	if(device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_drop_attr.attr)){
		device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_acc_attr.attr);
		device_destroy(sysfs_class, MKDEV(major_number, 0));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "PacketCounterDevice");
		nf_unregister_net_hook(&init_net, nfho_in);
		nf_unregister_net_hook(&init_net, nfho_out);
		nf_unregister_net_hook(&init_net, nfho_through);
		kfree(nfho_in);
		kfree(nfho_out);
		kfree(nfho_through);
		return -1;
	}
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
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_acc_attr.attr);
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_drop_attr.attr);
	device_destroy(sysfs_class, MKDEV(major_number, 0));
	class_destroy(sysfs_class);
	unregister_chrdev(major_number, "PacketCounterDevice");
}

module_init(ip_blocker_init);
module_exit(ip_blocker_exit);
