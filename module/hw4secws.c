#include <linux/netfilter.h>
#include <linux/in.h>

#include "fw.h"
#include "RuleTable.h"
#include "PacketFilter.h"
#include "LogDevice.h"
#include "ConnectionTable.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yinon Ben David");

static struct nf_hook_ops *nfho = NULL;
static int log_device_major = 0;
static int rules_device_major = 0;
static int log_reset_device_major = 0;
static int conns_device_major = 0;
static struct class* sysfs_class = NULL;
static struct device* rules_device = NULL;
static struct device* log_device = NULL;
static struct device* log_reset_device = NULL;
static struct device* conns_device = NULL;

// define the log device operations
static struct file_operations log_fops = {
	.owner = THIS_MODULE,
	.open = open_log_device,
	.read = read_log_device
};

// define the rules device operations (no ops for this char device)
static struct file_operations rules_fops = {
	.owner = THIS_MODULE
};

static struct file_operations log_reset_fops = {
	.owner = THIS_MODULE
};

static struct file_operations conns_fops = {
	.owner = THIS_MODULE
};

static DEVICE_ATTR(reset, S_IWUSR | S_IRUGO, NULL, modify_log_device);
static DEVICE_ATTR(rules, S_IWUSR | S_IRUGO, display_rule_table, modify_rule_table);
static DEVICE_ATTR(conns, S_IRUGO, display_connection_table, NULL);

static int __init firewall_module(void){
	// create the netfilter hook
	nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);

	nfho -> hook = filter;
	// the hooknum should be the pre-routing hook
	//nfho -> hooknum = NF_INET_PRE_ROUTING;
	nfho -> hooknum = NF_INET_FORWARD;
	nfho -> pf = NFPROTO_IPV4;
	nfho -> priority = NF_IP_PRI_FIRST;
	if(nf_register_net_hook(&init_net, nfho) != 0){
		printk(KERN_ERR "Failed to register nfhook.\n");
		goto nf_hook_registration_error;
	}

	// create the log device and sysfs attributes
	log_device_major = register_chrdev(0, "fw_log", &log_fops);
	if(log_device_major < 0){
		printk(KERN_ERR "Failed to register log char device.\n");
		goto log_device_registration_error;
	}

	sysfs_class = class_create(THIS_MODULE, CLASS_NAME);
	if(IS_ERR(sysfs_class)){
		printk(KERN_ERR "Failed to create sysfs class.\n");
		goto sysfs_class_creation_error;
	}

	// create the log_reset device
	log_reset_device_major = register_chrdev(0, "fw_reset_log", &log_reset_fops);
	if(log_reset_device_major < 0){
		printk(KERN_ERR "Failed to register reset log char device.\n");
		goto reset_log_device_error;
	}

	log_device = device_create(sysfs_class, NULL, MKDEV(log_device_major, 0), NULL, "fw_log");
	if(IS_ERR(log_device)){
		printk(KERN_ERR "Failed to create log sysfs device.\n");
		goto log_device_creation_error;
	}

	log_reset_device = device_create(sysfs_class, NULL, MKDEV(log_reset_device_major, 0), NULL, DEVICE_NAME_LOG);
	if(IS_ERR(log_reset_device)){
		printk(KERN_ERR "Failed to create reset log sysfs device");
		goto log_reset_device_creation_error;
	}

	if(device_create_file(log_reset_device, (const struct device_attribute*)&dev_attr_reset.attr) != 0){
		printk(KERN_ERR "Failed to create log_device file.\n");
		goto log_device_file_creation_error;
	}

	// create the rules device and sysfs attributes
	rules_device_major = register_chrdev(0, "rules", &rules_fops);
	if(rules_device_major < 0){
		printk(KERN_ERR "Failed to create rules char device.\n");
		goto rules_device_registration_error;
	}
	rules_device = device_create(sysfs_class, NULL, MKDEV(rules_device_major, 0), NULL, DEVICE_NAME_RULES);
	if(IS_ERR(rules_device)){
		printk(KERN_ERR "Failed to create rules sysfs device.\n");
		goto rules_device_creation_error;
	}

	if(device_create_file(rules_device, (const struct device_attribute*)&dev_attr_rules.attr) != 0){
		printk(KERN_ERR "Failed to create rules file.\n");
		goto rules_file_creation_error;
	}

	// create the connection table device and sysfs attributes
	conns_device_major = register_chrdev(0, "conns", &conns_fops);
	if(conns_device_major < 0){
		printk(KERN_ERR "Failed to create conns char device.\n");
		goto conns_device_registration_error;
	}
	conns_device = device_create(sysfs_class, NULL, MKDEV(conns_device_major, 0), NULL, DEVICE_NAME_CONNS);
	if(IS_ERR(conns_device)){
		printk(KERN_ERR "Failed to create conns sysfs device.\n");
		goto conns_device_creation_error;
	}

	if(device_create_file(conns_device, (const struct device_attribute*)&dev_attr_conns.attr) != 0){
		printk(KERN_ERR "Failed to create conns file.\n");
		goto conns_file_creation_error;
	}
	return 0;

// to avoid code duplication, we will use uconditional jumps to handle the error cases:
conns_file_creation_error:
	device_destroy(sysfs_class, MKDEV(conns_device_major, 0));
conns_device_creation_error:
	unregister_chrdev(conns_device_major, "conns");
conns_device_registration_error:
	device_remove_file(conns_device, (const struct device_attribute*)&dev_attr_conns.attr);
rules_file_creation_error:
	device_destroy(sysfs_class, MKDEV(rules_device_major, 0));
rules_device_creation_error:
	unregister_chrdev(rules_device_major, "rules");
rules_device_registration_error:
	device_remove_file(log_reset_device, (const struct device_attribute*)&dev_attr_reset.attr);
log_device_file_creation_error:
	device_destroy(sysfs_class, MKDEV(log_reset_device_major, 0));
log_reset_device_creation_error:
	device_destroy(sysfs_class, MKDEV(log_device_major, 0));
log_device_creation_error:
	unregister_chrdev(log_reset_device_major, "fw_reset_log");
reset_log_device_error:
	class_destroy(sysfs_class);
sysfs_class_creation_error:
	unregister_chrdev(log_device_major, "fw_log");
log_device_registration_error:
	nf_unregister_net_hook(&init_net, nfho);
	kfree(nfho);
nf_hook_registration_error:
	return -1;
}

static void __exit firewall_module_exit(void){
	clear_log(); // clear any existing log entries
	clear_connection_table(); // clear any existing connection entries
	device_remove_file(conns_device, (const struct device_attribute*)&dev_attr_conns.attr);
	device_destroy(sysfs_class, MKDEV(conns_device_major, 0));
	unregister_chrdev(conns_device_major, "conns");
	device_remove_file(rules_device, (const struct device_attribute*)&dev_attr_rules.attr);
	device_destroy(sysfs_class, MKDEV(rules_device_major, 0));
	unregister_chrdev(rules_device_major, "rules");
	device_remove_file(log_reset_device, (const struct device_attribute*)&dev_attr_reset.attr);
	device_destroy(sysfs_class, MKDEV(log_reset_device_major, 0));
	device_destroy(sysfs_class, MKDEV(log_device_major, 0));
	unregister_chrdev(log_reset_device_major, "fw_reset_log");
	class_destroy(sysfs_class);
	unregister_chrdev(log_device_major, "fw_log");
	nf_unregister_net_hook(&init_net, nfho);
	kfree(nfho);
}

module_init(firewall_module);
module_exit(firewall_module_exit);