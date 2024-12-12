#ifndef _LOGDEVICE_H_
#define _LOGDEVICE_H_

#include <linux/list.h>

#include "fw.h"
#include "RuleTable.h"

#define LOG_BUFFER_SIZE (sizeof(unsigned long) + sizeof(unsigned char) + sizeof(unsigned char) + sizeof(__be32) + sizeof(__be32) + sizeof(__be16) + sizeof(__be16) + sizeof(int) + sizeof(unsigned int))

struct firewall_log {
    struct list_head list;
    log_row_t log_data;
};

void set_log_address_and_protocol(log_row_t *log_row, __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, __u8 protocol);
void log_it(log_row_t *log_row, reason_t reason, unsigned char action);
ssize_t modify_log_device(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
int open_log_device(struct inode *inode, struct file *file);
ssize_t read_log_device(struct file *file, char __user *buf, size_t count, loff_t *pos);

#endif // _LOGDEVICE_H_