#include "LogDevice.h"

static LIST_HEAD(log_list); // Initialize the list
static __u32 log_list_len = 0;
static __u8 passed_len = 0; // flag to indicate if the log list length was passed
struct firewall_log *current_log = NULL; // pointer to the current log entry when reading from the log device

void set_log_address_and_protocol(log_row_t *log_row, __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, __u8 protocol){
    log_row->src_ip = src_ip;
    log_row->dst_ip = dst_ip;
    log_row->src_port = src_port;
    log_row->dst_port = dst_port;
    log_row->protocol = protocol;
    log_row->timestamp = ktime_get_real_seconds();
}

void log_it(log_row_t *log_row, reason_t reason, unsigned char action){
    log_row->reason = reason;
    log_row->action = action;
    log_row->count = 1;

    // iterate over the list and check if the log already exists
    struct firewall_log *entry;
    list_for_each_entry(entry, &log_list, list){
        if(entry->log_data.src_ip == log_row->src_ip && entry->log_data.dst_ip == log_row->dst_ip && entry->log_data.src_port == log_row->src_port && entry->log_data.dst_port == log_row->dst_port && entry->log_data.protocol == log_row->protocol){
            entry->log_data.count++;
            entry->log_data.timestamp = log_row->timestamp;
            return;
        }
    }
    // if the log does not exist, create a new entry
    struct firewall_log *new_log = (struct firewall_log*)kmalloc(sizeof(struct firewall_log), GFP_KERNEL);
    new_log->log_data = *log_row;
    list_add_tail(&new_log->list, &log_list);
}

void clear_log(void){
    struct firewall_log *entry, *tmp;
    list_for_each_entry_safe(entry, tmp, &log_list, list){
        list_del(&entry->list);
        kfree(entry);
    }
}

ssize_t modify_log_device(struct device *dev, struct device_attribute *attr, const char *buf, size_t count){
    // if any data is written to the sysfs log device, clear the log
    clear_log();
    return count;
}

// "open" function for the log device
int open_log_device(struct inode *inode, struct file *file){
    passed_len = 0;
    current_log = NULL;
    return 0;
}

// "read" function for the log char device
ssize_t read_log_device(struct file *file, char __user *buf, size_t count, loff_t *pos){
    struct firewall_log *entry;
    char log_buffer[LOG_BUFFER_SIZE];
    ssize_t len = 0;

    // if the log list length was not passed yet, send it to the user
    if(!passed_len){
        // check if the buffer is large enough to hold the log list length
        if(count < sizeof(__u32)){
            return 0;
        }
        // send the log list length to the user
        if(copy_to_user(buf, &log_list_len, sizeof(__u32)) != 0){
            return -EFAULT;
        }
        passed_len = 1;
        len += sizeof(__u32);
        count -= sizeof(__u32);
        buf += sizeof(__u32);
        *pos += sizeof(__u32);
        return len;
    }
    // we already passed the log list length, now we can send the next log entry
    // each read call will send one log entry
    // if the current_log pointer is NULL, we need to start from the beginning of the list
    if(current_log == NULL){
        current_log = list_first_entry(&log_list, struct firewall_log, list);
    }
    else{
        current_log = list_next_entry(current_log, list);
    }
    // if we reached the end of the list, return 0
    if(current_log == NULL){
        return 0; // EOF
    }

    // Ensure there is enough space in the buffer to hold the log entry
    if(count < LOG_BUFFER_SIZE){
        return -EINVAL;
    }

    // format of the log entry: <timestamp> <protocol> <action> <src_ip> <dst_ip> <src_port> <dst_port> <reason> <count>
    len = scnprintf(
        log_buffer, LOG_BUFFER_SIZE, "%lu %u %u %u %u %u %u %u %u\n",
        current_log->log_data.timestamp,
        current_log->log_data.protocol,
        current_log->log_data.action,
        current_log->log_data.src_ip,
        current_log->log_data.dst_ip,
        current_log->log_data.src_port,
        current_log->log_data.dst_port,
        current_log->log_data.reason,
        current_log->log_data.count
    );

    // copy the log entry to the user
    if(copy_to_user(buf, log_buffer, len) != 0){
        return -EFAULT;
    }

    *pos += len;
    return len;
}