#include "LogDevice.h"

static LIST_HEAD(log_list); // Initialize the list
static __u32 log_list_len = 0;
static __u8 passed_len = 0; // flag to indicate if the log list length was passed
static int reached_end = 0; // flag to indicate if we reached the end of the list when passing data
struct firewall_log *current_log = NULL; // pointer to the current log entry when reading from the log device

void fill_buffer(log_row_t* log_row, char* buf){
    // format of the log entry: <timestamp> <protocol> <action> <src_ip> <dst_ip> <src_port> <dst_port> <reason> <count>
    memcpy(buf, &(log_row->timestamp), sizeof(unsigned long));
    buf += sizeof(unsigned long);
    memcpy(buf, &(log_row->protocol), sizeof(unsigned char));
    buf += sizeof(unsigned char);
    memcpy(buf, &(log_row->action), sizeof(unsigned char));
    buf += sizeof(unsigned char);
    memcpy(buf, &(log_row->src_ip), sizeof(__be32));
    buf += sizeof(__be32);
    memcpy(buf, &(log_row->dst_ip), sizeof(__be32));
    buf+= sizeof(__be32);
    memcpy(buf, &(log_row->src_port), sizeof(__be16));
    buf += sizeof(__be16);
    memcpy(buf, &(log_row->dst_port), sizeof(__be16));
    buf += sizeof(__be16);
    memcpy(buf, &(log_row->reason), sizeof(reason_t));
    buf += sizeof(reason_t);
    memcpy(buf, &(log_row->count), sizeof(unsigned int));
    buf += sizeof(unsigned int);
}

void set_log_address_and_protocol(log_row_t *log_row, __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, __u8 protocol){
    log_row->src_ip = src_ip;
    log_row->dst_ip = dst_ip;
    log_row->src_port = src_port;
    log_row->dst_port = dst_port;
    log_row->protocol = protocol;
    log_row->timestamp = ktime_get_real_seconds();
}

__u8 compare_logs(log_row_t *log_row, log_row_t *log_row2){
    if(log_row->src_ip == log_row2->src_ip && log_row->dst_ip == log_row2->dst_ip && log_row->src_port == log_row2->src_port && log_row->dst_port == log_row2->dst_port && log_row->protocol == log_row2->protocol && log_row->action == log_row2->action){
        return 1;
    }
    return 0;
}

void log_it(log_row_t *log_row, reason_t reason, unsigned char action){
    log_row->reason = reason;
    log_row->action = action;
    log_row->count = 1;

    // iterate over the list and check if the log already exists
    struct firewall_log *entry;
    list_for_each_entry(entry, &log_list, list){
        if(compare_logs(&entry->log_data, log_row)){ // added a check for action because our fw is stateful now
            entry->log_data.count++;
            entry->log_data.timestamp = log_row->timestamp;
            return;
        }
    }
    // if the log does not exist, create a new entry
    struct firewall_log *new_log = (struct firewall_log*)kmalloc(sizeof(struct firewall_log), GFP_KERNEL);
    new_log->log_data = *log_row;
    new_log->log_data.count = 1;
    list_add_tail(&new_log->list, &log_list);
    log_list_len++;
}

void clear_log(void){
    struct firewall_log *entry, *tmp;
    list_for_each_entry_safe(entry, tmp, &log_list, list){
        list_del(&entry->list);
        kfree(entry);
    }
    log_list_len = 0;
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
    reached_end = 0;
    print_logs();
    return 0;
}

// "read" function for the log char device
ssize_t read_log_device(struct file *file, char __user *buf, size_t count, loff_t *pos){
    
    struct firewall_log *entry;
    int log_buffer_size = sizeof(unsigned long) + sizeof(unsigned char) + sizeof(unsigned char) + sizeof(__be32) + sizeof(__be32) + sizeof(__be16) + sizeof(__be16) + sizeof(reason_t) + sizeof(unsigned int);
    char log_buffer[log_buffer_size];
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

    // Ensure there is enough space in the buffer to hold the log entry
    if(count < log_buffer_size){
        return -EINVAL;
    }
    /*// printing the current log for debug purposes
    printk(KERN_INFO "Passing this Log entry: timestamp: %lu, protocol: %u, action: %hhu, src_ip: %pI4, dst_ip: %pI4, src_port: %hu, dst_port: %hu, reason: %d, count: %u\n",
            current_log->log_data.timestamp,
            current_log->log_data.protocol,
            current_log->log_data.action,
            &current_log->log_data.src_ip,
            &current_log->log_data.dst_ip,
            current_log->log_data.src_port,
            current_log->log_data.dst_port,
            current_log->log_data.reason,
            current_log->log_data.count
        ); */
    fill_buffer(&current_log->log_data, log_buffer);
    
    if(count < log_buffer_size){
        // not enough space to pass log
        return len;
    }

    // copy the log entry to the user
    if(copy_to_user(buf, log_buffer, log_buffer_size) != 0){
        return -EFAULT;
    }

    len += log_buffer_size;
    count -= log_buffer_size;
    buf += log_buffer_size;
    return len;
}

// debug function to print the log list to the kernel log
void print_logs(void){
    struct firewall_log *entry;
    printk(KERN_INFO "Log list length: %u\n", log_list_len);
    list_for_each_entry(entry, &log_list, list){
        printk(KERN_INFO "Log entry: timestamp: %lu, protocol: %u, action: %hhu, src_ip: %pI4, dst_ip: %pI4, src_port: %hu, dst_port: %hu, reason: %d, count: %u\n",
            entry->log_data.timestamp,
            entry->log_data.protocol,
            entry->log_data.action,
            &entry->log_data.src_ip,
            &entry->log_data.dst_ip,
            entry->log_data.src_port,
            entry->log_data.dst_port,
            entry->log_data.reason,
            entry->log_data.count
        );
    }
}
