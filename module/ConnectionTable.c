#include "ConnectionTable.h"

// The connection table will be implemented as a linked list
static LIST_HEAD(connection_table);
static __u32 connection_table_len = 0;
struct connection_entry *current_connection = NULL; // pointer to the current connection entry when reading from the connection table

// Function to add a new connection to the connection table
void add_connection(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, __u8 state){
    connection_t new_connection;
    new_connection.src_ip = src_ip;
    new_connection.dst_ip = dst_ip;
    new_connection.src_port = src_port;
    new_connection.dst_port = dst_port;
    new_connection.state = state;

    // iterate over the list and check if the connection already exists
    struct connection_entry *entry;
    list_for_each_entry(entry, &connection_table, list){
        if(entry->connection_data.src_ip == new_connection.src_ip && entry->connection_data.dst_ip == new_connection.dst_ip
        && entry->connection_data.src_port == new_connection.src_port && entry->connection_data.dst_port == new_connection.dst_port){
            entry->connection_data.state = new_connection.state;
            return;
        }
    }
    // if the connection does not exist, create a new entry
    struct connection_entry *new_entry = (struct connection_entry*)kmalloc(sizeof(struct connection_entry), GFP_KERNEL);
    new_entry->connection_data = new_connection;
    list_add_tail(&new_entry->list, &connection_table);
    connection_table_len++;
}

// Function to remove a connection from the connection table
void remove_connection(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port){
    struct connection_entry *entry, *tmp;
    list_for_each_entry_safe(entry, tmp, &connection_table, list){
        if(entry->connection_data.src_ip == src_ip && entry->connection_data.dst_ip == dst_ip
        && entry->connection_data.src_port == src_port && entry->connection_data.dst_port == dst_port){
            list_del(&entry->list);
            kfree(entry);
            connection_table_len--;
            return;
        }
    }
}

// Function to clear the connection table
void clear_connection_table(void){
    struct connection_entry *entry, *tmp;
    list_for_each_entry_safe(entry, tmp, &connection_table, list){
        list_del(&entry->list);
        kfree(entry);
    }
    connection_table_len = 0;
}

// Function to update the state of a connection in the connection table
void update_connection_state(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, __u8 state){
    struct connection_entry *entry;
    list_for_each_entry(entry, &connection_table, list){
        if(entry->connection_data.src_ip == src_ip && entry->connection_data.dst_ip == dst_ip
        && entry->connection_data.src_port == src_port && entry->connection_data.dst_port == dst_port){
            entry->connection_data.state = state;
            return;
        }
    }
}

// Function to get the state of a connection in the connection table
__u8 get_connection_state(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port){
    struct connection_entry *entry;
    list_for_each_entry(entry, &connection_table, list){
        if(entry->connection_data.src_ip == src_ip && entry->connection_data.dst_ip == dst_ip
        && entry->connection_data.src_port == src_port && entry->connection_data.dst_port == dst_port){
            return entry->connection_data.state;
        }
    }
    return TCP_STATE_CLOSED;
}

// Function to pass the connection table to user space
ssize_t display_connection_table(struct device *dev, struct device_attribute *attr, char *buf){
    int i = 0;
    ssize_t len = 0;

    if(connection_table_len == 0){
        return scnprintf(buf, PAGE_SIZE, "0\n");
    }

    // send to the user the number of connections
    len += scnprintf(buf + len, PAGE_SIZE - len, "%u\n", connection_table_len);

    struct connection_entry *entry;
    list_for_each_entry(entry, &connection_table, list){
        connection_t connection = entry->connection_data;
        len += scnprintf(buf + len, PAGE_SIZE - len, "%u %u %hu %hu %hhu\n",
         connection.src_ip, connection.dst_ip, connection.src_port, connection.dst_port, connection.state);
    }

    return len;
}

// Function to find a connection in the connection table, returns a pointer to the connection entry if found, NULL otherwise
struct connection_entry *find_connection(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port){
    struct connection_entry *entry;
    list_for_each_entry(entry, &connection_table, list){
        if(entry->connection_data.src_ip == src_ip && entry->connection_data.dst_ip == dst_ip
        && entry->connection_data.src_port == src_port && entry->connection_data.dst_port == dst_port){
            return entry;
        }
    }
    return NULL;
}

// a debug function that prints the connections to the kernel log
void print_connections(void){
    struct connection_entry *entry;
    printk(KERN_INFO "Connection table length: %u\n", connection_table_len);
    list_for_each_entry(entry, &connection_table, list){
        connection_t connection = entry->connection_data;
        printk(KERN_INFO "Connection: src_ip: %pI4, dst_ip: %pI4, src_port: %hu, dst_port: %hu, state: %hhu\n",
         &connection.src_ip, &connection.dst_ip, connection.src_port, connection.dst_port, connection.state);
    }
}
