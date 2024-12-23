#ifndef CONNECTION_TABLE_H
#define CONNECTION_TABLE_H

#include <linux/list.h>
#include "fw.h"

typedef struct {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 state;;
} connection_t;

// create enum for TCP states
typedef enum {
    TCP_STATE_CLOSED = 0,
    TCP_STATE_LISTEN,
    TCP_STATE_SYN_SENT,
    TCP_STATE_SYN_RECV,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_FIN_WAIT1,
    TCP_STATE_FIN_WAIT2,
    TCP_STATE_CLOSE_WAIT,
    TCP_STATE_LAST_ACK,
    TCP_STATE_TIME_WAIT,
    TCP_STATE_CLOSING,
} tcp_state_t;

struct connection_entry {
    struct list_head list;
    connection_t connection_data;
};

// create enum for TCP packet types
typedef enum {
    TCP_SYN = 0,
    TCP_SYN_ACK,
    TCP_ACK,
    TCP_FIN,
    TCP_FIN_ACK,
    TCP_RST,
    TCP_RST_ACK,
    TCP_UNKNOWN,
} tcp_packet_t;

void add_connection(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, __u8 state);

void remove_connection(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port);

void clear_connection_table(void);

void update_connection_state(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, __u8 state);

__u8 get_connection_state(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port);

ssize_t display_connection_table(struct device *dev, struct device_attribute *attr, char *buf);

#endif // CONNECTION_TABLE_H