#ifndef PROXY_H
#define PROXY_H

#include "ConnectionTable.h"

typedef struct {
    __be32 client_ip;
    __be16 client_port;
    __be32 server_ip;
    __be16 server_port;
    __be16 proxy_port;
} proxy_t;

struct proxy_entry {
    struct list_head list;
    proxy_t proxy_data;
};

int create_proxy_connection(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, direction_t packet_direction);
void add_proxy_connection(__be32 client_ip, __be16 client_port, __be32 server_ip, __be16 server_port, __be16 proxy_port);
void remove_proxy_connection(__be32 client_ip, __be16 client_port, __be32 server_ip, __be16 server_port);
void clear_proxy_connections(void);
proxy_t *find_proxy_connection(__be32 client_ip, __be16 client_port, __be32 server_ip, __be16 server_port);
void find_src_ip_and_port(__be32 *src_ip, __be16 *src_port, __be32 dst_ip, __be16 dst_port, __be16 proxy_port, direction_t packet_direction);
ssize_t display_proxy_table(struct device *dev, struct device_attribute *attr, char *buf);
ssize_t store_proxy_device(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
void reroute_incoming_packet(struct sk_buff *skb, __be16 proxy_port, direction_t packet_direction);
void reroute_outgoing_packet(struct sk_buff *skb, __be16 proxy_port, __be16 dst_port, direction_t packet_direction);
void fix_checksums(struct sk_buff *skb);

#endif // PROXY_H