#ifndef PROXY_H
#define PROXY_H

#include "ConnectionTable.h"

typdef struct {
    __be32 client_ip,
    __be16 client_port,
    __be32 server_ip,
    __be16 server_port,
    __be16 proxy_port,
} proxy_t;

struct proxy_entry {
    struct list_head list;
    proxy_t proxy_data;
};

int create_proxy_connection(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, direction_t packet_direction);
int add_proxy_connection(__be32 client_ip, __be16 client_port, __be32 server_ip, __be16 server_port, __be16 proxy_port);
void remove_proxy_connection(__be32 client_ip, __be16 client_port, __be32 server_ip, __be16 server_port, __be16 proxy_port);
void clear_proxy_connections(void);
proxy_t *find_proxy_connection(__be32 client_ip, __be16 client_port, __be32 server_ip, __be16 server_port, __be16 proxy_port);

#endif // PROXY_H