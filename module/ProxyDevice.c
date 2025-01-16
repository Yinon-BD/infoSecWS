#include "ProxyDevice.h"

static LIST_HEAD(proxy_connections);
static __u32 proxy_connections_len = 0;


int create_proxy_connection(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, direction_t packet_direction){
    // check if the direction is from the client to the server
    if(packet_direction == DIRECTION_OUT){
        // check if the destination port is a HTTP port
        if(dst_port == 80){
            add_proxy_connection(src_ip, src_port, dst_ip, dst_port, 0); // the proxy port is not known yet
            add_connection(src_ip, dst_ip, src_port, dst_port, TCP_STATE_PROXY);
            add_connection(dst_ip, src_ip, dst_port, src_port, TCP_STATE_PROXY);
            return 1;
        }
        return 0;
    }
    return 0;
}

void add_proxy_connection(__be32 client_ip, __be16 client_port, __be32 server_ip, __be16 server_port, __be16 proxy_port){
    proxy_t new_proxy_connection;
    new_proxy_connection.client_ip = client_ip;
    new_proxy_connection.client_port = client_port;
    new_proxy_connection.server_ip = server_ip;
    new_proxy_connection.server_port = server_port;
    new_proxy_connection.proxy_port = proxy_port;

    // iterate over the list and check if the connection already exists
    struct proxy_entry *entry;
    list_for_each_entry(entry, &proxy_connections, list){
        if(entry->proxy_data.client_ip == new_proxy_connection.client_ip && entry->proxy_data.client_port == new_proxy_connection.client_port
        && entry->proxy_data.server_ip == new_proxy_connection.server_ip && entry->proxy_data.server_port == new_proxy_connection.server_port
        && entry->proxy_data.proxy_port == new_proxy_connection.proxy_port){
            return;
        }
    }
    // if the connection does not exist, create a new entry
    struct proxy_entry *new_entry = (struct proxy_entry*)kmalloc(sizeof(struct proxy_entry), GFP_KERNEL);
    new_entry->proxy_data = new_proxy_connection;
    list_add_tail(&new_entry->list, &proxy_connections);
    proxy_connections_len++;
}

void remove_proxy_connection(__be32 client_ip, __be16 client_port, __be32 server_ip, __be16 server_port){
    struct proxy_entry *entry, *tmp;
    list_for_each_entry_safe(entry, tmp, &proxy_connections, list){
        if(entry->proxy_data.client_ip == client_ip && entry->proxy_data.client_port == client_port
        && entry->proxy_data.server_ip == server_ip && entry->proxy_data.server_port == server_port)
        {
            list_del(&entry->list);
            kfree(entry);
            proxy_connections_len--;
            return;
        }
    }
}

void find_src_ip_and_port(__be32 *src_ip, __be16 *src_port, __be32 dst_ip, __be16 dst_port, __be16 proxy_port, direction_t packet_direction){
    struct proxy_entry *entry;
    list_for_each_entry(entry, &proxy_connections, list){
        if(packet_direction == DIRECTION_OUT){ // source = client, destination = server
            if(entry->proxy_data.server_ip == dst_ip && entry->proxy_data.server_port == dst_port
            && entry->proxy_data.proxy_port == proxy_port){
                *src_ip = entry->proxy_data.client_ip;
                *src_port = entry->proxy_data.client_port;
                return;
            }
        }
        else{ // source = server, destination = client
            if(entry->proxy_data.client_ip == dst_ip && entry->proxy_data.client_port == dst_port){
                *src_ip = entry->proxy_data.server_ip;
                *src_port = entry->proxy_data.server_port;
                return;
            }
        }
    }
}

void clear_proxy_connections(void){
    struct proxy_entry *entry, *tmp;
    list_for_each_entry_safe(entry, tmp, &proxy_connections, list){
        list_del(&entry->list);
        kfree(entry);
    }
    proxy_connections_len = 0;
}

proxy_t* find_proxy_connection(__be32 client_ip, __be16 client_port, __be32 server_ip, __be16 server_port){
    struct proxy_entry *entry;
    list_for_each_entry(entry, &proxy_connections, list){
        if(entry->proxy_data.client_ip == client_ip && entry->proxy_data.client_port == client_port
        && entry->proxy_data.server_ip == server_ip && entry->proxy_data.server_port == server_port){
            return &(entry->proxy_data);
        }
    }
    return NULL;
}

void fix_checksums(struct sk_buff *skb){ // this function corrects the TCP and IP's checksum fields after modifying the packet
    struct iphdr *ip_header = ip_hdr(skb);
    struct tcphdr *tcp_header = tcp_hdr(skb);

    // Fix TCP header checksum
    int tcplen = (ntohs(ip_header->tot_len) - ((ip_header->ihl) << 2));
    tcp_header->check = 0;
    tcp_header->check =
        tcp_v4_check(tcplen, ip_header->saddr, ip_header->daddr, csum_partial((char *)tcp_header, tcplen, 0));

    // Fix IP header checksum
    ip_header->check = 0;
    ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);
    skb->ip_summed = CHECKSUM_NONE;
}

void reroute_incoming_packet(struct sk_buff *skb, __be16 proxy_port, direction_t packet_direction){
    struct iphdr *ip_header = ip_hdr(skb);
    struct tcphdr *tcp_header = tcp_hdr(skb);
    __be32 src_ip = ip_header->saddr;
    __be32 dst_ip = ip_header->daddr;
    __be16 src_port = tcp_header->source;
    __be16 dst_port = tcp_header->dest;

    printk(KERN_INFO "Receiving packet from: IP - %pI4 Port - %hu\n", &src_ip, ntohs(src_port));

    if(packet_direction == DIRECTION_OUT){ // client to server, we need to change the destination IP to fw in leg and port based on original dst port
        if(dst_port == htons(80)){
            tcp_header->dest = htons(800);
        }
        else if(dst_port == htons(21)){
            tcp_header->dest = htons(210);
        }
        ip_header->daddr = htonl(FW_IN_LEG);
    }
    else{ // server to client, we need to change the destination IP to fw out leg and the dst port to the proxy port
        ip_header->daddr = htonl(FW_OUT_LEG);
        tcp_header->dest = htons(proxy_port);
    }
    fix_checksums(skb);
    printk(KERN_INFO "Spoofed incoming packet data:\n");
    printk(KERN_INFO "IP dest: %pI4 Port dest: %hu \n", &(ip_header->daddr), ntohs(tcp_header->dest));
}

void reroute_outgoing_packet(struct sk_buff *skb, __be16 proxy_port, __be16 dst_port, direction_t packet_direction){
    struct iphdr *ip_header = ip_hdr(skb);
    struct tcphdr *tcp_header = tcp_hdr(skb);
    __be32 src_ip;
    __be16 src_port;
	__be32 dst_ip = ip_header->daddr;
	__u8 protocol = ip_header->protocol;

    if(protocol != PROT_TCP){
        return 0;
    }

    printk(KERN_INFO "sending packet to: IP - %pI4 Port - %hu\n", &dst_ip, dst_port);
    printk(KERN_INFO "source port: %hu\n", proxy_port);

    find_src_ip_and_port(&src_ip, &src_port, dst_ip, dst_port, proxy_port, packet_direction);
    // set the new source IP and port
    ip_header->saddr = src_ip;
    tcp_header->source = htons(src_port);
    fix_checksums(skb);
    printk(KERN_INFO "Spoofed outgoing packet data:\n");
    printk(KERN_INFO "IP src: %pI4 Port src: %hu \n", &(ip_header->saddr), ntohs(tcp_header->source));
}

void fill_proxy_buffer(char *buf, proxy_t *proxy){
    memcpy(buf, &(proxy->client_ip), sizeof(__be32));
    buf += sizeof(__be32);
    memcpy(buf, &(proxy->client_port), sizeof(__be16));
    buf += sizeof(__be16);
    memcpy(buf, &(proxy->server_ip), sizeof(__be32));
    buf += sizeof(__be32);
    memcpy(buf, &(proxy->server_port), sizeof(__be16));
    buf += sizeof(__be16);
    memcpy(buf, &(proxy->proxy_port), sizeof(__be16));
}

// Function that will pass the proxy connections to user space
ssize_t display_proxy_table(struct device *dev, struct device_attribute *attr, char *buf){
    int i = 0;
    ssize_t len = 0;
    struct proxy_entry *entry;
    proxy_t proxy;
    int proxy_entry_size = sizeof(__be32) * 2 + sizeof(__be16) * 3;

    memcpy(buf, &proxy_connections_len, sizeof(__u32));
    buf += sizeof(__u32);

    list_for_each_entry(entry, &proxy_connections, list){
        proxy = entry->proxy_data;
        fill_proxy_buffer(buf, &proxy);
        buf += proxy_entry_size;
    }
    len = sizeof(__u32) + proxy_connections_len * proxy_entry_size;
    return len;
}

void extract_address_from_buffer(const char *buf, __be32 *client_ip, __be16 *client_port, __be16 *proxy_port){
    memcpy(client_ip, buf, sizeof(__be32));
    buf += sizeof(__be32);
    memcpy(client_port, buf, sizeof(__be16));
    buf += sizeof(__be16);
    memcpy(proxy_port, buf, sizeof(__be16));
}

void find_server_address(__be32 client_ip, __be16 client_port, __be32 *server_ip, __be16 *server_port){
    struct proxy_entry *entry;
    list_for_each_entry(entry, &proxy_connections, list){
        if(entry->proxy_data.client_ip == client_ip && entry->proxy_data.client_port == client_port){
            *server_ip = entry->proxy_data.server_ip;
            *server_port = entry->proxy_data.server_port;
            return;
        }
    }
}

// Store function for the proxy char device
// The user will pass the proxy connection in the following format:
// <client_ip> <client_port> <proxy_port>
// the function will look for the client_ip and client_port in the proxy connections list
// if it finds a match, it will update the proxy_port
// if the proxy port is 0, it means the connection is terminated and we need to remove it from the conns and proxy conns lists

ssize_t store_proxy_device(struct device *dev, struct device_attribute *attr, const char *buf, size_t count){
    __be32 buffer_size = sizeof(__be32) + sizeof(__be16) * 2;
    __be32 client_ip;
    __be16 client_port;
    __be16 proxy_port;
    struct proxy_entry *entry;
    proxy_t proxy;

    extract_address_from_buffer(buf, &client_ip, &client_port, &proxy_port);

    printk(KERN_INFO "New info from proxy server\n");
    printk(KERN_INFO "cIP: %pI4 cPort: %hu proxy: %hu\n", &client_ip, client_port, proxy_port);

    if(proxy_port == 0){
        // we need to find the matching server address and remove the connection
        __be32 server_ip;
        __be16 server_port;
        find_server_address(client_ip, client_port, &server_ip, &server_port);
        remove_connection(client_ip, server_ip, client_port, server_port);
        remove_connection(server_ip, client_ip, server_port, client_port);
        remove_proxy_connection(client_ip, client_port, server_ip, server_port);
        printk(KERN_INFO "proxy connection removed successfuly!\n");
        return count;
    }

    list_for_each_entry(entry, &proxy_connections, list){
        proxy = entry->proxy_data;
        if(proxy.client_ip == client_ip && proxy.client_port == client_port){
            entry->proxy_data.proxy_port = proxy_port;
            printk(KERN_INFO "proxy port updated successfuly!\n");
            return count;
        }
    }
    return -EINVAL;
}

