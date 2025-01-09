#include "ProxyDevice.h"

static proxy_connection_t proxy_connections[MAX_PROXY_CONNECTIONS];

void add_proxy_connection(connection_t *connection, __be16 localPort){
    proxy_connection[localPort].connection = connection;
    proxy_connection[localPort].active = 1;
}

void remove_proxy_connection(__be16 localPort){
    proxy_connection[localPort].active = 0;
}

connection_t *get_proxy_connection(__be16 localPort){
    if(proxy_connection[localPort].active){
        return proxy_connection[localPort].connection;
    }
    return NULL;
}