#ifndef PROXY_H
#define PROXY_H

#include "ConnectionTable.h"

#define MAX_PROXY_CONNECTIONS 65536

typdef struct {
    connection_t *connection,
    __be8 active,
} proxy_connection_t;

#endif // PROXY_H