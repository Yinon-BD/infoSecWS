#ifndef USR_CONN_H
#define USR_CONN_H

#include "UserParser.h"

#define CONN_SYSFS_PATH "/sys/class/fw/conns/conns"

#define STRING_TAIL(x) (x + strlen(x))

int show_conns(void);

typedef struct{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t state;
} connection_t;

// create enum for TCP states
typedef enum {
    TCP_STATE_INIT = 0, // fake state for the initial connection
    TCP_STATE_CLOSED,
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

#endif // USR_CONN_H