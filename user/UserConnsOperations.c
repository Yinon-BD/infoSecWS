#include "UserConnsOperations.h"

int conn_ip_to_string(uint32_t ip, char* str){
    struct in_addr ip_addr;
    ip_addr.s_addr = ip;
    if(inet_ntop(AF_INET, &ip_addr, str, INET_ADDRSTRLEN) == NULL){
        return -1;
    }
    strcat(str, " ");
    return 0;
}

int conn_state_to_string(uint8_t state, char* str){
    switch(state){
        case TCP_STATE_INIT:
            strcpy(str, "INIT");
            break;
        case TCP_STATE_CLOSED:
            strcpy(str, "CLOSED");
            break;
        case TCP_STATE_LISTEN:
            strcpy(str, "LISTEN");
            break;
        case TCP_STATE_SYN_SENT:
            strcpy(str, "SYN_SENT");
            break;
        case TCP_STATE_SYN_RECV:
            strcpy(str, "SYN_RECV");
            break;
        case TCP_STATE_ESTABLISHED:
            strcpy(str, "ESTABLISHED");
            break;
        case TCP_STATE_FIN_WAIT1:
            strcpy(str, "FIN_WAIT1");
            break;
        case TCP_STATE_FIN_WAIT2:
            strcpy(str, "FIN_WAIT2");
            break;
        case TCP_STATE_CLOSE_WAIT:
            strcpy(str, "CLOSE_WAIT");
            break;
        case TCP_STATE_LAST_ACK:
            strcpy(str, "LAST_ACK");
            break;
        case TCP_STATE_TIME_WAIT:
            strcpy(str, "TIME_WAIT");
            break;
        case TCP_STATE_CLOSING:
            strcpy(str, "CLOSING");
            break;
        default:
            return -1;
    }
    return 0;
}

int print_connection(char* line){
    connection_t conn;
    char print_buf[256];
    sscanf(line, "%u %u %hu %hu %hhu\n", &conn.src_ip, &conn.dst_ip, &conn.src_port, &conn.dst_port, &conn.state);
    // add src ip to print buffer
    if(conn_ip_to_string(conn.src_ip, STRING_TAIL(print_buf)) == -1){
        printf("Failed to convert src ip to string\n");
        return -1;
    }
    // add dst ip to print buffer
    if(conn_ip_to_string(conn.dst_ip, STRING_TAIL(print_buf)) == -1){
        printf("Failed to convert dst ip to string\n");
        return -1;
    }
    // add src port to print buffer
    sprintf(STRING_TAIL(print_buf), "%hu ", conn.src_port);
    // add dst port to print buffer
    sprintf(STRING_TAIL(print_buf), "%hu ", conn.dst_port);
    // add state to print buffer
    if(conn_state_to_string(conn.state, STRING_TAIL(print_buf)) == -1){
        printf("Failed to convert state to string\n");
        return -1;
    }
    printf("%s\n", print_buf);
    return 0;
}

int show_conns(void){
    FILE* fp = fopen(CONN_SYSFS_PATH, "rb");
    int num_conns;
    if(fp == NULL){
        perror("Failed to open conns device\n");
        return -1;
    }
    char line[256];
    // first read the number of connections
    if(fgets(line, sizeof(line), fp) == NULL){
        perror("Failed to read number of connections\n");
        fclose(fp);
        return -1;
    }
    sscanf(line, "%d", &num_conns);

    // if there is more than 0 connections, print the header of the table
    if(num_conns > 0){
        printf("src_ip\tdst_ip\tsrc_port\tdst_port\tstate\n");
    }

    // now read the connections
    for(int i = 0; i < num_conns; i++){
        if(fgets(line, sizeof(line), fp) == NULL){
            perror("Failed to read connection\n");
            fclose(fp);
            return -1;
        }
        if(print_connection(line) == -1){
            printf("Failed to print connection number %d.\n", i);
            fclose(fp);
            return -1;
        }
    }
    fclose(fp);
    return 0;
}