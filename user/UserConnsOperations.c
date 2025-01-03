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

fill_connection(connection_t* conn, char* line){
    memcpy(&(conn->src_ip), line, sizeof(uint32_t));
    line += sizeof(uint32_t);
    memcpy(&(conn->dst_ip), line, sizeof(uint32_t));
    line += sizeof(uint32_t);
    memcpy(&(conn->src_port), line, sizeof(uint16_t));
    line += sizeof(uint16_t);
    memcpy(&(conn->dst_port), line, sizeof(uint16_t));
    line += sizeof(uint16_t);
    memcpy(&(conn->state), line, sizeof(uint8_t));
}

int print_connection(char* line){
    connection_t conn;
    char print_buf[256];
    fill_connection(&conn, line);
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
    uint32_t num_conns;
    if(fp == NULL){
        perror("Failed to open conns device\n");
        return -1;
    }
    // first read the number of connections
    if(fread(&num_conns, sizeof(uint32_t), 1, fp) != 1){
        perror("Failed to read number of connections\n");
        fclose(fp);
        return -1;
    }

    // if there is more than 0 connections, print the header of the table
    if(num_conns > 0){
        printf("src_ip\tdst_ip\tsrc_port\tdst_port\tstate\n");
    }
    int conn_entry_size = sizeof(uint32_t) * 2 + sizeof(uint16_t) * 2 + sizeof(uint8_t);
    char connection[conn_entry_size];
    // now read the connections
    for(int i = 0; i < num_conns; i++){
        if(fread(connection, conn_entry_size, 1, fp) == NULL){
            perror("Failed to read connection\n");
            fclose(fp);
            return -1;
        }
        if(print_connection(connection) == -1){
            printf("Failed to print connection number %d.\n", i);
            fclose(fp);
            return -1;
        }
    }
    fclose(fp);
    return 0;
}