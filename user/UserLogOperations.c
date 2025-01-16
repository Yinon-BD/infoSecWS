#include "UserLogOperations.h"

void fill_log(log_row_t* log, char* buffer){
    memcpy(&(log->timestamp), buffer, sizeof(unsigned long));
    buffer += sizeof(unsigned long);
    memcpy(&(log->protocol), buffer, sizeof(unsigned char));
    buffer += sizeof(unsigned char);
    memcpy(&(log->action), buffer, sizeof(unsigned char));
    buffer += sizeof(unsigned char);
    memcpy(&(log->src_ip), buffer, sizeof(uint32_t));
    buffer += sizeof(uint32_t);
    memcpy(&(log->dst_ip), buffer, sizeof(uint32_t));
    buffer += sizeof(uint32_t);
    memcpy(&(log->src_port), buffer, sizeof(uint16_t));
    buffer += sizeof(uint16_t);
    memcpy(&(log->dst_port), buffer, sizeof(uint16_t));
    buffer += sizeof(uint16_t);
    memcpy(&(log->reason), buffer, sizeof(reason_t));
    buffer += sizeof(reason_t);
    memcpy(&(log->count), buffer, sizeof(unsigned int));
    buffer += sizeof(unsigned int);
}

//convert a ktime_t timestamp to a human readable format DD/MM/YYYY HH:MM:SS
void print_timestamp(unsigned long timestamp){
    struct tm* tm_info;
    char buffer[26];
    
    tm_info = localtime((time_t*)&timestamp);

    strftime(buffer, sizeof(buffer), "%d/%m/%Y %H:%M:%S", tm_info);

    printf("%s", buffer);
}

// convert an ip address from uint32_t to a human readable format
void print_ip(uint32_t ip){
    struct in_addr ip_addr;
    ip_addr.s_addr = ip;
    printf("%s", inet_ntoa(ip_addr));
}

// convert a protocol from uint8_t to a human readable format
void print_protocol(unsigned char protocol){
    switch(protocol){
        case PROT_ICMP:
            printf("icmp");
            break;
        case PROT_TCP:
            printf("tcp");
            break;
        case PROT_UDP:
            printf("udp");
            break;
        default:
            printf("UNKNOWN");
            break;
    }
}

// convert an action from unsigned char to a human readable format
void print_action(unsigned char action){
    switch(action){
        case NF_ACCEPT:
            printf("accept");
            break;
        case NF_DROP:
            printf("drop");
            break;
        default:
            printf("UNKNOWN");
            break;
    }
}

// convert a reason from reason_t to a human readable format
void print_reason(reason_t reason){
    switch(reason){
        case REASON_FW_INACTIVE:
            printf("FW_INACTIVE");
            break;
        case REASON_NO_MATCHING_RULE:
            printf("NO_MATCHING_RULE");
            break;
        case REASON_XMAS_PACKET:
            printf("XMAS_PACKET");
            break;
        case REASON_ILLEGAL_VALUE:
            printf("ILLEGAL_VALUE");
            break;
        case REASON_UNMATCHING_STATE:
            printf("UNMATCHING_STATE");
            break;
        case REASON_MATCHING_STATE:
            printf("MATCHING_STATE");
            break;
        case REASON_PROXY_CONN:
            printf("PROXY_CONN");
            break;
        default:
            printf("%d", reason);
            break;
    }
}

// print a single log entry
// format of the log entry from buffer: <timestamp> <protocol> <action> <src_ip> <dst_ip> <src_port> <dst_port> <reason> <count>
int print_log_entry(char log_entry[]){
    log_row_t log_row;
    fill_log(&log_row, log_entry);
    print_timestamp(log_row.timestamp);
    printf("		");
    print_ip(log_row.src_ip);
    printf("		");
    print_ip(log_row.dst_ip);
    printf("		%hu		%hu		", log_row.src_port, log_row.dst_port);
    print_protocol(log_row.protocol);
    printf("		");
    print_action(log_row.action);
    printf("	");
    print_reason(log_row.reason);
    printf("				%u\n",log_row.count);
    return 0;
}

int show_log(void){
    int log_count = 0;
    size_t log_entry_size = sizeof(unsigned long) + sizeof(unsigned char) + sizeof(unsigned char) + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t) + sizeof(reason_t) + sizeof(unsigned int);
    FILE* fp = fopen(LOG_READ_PATH, "rb");
    if(fp == NULL){
        perror("Failed to open log device\n");
        return -1;
    }
    // first read the number of log entries
    if(fread(&log_count, sizeof(int), 1, fp) != 1){
        perror("Failed to read log count\n");
        fclose(fp);
        return -1;
    }
    printf("log count is %d\n", log_count);
    if(log_count == 0){
        return 0;
    }
    // the first print will be the title of the logs
    printf("timestamp			src_ip			dst_ip			src_port	dst_port	protocol	action	reason				count\n");
    // now read the log entries
    for(int i = 0; i < log_count; i++){
        char log_entry[log_entry_size];
        if(fread(log_entry, log_entry_size, 1, fp) != 1){
            perror("Failed to read log entry\n");
            fclose(fp);
            return -1;
        }
        //printf("raw form of log number %d\n", i+1 );
        //printf("%s\n", log_entry);
        if(print_log_entry(log_entry) == -1){
            printf("Failed to print log entry\n");
            fclose(fp);
            return -1;
        }
    }
    fclose(fp);
    return 0;
}

int clear_log(void){
    FILE* fp = fopen(LOG_SYSFS_PATH, "wb");
    if(fp == NULL){
        perror("Failed to open log reset device\n");
        return -1;
    }
    // write any data to the device to clear the log
    if(fwrite("1", 1, 1, fp) != 1){
        perror("Failed to write to log reset device\n");
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}