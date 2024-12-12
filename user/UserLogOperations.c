#include "UserLogOperations.h"

//convert a ktime_t timestamp to a human readable format DD/MM/YYYY HH:MM:SS
void print_timestamp(unsigned long timestamp){
    struct tm* tm_info;
    char buffer[26];
    
    tm_info = localtime((time_t*)&timestamp);

    strftime(buffer, sizeof(buffer), "%d/%m/%Y %H:%M:%S", tm_info);

    printf("%s", buffer);
}

// print a single log entry
// format of the log entry from buffer: <timestamp> <protocol> <action> <src_ip> <dst_ip> <src_port> <dst_port> <reason> <count>
int print_log_entry(char log_entry[]){
    log_row_t log_row;
    sscanf(log_entry, "%lu %hhu %hhu %u %u %hu %hu %hhu %u", &log_row.timestamp, &log_row.protocol, &log_row.action, &log_row.src_ip, &log_row.dst_ip, &log_row.src_port, &log_row.dst_port, &log_row.reason, &log_row.count);
    print_timestamp(log_row.timestamp);
    printf("		");
    printf("%u		%u		%hu		%hu		%hhu		%hhu	%hhu				%u\n", log_row.src_ip, log_row.dst_ip, log_row.src_port, log_row.dst_port, log_row.protocol, log_row.action, log_row.reason, log_row.count);
    return 0;
}

int show_log(void){
    int log_count = 0;
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
    // the first print will be the title of the logs
    printf("timestamp			src_ip			dst_ip			src_port	dst_port	protocol	action	reason				count\n");
    // now read the log entries
    for(int i = 0; i < log_count; i++){
        char log_entry[LOG_ENTRY_SIZE];
        if(fread(log_entry, LOG_ENTRY_SIZE, 1, fp) != 1){
            perror("Failed to read log entry\n");
            fclose(fp);
            return -1;
        }
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