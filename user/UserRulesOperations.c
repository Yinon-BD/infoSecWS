#include "UserRulesOperations.h"

char *my_itoa(unsigned int number, char* str){
    if(str == NULL){
        return NULL;
    }
    sprintf(str, "%u", number);
    return str;
}

int direction_to_string(direction_t direction, char* str){
    switch(direction){
        case DIRECTION_IN:
            strcpy(str, "in ");
            break;
        case DIRECTION_OUT:
            strcpy(str, "out ");
            break;
        case DIRECTION_ANY:
            strcpy(str, "any ");
            break;
        default:
            return -1;
    }
    return 0;
}

// convert ip address to string of the form "x.x.x.x/y"
int ip_to_string(uint32_t ip, uint32_t mask, uint32_t size, char* str){
    struct in_addr ip_addr;
    struct in_addr mask_addr;
    ip_addr.s_addr = ip;
    mask_addr.s_addr = mask;
    char size_buf[3];
    // first check if IP is any
    if(ip == 0 && mask == 0 && size == 0){
        strcpy(str, "any ");
        return 0;
    }
    if(inet_ntop(AF_INET, &ip_addr, str, INET_ADDRSTRLEN) == NULL){
        return -1;
    }
    strcat(str, "/");
    snprintf(size_buf, sizeof(size_buf), "%d", size);
    strcat(str, size_buf);
    strcat(str, " ");
    return 0;
}

int port_to_string(uint16_t port, char* str){
    // check if port number is valid
    if(port < 0 || port > 65535){
        return -1;
    }
    if(port == 0){
        strcpy(str, "any ");
    }
    else if(port == PORT_ABOVE_1023){
        strcpy(str, ">1023 ");
    }
    else{
        sprintf(str, "%d ", port);
    }
    return 0;
}

int protocol_to_string(uint8_t protocol, char* str){
    switch(protocol){
        case PROT_ICMP:
            strcpy(str, "ICMP ");
            break;
        case PROT_TCP:
            strcpy(str, "TCP ");
            break;
        case PROT_UDP:
            strcpy(str, "UDP ");
            break;
        case PROT_OTHER:
            strcpy(str, "other ");
            break;
        case PROT_ANY:
            strcpy(str, "any ");
            break;
        default:
            return -1;
    }
    return 0;
}

int ack_to_string(ack_t ack, char* str){
    switch(ack){
        case ACK_NO:
            strcpy(str, "no ");
            break;
        case ACK_YES:
            strcpy(str, "yes ");
            break;
        case ACK_ANY:
            strcpy(str, "any ");
            break;
        default:
            return -1;
    }
    return 0;
}

int action_to_string(uint8_t action, char* str){
    switch(action){
        case NF_ACCEPT:
            strcpy(str, "accept");
            break;
        case NF_DROP:
            strcpy(str, "drop");
            break;
        default:
            return -1;
    }
    return 0;
}

int print_rule(char* line){
    rule_t rule;
    char print_buf[256];
    sscanf(line, "%s %d %u %u %u %u %u %u %u %u %u %u %u\n",
    rule.rule_name, &rule.direction, &rule.src_ip, &rule.src_prefix_mask, &rule.src_prefix_size, &rule.dst_ip, &rule.dst_prefix_mask, &rule.dst_prefix_size, &rule.src_port, &rule.dst_port, &rule.protocol, &rule.ack, &rule.action);
    strcpy(print_buf, rule.rule_name);
    strcat(print_buf, " ");
    // add direction to print buffer
    if(direction_to_string(rule.direction, STRING_TAIL(print_buf)) == -1){
        printf("Failed to convert direction to string\n");
        return -1;
    }
    // add src ip and mask to print buffer
    if(ip_to_string(rule.src_ip, rule.src_prefix_mask, rule.src_prefix_size, STRING_TAIL(print_buf)) == -1){
        printf("Failed to convert src ip to string\n");
        return -1;
    }
    // add dst ip and mask to print buffer
    if(ip_to_string(rule.dst_ip, rule.dst_prefix_mask, rule.dst_prefix_size, STRING_TAIL(print_buf)) == -1){
        printf("Failed to convert dst ip to string\n");
        return -1;
    }
    // add protocol to print buffer
    if(protocol_to_string(rule.protocol, STRING_TAIL(print_buf)) == -1){
        printf("Failed to convert protocol to string\n");
        return -1;
    }
    // add src port to print buffer
    if(port_to_string(rule.src_port, STRING_TAIL(print_buf)) == -1){
        printf("Failed to convert src port to string\n");
        return -1;
    }
    // add dst port to print buffer
    if(port_to_string(rule.dst_port, STRING_TAIL(print_buf)) == -1){
        printf("Failed to convert dst port to string\n");
        return -1;
    }
    // add ack to print buffer
    if(ack_to_string(rule.ack, STRING_TAIL(print_buf)) == -1){
        printf("Failed to convert ack to string\n");
        return -1;
    }
    // add action to print buffer
    if(action_to_string(rule.action, STRING_TAIL(print_buf)) == -1){
        printf("Failed to convert action to string\n");
        return -1;
    }
    printf("%s\n", print_buf);
    return 0;
}

// convert a rule_t struct to a buffer to send to the device
// buffer format: <rule_name> <direction> <src_ip> <src_prefix_mask> <src_prefix_size> <dst_ip> <dst_prefix_mask> <dst_prefix_size> <src_port> <dst_port> <protocol> <ack> <action>
int rule_to_buffer(rule_t* rule, char* buf){
    // first add rule name to buffer
    strcpy(buf, rule->rule_name);
    strcat(buf, " ");
    // add direction to buffer
    my_itoa(rule->direction, STRING_TAIL(buf));
    strcat(buf, " ");
    // add src ip to buffer
    my_itoa(rule->src_ip, STRING_TAIL(buf));
    strcat(buf, " ");
    // add src prefix mask to buffer
    my_itoa(rule->src_prefix_mask, STRING_TAIL(buf));
    strcat(buf, " ");
    // add src prefix size to buffer
    my_itoa(rule->src_prefix_size, STRING_TAIL(buf));
    strcat(buf, " ");
    // add dst ip to buffer
    my_itoa(rule->dst_ip, STRING_TAIL(buf));
    strcat(buf, " ");
    // add dst prefix mask to buffer
    my_itoa(rule->dst_prefix_mask, STRING_TAIL(buf));
    strcat(buf, " ");
    // add dst prefix size to buffer
    my_itoa(rule->dst_prefix_size, STRING_TAIL(buf));
    strcat(buf, " ");
    // add src port to buffer
    my_itoa(rule->src_port, STRING_TAIL(buf));
    strcat(buf, " ");
    // add dst port to buffer
    my_itoa(rule->dst_port, STRING_TAIL(buf));
    strcat(buf, " ");
    // add protocol to buffer
    my_itoa(rule->protocol, STRING_TAIL(buf));
    strcat(buf, " ");
    // add ack to buffer
    my_itoa(rule->ack, STRING_TAIL(buf));
    strcat(buf, " ");
    // add action to buffer
    my_itoa(rule->action, STRING_TAIL(buf));
    return 0;
}

int show_rules(void){
    FILE* fp = fopen(RULES_SYSFS_PATH, "rb");
    int num_rules;
    if(fp == NULL){
        perror("Failed to open rules device\n");
        return -1;
    }
    char line[256];
    // first read the number of rules
    if(fgets(line, sizeof(line), fp) == NULL){
        perror("Failed to read number of rules\n");
        fclose(fp);
        return -1;
    }
    sscanf(line, "%d", &num_rules);

    // now read the rules
    for(int i = 0; i < num_rules; i++){
        if(fgets(line, sizeof(line), fp) == NULL){
            perror("Failed to read rule\n");
            fclose(fp);
            return -1;
        }
        if(print_rule(line) == -1){
            printf("Failed to print rule\n");
            fclose(fp);
            return -1;
        }
    }
    fclose(fp);
    return 0;
}

int load_rules(char *file_path){
    rule_t rule_table[MAX_RULES];
    int num_rules = 0;
    FILE* fp = fopen(file_path, "rb");
    if(fp == NULL){
        perror("Failed to open local rule table file\n");
        return -1;
    }
    char line[256];
    while(fgets(line, sizeof(line), fp) != NULL){
        if(string_to_rule(line, &rule_table[num_rules]) == -1){
            printf("Failed to convert string to rule in line %d.\n", num_rules);
            fclose(fp);
            return -1;
        }
        num_rules++;
    }
    fclose(fp);
    // now write the rules to the device
    fp = fopen(RULES_SYSFS_PATH, "wb");
    if(fp == NULL){
        perror("Failed to open rules device\n");
        return -1;
    }
    // first we will write the number of rules
    fprintf(fp, "%d\n", num_rules);
    // now we will convert each rule to a buffer and write it to the device
    for(int i = 0; i < num_rules; i++){
        char rule_buf[256];
        if(rule_to_buffer(&rule_table[i], rule_buf) == -1){
            printf("Failed to convert rule to buffer\n");
            fclose(fp);
            return -1;
        }
        fprintf(fp, "%s\n", rule_buf);
    }
    fclose(fp);
    return 0;
}

// convert a rule in string format to a rule_t struct
// string format: <rule_name> <direction> <src_ip>/<src_prefix_size> <dst_ip>/<dst_prefix_size> <protocol> <src_port> <dst_port> <ack> <action>
int string_to_rule(char* line, rule_t* rule){
    char direction_str[5];
    char src_ip_str[20], dst_ip_str[20];
    char src_port_str[10], dst_port_str[10];
    char protocol_str[6];
    char ack_str[5];
    char action_str[10];
    sscanf(line, "%s %s %s %s %s %s %s %s %s\n",
    rule->rule_name, direction_str, src_ip_str, dst_ip_str, protocol_str, src_port_str, dst_port_str, ack_str, action_str);
    // convert direction to direction_t
    if(string_to_direction(direction_str, &rule->direction) == -1){
        printf("Failed to convert direction string to direction_t\n");
        return -1;
    }
    // convert src ip to uint32_t
    if(string_to_ip(src_ip_str, &rule->src_ip, &rule->src_prefix_mask, &rule->src_prefix_size) == -1){
        printf("Failed to convert src ip string to uint32_t\n");
        return -1;
    }
    // convert dst ip to uint32_t
    if(string_to_ip(dst_ip_str, &rule->dst_ip, &rule->dst_prefix_mask, &rule->dst_prefix_size) == -1){
        printf("Failed to convert dst ip string to uint32_t\n");
        return -1;
    }
    // convert src port to uint16_t
    if(string_to_port(src_port_str, &rule->src_port) == -1){
        printf("Failed to convert src port string to uint16_t\n");
        return -1;
    }
    // convert dst port to uint16_t
    if(string_to_port(dst_port_str, &rule->dst_port) == -1){
        printf("Failed to convert dst port string to uint16_t\n");
        return -1;
    }
    // convert protocol to uint8_t
    if(string_to_protocol(protocol_str, &rule->protocol) == -1){
        printf("Failed to convert protocol string to uint8_t\n");
        return -1;
    }
    // convert ack to ack_t
    if(string_to_ack(ack_str, &rule->ack) == -1){
        printf("Failed to convert ack string to ack_t\n");
        return -1;
    }
    // convert action to uint8_t
    if(string_to_action(action_str, &rule->action) == -1){
        printf("Failed to convert action string to uint8_t\n");
        return -1;
    }
    return 0;
}

// convert a direction string to direction_t
int string_to_direction(char* str, direction_t* direction){
    if(strcmp(str, "in") == 0){
        *direction = DIRECTION_IN;
    }
    else if(strcmp(str, "out") == 0){
        *direction = DIRECTION_OUT;
    }
    else if(strcmp(str, "any") == 0){
        *direction = DIRECTION_ANY;
    }
    else{
        return -1;
    }
    return 0;
}

// convert an ip string to uint32_t uint32_t uint32_t
int string_to_ip(char* str, uint32_t* ip, uint32_t* mask, uint32_t* size){
    if(strcmp(str, "any") == 0){
        *ip = 0;
        *mask = 0;
        *size = 0;
        return 0;
    }
    char ip_str[20];
    char size_str[5];
    sscanf(str, "%19[^/]/%s", ip_str, size_str);
    if(inet_pton(AF_INET, ip_str, ip) != 1){
        return -1;
    }
    *size = atoi(size_str);
    *mask = 0xFFFFFFFF << (32 - *size);
    return 0;
}

// convert a port string to uint16_t
int string_to_port(char* str, uint16_t* port){
    int port_num = atoi(str);
    if(strcmp(str, "any") == 0){
        *port = 0;
    }
    else if(strcmp(str, ">1023") == 0){
        *port = PORT_ABOVE_1023;
    }
    else if(port_num >= 0 && port_num <= 65535){
        *port = port_num;
    }
    else{
        return -1;
    }
    return 0;
}

// convert a protocol string to uint8_t
int string_to_protocol(char* str, uint8_t* protocol){
    if(strcmp(str, "ICMP") == 0){
        *protocol = PROT_ICMP;
    }
    else if(strcmp(str, "TCP") == 0){
        *protocol = PROT_TCP;
    }
    else if(strcmp(str, "UDP") == 0){
        *protocol = PROT_UDP;
    }
    else if(strcmp(str, "other") == 0){
        *protocol = PROT_OTHER;
    }
    else if(strcmp(str, "any") == 0){
        *protocol = PROT_ANY;
    }
    else{
        return -1;
    }
    return 0;
}

// convert an ack string to ack_t
int string_to_ack(char* str, ack_t* ack){
    if(strcmp(str, "no") == 0){
        *ack = ACK_NO;
    }
    else if(strcmp(str, "yes") == 0){
        *ack = ACK_YES;
    }
    else if(strcmp(str, "any") == 0){
        *ack = ACK_ANY;
    }
    else{
        return -1;
    }
    return 0;
}

// convert an action string to uint8_t
int string_to_action(char* str, uint8_t* action){
    if(strcmp(str, "accept") == 0){
        *action = NF_ACCEPT;
    }
    else if(strcmp(str, "drop") == 0){
        *action = NF_DROP;
    }
    else{
        return -1;
    }
    return 0;
}

// convert a direction_t to a buffer
