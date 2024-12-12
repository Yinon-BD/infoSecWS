#include "UserRulesOperations.h"

int print_rule(char* line){
    rule_t rule;
    sscanf(line, "%s %d %u %u %u %u %u %u %u %u %u %u %u",
    rule.rule_name, &rule.direction, &rule.src_ip, &rule.src_prefix_mask, &rule.src_prefix_size, &rule.dst_ip, &rule.dst_prefix_mask, &rule.dst_prefix_size, &rule.src_port, &rule.dst_port, &rule.protocol, &rule.ack, &rule.action);
    printf("%s", rule.rule_name);
    // print readable direction
    if(print_direction(rule.direction) == -1){
        return -1;
    }
    // print readable src ip
    if(print_ip(rule.src_ip, rule.src_prefix_mask, rule.src_prefix_size) == -1){
        return -1;
    }
    // print readable dst ip
    if(print_ip(rule.dst_ip, rule.dst_prefix_mask, rule.dst_prefix_size) == -1){
        return -1;
    }
    // print readable src port
    if(print_port(rule.src_port) == -1){
        return -1;
    }
    // print readable dst port
    if(print_port(rule.dst_port) == -1){
        return -1;
    }
    // print readable protocol
    if(print_protocol(rule.protocol) == -1){
        return -1;
    }
    // print readable ack
    if(print_ack(rule.ack) == -1){
        return -1;
    }
    // print readable action
    if(print_action(rule.action) == -1){
        return -1;
    }
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
            fclose(fp);
            return -1;
        }
    }
    fclose(fp);
    return 0;
    
}