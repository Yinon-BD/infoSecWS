#include "RuleTable.h"

static rule_table_t fw_rule_table = {.valid = 0};

rule_t *get_rule_table(void){
    return fw_rule_table.rules;
}

int is_rule_table_valid(void){
    return fw_rule_table.valid;
}

__u8 get_rule_table_size(void){
    return fw_rule_table.size;
}