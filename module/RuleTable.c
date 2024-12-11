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

ssize_t display_rule_table(struct device *dev, struct device_attribute *attr, char *buf){
    int i = 0;
    ssize_t len = 0;

    if(!fw_rule_table.valid || fw_rule_table.size == 0){
        return scnprintf(buf, PAGE_SIZE, "0\n");
    }
    __u8 rules_size = fw_rule_table.size;
    // send to the user the number of rules
    len += scnprintf(buf + len, PAGE_SIZE - len, "%u\n", rules_size);

    for(i = 0; i < rules_size; i++){
        rule_t *rule = fw_rule_table.rules + i;
        len += scnprintf(buf + len, PAGE_SIZE - len, "%s %d %u %u %u %u %u %u %u %u %u %u %u\n", rule->rule_name, rule->direction, rule->src_ip, rule->src_prefix_mask, rule->src_prefix_size, rule->dst_ip, rule->dst_prefix_mask, rule->dst_prefix_size, rule->src_port, rule->dst_port, rule->protocol, rule->ack, rule->action);
    }

    return len;
}

ssize_t modify_rule_table(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
    int i = 0;
    __u8 rules_size = 0;
    const char *cursor = buf;

    // Parse the number of rules
    if (sscanf(cursor, "%u", &rules_size) != 1) {
        return -EINVAL;  // Invalid input format
    }

    // Advance cursor past the first line (number of rules)
    cursor = strchr(cursor, '\n');
    if (!cursor) {
        return -EINVAL;  // Malformed input: missing newline
    }
    cursor++;  // Move past the newline

    // Validate the number of rules
    if (rules_size > MAX_RULES) {
        return -EINVAL;  // Exceeds allowed rules
    }

    // Parse each rule
    // Rule format: <rule_name> <direction> <src_ip> <src_prefix_mask> <src_prefix_size> <dst_ip> <dst_prefix_mask> <dst_prefix_size> <src_port> <dst_port> <protocol> <ack> <action>
    for (i = 0; i < rules_size; i++) {
        rule_t rule;
        const char *next_line;
        int parsed = sscanf(cursor, "%19s %d %u %u %u %u %u %u %u %u %u %u %u",
                            rule.rule_name, &rule.direction, &rule.src_ip, &rule.src_prefix_mask,
                            &rule.src_prefix_size, &rule.dst_ip, &rule.dst_prefix_mask,
                            &rule.dst_prefix_size, &rule.src_port, &rule.dst_port,
                            &rule.protocol, &rule.ack, &rule.action);

        if (parsed != 13) {
            return -EINVAL;  // Malformed rule
        }

        // Add rule to the table
        fw_rule_table.rules[i] = rule;

        // Find the next line
        next_line = strchr(cursor, '\n');
        if (!next_line) {
            if (i == rules_size - 1) {
                // Last rule might not have a trailing newline
                break;
            }
            return -EINVAL;  // Malformed input
        }

        // Move cursor to the next rule
        cursor = next_line + 1;
    }

    fw_rule_table.valid = 1;
    fw_rule_table.size = rules_size;

    return count;  // Successfully processed all input
}
