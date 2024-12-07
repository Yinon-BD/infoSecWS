#ifndef _RULE_TABLE_H_
#define _RULE_TABLE_H_

#include "fw.h"

rule_t *get_rule_table(void);
int is_rule_table_valid(void);
__u8 get_rule_table_size(void);