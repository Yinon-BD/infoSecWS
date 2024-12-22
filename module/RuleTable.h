#ifndef _RULE_TABLE_H_
#define _RULE_TABLE_H_

#include "fw.h"

rule_t *get_rule_table(void);
int is_rule_table_valid(void);
__u8 get_rule_table_size(void);
ssize_t display_rule_table(struct device *dev, struct device_attribute *attr, char *buf);
ssize_t modify_rule_table(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

#endif // _RULE_TABLE_H_
