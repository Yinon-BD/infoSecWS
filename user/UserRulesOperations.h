#ifndef _USR_RULES_H_
#define _USR_RULES_H_

#include "header.h"

#define RULES_SYSFS_PATH "/sys/class/fw/rules/rules"

int show_rules(void);
int load_rules(char *file_path);

#endif // _USR_RULES_H_