#ifndef _USR_LOG_H_
#define _USR_LOG_H_

#include "UserParser.h"

#define LOG_SYSFS_PATH "/sys/class/fw/log/reset"
#define LOG_READ_PATH "/dev/fw_log"

#define LOG_ENTRY_SIZE 128

int show_log(void);
int clear_log(void);

#endif // _USR_LOG_H_