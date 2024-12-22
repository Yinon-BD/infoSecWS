#ifndef _USR_RULES_H_
#define _USR_RULES_H_

#include "UserParser.h"

#define RULES_SYSFS_PATH "/sys/class/fw/rules/rules"

#define STRING_TAIL(x) (x + strlen(x))

int show_rules(void);
int load_rules(char *file_path);
char *my_itoa(unsigned int number, char* str);

int direction_to_string(direction_t direction, char* str);
int ip_to_string(uint32_t ip, uint32_t mask, uint32_t size, char* str);
int port_to_string(uint16_t port, char* str);
int protocol_to_string(uint8_t protocol, char* str);
int ack_to_string(ack_t ack, char* str);
int action_to_string(uint8_t action, char* str);
int print_rule(char* line);
int rule_to_buffer(rule_t* rule, char* buf);

int string_to_rule(char* line, rule_t* rule);
int string_to_direction(char* str, direction_t* direction);
int string_to_ip(char* str, uint32_t* ip, uint32_t* mask, uint32_t* size);
int string_to_port(char* str, uint16_t* port);
int string_to_protocol(char* str, uint8_t* protocol);
int string_to_ack(char* str, ack_t* ack);
int string_to_action(char* str, uint8_t* action);


#endif // _USR_RULES_H_