# InfoSec Workshop HW3:

In this assignment I implemented a stateless packet filtering firewall.

The Operation of the firewall is based on a rule table that is loaded to the firewall thorugh the user.

The implementation is taking place in both the User-space and the kernel-space.

There are 4 functions the firewall support besides packet filtering:

1. Loading a new rule table to the firewall
2. printing the rule table to the user
3. sending filtering logs to the user
4. reset the logs based on user request

## Kernel Space Functionality

The netfilter API is used to "catch" the arriving packets and decide wether a packet should be accepted or dropped.
To communicate between the userspace and the kernel-space I created one Char Device to pass the logs thorugh, and two sysfs devices to pass the rule table and request log reset.

The kernel code is divided into 4 files:
- hw3secws: the file which initiates the module, the char and sysfs devices and the netfilter hook.
- RuleTable: the file which stores the rule table in kernel space, builds it from user input and outputs it upon user's  request.
- PacketFilter: the file that contains the netfilter hook function, that decides packets' fate.
- LogDevice: the file that stores the logs, packet filter history, and outputs it to the user or resets it upon the user's request.

### hw3secws

when the module loads, it runs the *firewall_module* which do:
1. initialize the netfilter hook, configure it the catch packets the are being forwarded and act according to the filter function in PacketFilter file.
2. creates a char device for reading logs, it has the open and read functions that are implemented in the LogDevice file.
3. creates a sysfs class
4. creates another char device for reseting the logs, we create a sysfs device and give it the store function which is implemented in LogDevice file.
5. creates a sysfs device for the rule table which will display the rule table to the user and modify it when the kernel recieve a new one from the user.

### RuleTable

This file manages the rule table.
It contains a rule_table struct which contains info about the rule table size and its validity.
It also contains an array of rule structs.

There are two main functions in RuleTable:

*display_rule_table*: this function sends the user a buffer which will contains the size of the firewall and a stream of strings that would tell the user how to build the rules.
auxilary functions are used to "compress" the rules and send it to the user a string stream.

*modify_rule_table*: this function creates a new ruletable based on the user input. the function receive a compressed buffer that contains the amount of rules and the rules themselves.
Using auxilary functions it parses the buffer and create a new rule table.

### PacketFilter

This file contains one main function: *filter*
This function decides wether the netfilter hook should accept or drop an arriving packet.
This function also create a log entry and fill its fields. Before returning an action to the hook, it sends the LogDevice the new log to be added to the log list.

There are other helper functions for the filter, which are documented in the code.

### LogDevice

This file manages the filtering logs.
It using the klist data structure to hold the logs.
The function *log_it* gets new logs from the packetfilter function and either make a new node list if there are on other packets from this type or increment the count field on a matching log node.

Using the *open_log_device* and *read_log_device* the char device pass the log entries to the user.
Although when the user asks to show logs it asks to get the whole log list, I decided to implement the read function so in each call the user will get one log entry to avoid kernel blocking.

The function *clear_log* resets the log upon recieving a command from the user.


## UserSpace Functionality

In the UserSpace the right data is sent or recieved from the kernel based on the user commands.

The userspace has three files:

- UserParser: This File parse the user commands and executes the right function based on user arguments.
- UserLogOperations: This File contains the function that interacts with the log char device and the log sysfs device to read and reset the logs
- UserRuleTabel: This File contains functions that related to ruletable functions, such as load and receiving a ruletable

### UserParser:

In this file lies the ***main*** function. It parses the the user arguments and runs the right function for the desired action.
The accepted arguments are the following:
1. load_rules <filepath> - it will load a new ruletable to the kernel that contained in the file provided
2. show_rules - this will print to the user the current active ruletable in the kernel.
3. show_log - this will print to the user the log entries
4. reset_log - this will reset the logs that stored in the kernel

This file's header also contains libraries and struct which other userspace files can use.

### UserLogOperations

This file contains the implementations to the *show_log* and *reset_log* functions.

*show_log*: this function opens the char device and try to read the log entries from the device. In the first call to read, the device returns the amount of log entries so the function can know how many read calls should it make. each read call returns one log entry (or amount of log entries in first call) in order to avoid kernel blocking.

*reset_log*: this function sends to the sysfs device the string "1" to ask it to reset the logs.

### UserRuleOperations

This file contains the implementations to the *show_rules* and *load_rules* functions.

*show_rules:* this function try to read from the kernel the active ruletable. it first gets the amount of active rules in the rule table. Then upon receiving each buffer line it creates a rule struct array for the rules. after building the array the function print the rules in human readable form. It uses auxilary function to build a rule from the buffer, and build a printable string from a rule struct.

*load_rules(char[])*: this function tries to build a rule table from the given file. Upon succeeding, it converts the rules to a compressed buffer and send it to the device.

In both of these function, upon any failure in any stage (file to rule, rule to buffer, buffer to rule, etc.), the function prints an error message to the user and signals the main to stop the execution.


