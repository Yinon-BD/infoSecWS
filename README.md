# InfoSec Workshop HW3

In this assignment, I implemented a stateless packet-filtering firewall.

The firewall operates based on a rule table provided by the user. The implementation involves functionality in both user space and kernel space.

## Features

The firewall supports the following features:

1. Loading a new rule table.
2. Printing the rule table to the user.
3. Sending filtering logs to the user.
4. Resetting logs upon user request.

## Kernel Space Functionality

The kernel-space implementation uses the `netfilter` API to "catch" arriving packets and decide whether to accept or drop them. Communication between user space and kernel space is facilitated by:
- A character device for passing logs.
- Two `sysfs` devices for passing the rule table and resetting logs.

The kernel code consists of four files:

- **`hw3secws`**: Initializes the module, character, and `sysfs` devices and sets up the netfilter hook.
- **`RuleTable`**: Manages the rule table, including storing, building, and displaying it.
- **`PacketFilter`**: Implements the filtering logic using the netfilter hook.
- **`LogDevice`**: Manages the logs, including storing, displaying, and resetting them.

### `hw3secws`

When the module loads, it performs the following steps:
1. Initializes the netfilter hook to filter forwarded packets using the `filter` function from the `PacketFilter` file.
2. Creates a character device for reading logs, with `open` and `read` functions implemented in the `LogDevice` file.
3. Creates a `sysfs` class and devices for:
   - Resetting logs (store function in `LogDevice`).
   - Displaying and modifying the rule table.

### `RuleTable`

This file manages the rule table using the `rule_table` structure. It includes:
- **`display_rule_table`**: Sends a buffer containing the table size and compressed rules to the user.
- **`modify_rule_table`**: Creates a new rule table from user input by parsing a compressed buffer of rules.

### `PacketFilter`

Contains the primary function `filter`, which:
- Decides whether to accept or drop a packet.
- Creates log entries and sends them to the `LogDevice`.

### `LogDevice`

Manages logs using a `klist` data structure. Key functions:
- **`log_it`**: Adds or updates log entries.
- **`open_log_device`** and **`read_log_device`**: Allow the user to read log entries sequentially.
- **`clear_log`**: Resets logs when requested by the user.

## User Space Functionality

The user-space implementation parses user commands and interacts with kernel-space devices. It comprises three files:

- **`UserParser`**: Parses user commands and executes corresponding actions.
- **`UserLogOperations`**: Handles log-related actions (e.g., reading and resetting logs).
- **`UserRuleTable`**: Manages rule table operations (e.g., loading and displaying rules).

### `UserParser`

Contains the `main` function, which supports the following commands:
1. `load_rules <filepath>`: Loads a new rule table from the specified file.
2. `show_rules`: Displays the current active rule table.
3. `show_log`: Displays log entries.
4. `reset_log`: Resets the stored logs.

### `UserLogOperations`

Implements:
- **`show_log`**: Reads log entries from the kernel. The first read call fetches the log count; subsequent calls fetch entries sequentially.
                    It also converts the raw data from the buffer into a human-readable format, ensuring that the logs are easy to understand for the user.
- **`reset_log`**: Sends a reset command to the kernel via the `sysfs` device.

### `UserRuleTable`

Implements:
- **`show_rules`**: Reads the active rule table from the kernel and formats it for display.
- **`load_rules`**: Reads a rule table from a file, compresses it, and sends it to the kernel.

Both functions handle errors at every stage and print appropriate messages to the user.

---
