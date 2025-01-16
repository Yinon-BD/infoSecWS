# InfoSec Workshop HW4

In this assignment, I implemented stateful inspection of packets and a proxy server for HTTP and FTP connections.

---

## New Features

Building on the features described in the HW3 documentation, the firewall now includes:

1. Printing a table of active TCP connections and their current states.
2. Proxying HTTP connections.
3. Proxying FTP connections.

---

## Kernel Space Functionality

Unlike in HW3, this assignment uses two `netfilter` hooks:  
- **Pre-Routing stage**: For handling inbound packets.  
- **Local-Out stage**: For handling outbound packets during proxy operations.

### New Kernel Files

Two new files were added to the kernel code:

1. **`ConnectionTable`**  
   Manages active TCP connections by adding, removing, and updating their states.  
   Each connection is represented by **two entries**: one for the client side and one for the server side.

2. **`ProxyDevice`**  
   Maintains a list of connections requiring proxying. It modifies packet fields as needed to facilitate proxy server operations.

---

### `ConnectionTable`

Provides an API to maintain the connections table. When a TCP packet arrives, it undergoes stateful inspection implemented in the `PacketFilter`.

#### TCP States

The TCP states (inspired by the TCP Finite State Machine) are as follows:

1. **INIT**: Initial state when a connection is added to the table.  
   - May transition immediately, except for FTP connections.  
2. **CLOSED**: Connection is closed upon receiving an `RST` packet.  
   - Removed from the table after an `RST-ACK` is received from the other side.  
3. **LISTEN**: Server-side state when a `SYN` is received, assuming the server is listening.  
4. **SYN_SENT**: Client-side state when a `SYN` is sent.  
5. **SYN_RECV**: Server-side state after sending a `SYN-ACK`.  
6. **ESTABLISHED**: Connection reaches this state after the 3-way handshake.  
   - Remains until an `RST` or `FIN` packet is sent.  
7. **FIN_WAIT1**: State after sending a `FIN` packet.  
   - No further packets are expected from this side in this state.  
8. **FIN_WAIT2**: Waiting for an acknowledgment (`ACK`) to the sent `FIN`.  
9. **CLOSE_WAIT**: Connection termination begins; the side in this state acknowledges the `FIN` and sends its own `FIN`.  
10. **LAST_ACK**: Transitioned to after sending a `FIN` and acknowledging the other's `FIN`.  
    - Waits for final acknowledgment.  
11. **TIME_WAIT**: After acknowledging a `FIN`, waits for the other side to also enter this state.  
12. **CLOSING**: Both sides have sent a `FIN` and are awaiting acknowledgment.  
13. **PROXY**: Indicates that this is a proxy connection and bypasses state inspection.

The state transitions and logic are detailed more thoroughly in `validate_TCP_packet` function in `PacketFilter.c`.

---

### `ProxyDevice`

Handles connections requiring proxying. It modifies packet fields as follows:  
- **Pre-Routing hook**: Spoofs destination fields for incoming packets.  
- **Local-Out hook**: Spoofs source fields for outgoing packets.

---

### Adjustments in `hw4secws`

Three new devices were added:  
1. For retrieving the connection table from kernel space to user space.  
2. For managing proxy server addresses and ports.  
3. For creating connection entries for FTP data sockets.

---

## User Space Functionality

The main user-space program now accepts an additional argument:  
- **`show_conns`**: Outputs the active TCP connections.

---

## Proxy Servers

### HTTP Proxy

The HTTP proxy server operates as follows:  
1. When a client initiates an HTTP connection, the kernel reroutes the packet to the proxy server.  
   - The connection is established between the **client** and the **proxy server**.  
2. The proxy server establishes a separate connection with the actual HTTP server.  
   - To the HTTP server, it appears as though it is communicating with the client, thanks to packet spoofing by the kernel.  
3. The proxy receives responses from the HTTP server, verifies them (e.g., size and compression method), and forwards them to the client.

---

### FTP Proxy

The FTP proxy server operates similarly to the HTTP proxy server:  
1. The proxy intercepts the client's connection attempt and establishes its own connection with the FTP server.  
2. Once both connections are established:  
   - The client sends a `PORT` command to the FTP server.  
   - The proxy intercepts this command, notifies the kernel to allow the specific data connection port, and then forwards the command to the FTP server.  
3. The FTP server establishes the data socket directly with the client, bypassing the proxy.


-------------------------------------------------------------------

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
