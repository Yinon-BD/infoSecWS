import sys
import os
import socket
import struct
import select

MAX_CONTENT_LENGTH = 102400
FW_IN_LEG = '10.1.1.3'  # used for the firewall to communicate with the inside world
FW_OUT_LEG = '10.1.2.3' # used for the firewall to communicate with the outside world
DEVICE_PATH = '/sys/class/fw/proxy/proxy' # The path to the proxy device in the firewall.
UINT32_SIZE = 4 # The size of an unsigned int in bytes.
PROXY_ENTRY_SIZE = 4 + 2 + 4 + 2 + 2 # The size of a proxy entry in bytes.

def ip_to_str(ip):
    try:
        return socket.inet_ntoa(struct.pack('!I', ip))
    except Exception:
        return "Invalid IP"
    
def str_to_ip(ip_str):
    if ip_str == "any":
        return 0
    # Convert IP string to integer using socket
    packed_ip = socket.inet_aton(ip_str.strip())
    return struct.unpack("!I", packed_ip)[0]

def parse_ftp_command(data):
    """Parse FTP commands to identify the PORT command."""
    lines = data.decode().split('\r\n')
    for line in lines:
        if line.startswith("PORT"):
            # Extract IP and port from the PORT command
            parts = line.split()[1].split(',')
            ip = '.'.join(parts[:4])  # IP Address
            port = (int(parts[4]) << 8) + int(parts[5])  # Combine port parts
            return ip, port
    return None, None



def set_ftp_con(src_ip, dst_ip, src_port, dst_port):
    try:
        with open('/sys/class/fw/ftp/ftp', 'w') as ftp_set:
            ftp_set.write("{} {} {} {}\n".format(str_to_ip(src_ip), str_to_ip(dst_ip), src_port, dst_port))
    except FileNotFoundError:
        print("Error: File /sys/class/fw/ftp/ftp not found.")
    except Exception as e:
        print("An error occurred: {}".format(e))

def find_proxy_entry(client_address):
    client_ip, client_port = client_address
    try:
        with open(DEVICE_PATH, "rb") as device:
            # Read the buffer
            data = device.read()
        
        print("Data length: {}".format(len(data)))
        print("Data content: {}".format(data))
        # Read the number of proxy entries
        num_entries = struct.unpack("I", data[:UINT32_SIZE])[0]
        print("I didn't get thrown out, {} entries".format(num_entries))
        offset = UINT32_SIZE
        
        # Iterate over each proxy entry
        for i in range(num_entries):
            print(i)
            entry_buffer = data[offset:offset + PROXY_ENTRY_SIZE]
            entry = parse_proxy_entry(entry_buffer)
            offset += PROXY_ENTRY_SIZE

            # Check for a match
            if entry["client_ip"] == client_ip and entry["client_port"] == client_port:
                return entry
        
        return None  # No matching entry found
    except FileNotFoundError:
        # print(f"Device file {DEVICE_PATH} not found.")
        # different print command for python version older than 3.6
        print("Device file {} not found.".format(DEVICE_PATH))
        return None
    except Exception as e:
        # print(f"An error occurred: {e}")
        print("An error occurred: {}".format(e))
        return None

def parse_proxy_entry(buffer):
    #ip_format = "!4sH4sH"
    #client_ip, client_port, server_ip, server_port = struct.unpack(ip_format, buffer[:12])
    client_ip = struct.unpack("!I", buffer[:4])[0]
    client_port = struct.unpack("H", buffer[4:6])[0]
    server_ip = struct.unpack("!I", buffer[6:10])[0]
    server_port, proxy_port = struct.unpack("HH", buffer[10:])
    print(socket.inet_ntoa(struct.pack("!I", client_ip)))
    print(client_port)
    print(socket.inet_ntoa(struct.pack("!I", server_ip)))
    print(server_port)
    print(proxy_port)
    return {
        "client_ip": socket.inet_ntoa(struct.pack("!I", client_ip)),
        "client_port": client_port,
        "server_ip": socket.inet_ntoa(struct.pack("!I", server_ip)),
        "server_port": server_port,
        "proxy_port": proxy_port,
    }

def send_proxy_request(client_ip, client_port, proxy_port):
    """
    Send a buffer containing <client_IP><client_port><proxy_port> to the device.
    
    :param client_ip: String of the client IP (e.g., "192.168.1.1").
    :param client_port: Integer of the client port.
    :param proxy_port: Integer of the proxy port.
    """
    try:
        # Convert client IP to binary format
        client_ip_bin = socket.inet_aton(client_ip)  # Converts to a 4-byte binary format (__be32)
        
        # Pack the data into binary format
        # "!IHH" means:
        #   - "!"  : Network byte order (big-endian)
        #   - "I"  : Unsigned 32-bit integer (for the IP)
        #   - "H"  : Unsigned 16-bit integer (for the ports)
        pack = struct.pack('<HH', client_port, proxy_port) if sys.byteorder == 'little' else struct.pack('>HH', client_port, proxy_port)
        buffer = client_ip_bin + pack
        
        # Write the buffer to the device
        with open(DEVICE_PATH, "wb") as device:
            device.write(buffer)
        
        # print(f"Successfully sent: {client_ip}:{client_port}:{proxy_port}")
        print("Successfully sent: {}:{}:{}".format(client_ip, client_port, proxy_port))
    
    except FileNotFoundError:
        # print(f"Device file {self.DEVICE_PATH} not found.")
        # different print command for python version older than 3.6
        print("Device file {} not found.".format(DEVICE_PATH))
    except Exception as e:
        # print(f"An error occurred: {e}")
        print("An error occurred: {}".format(e))

def run_server(host=FW_IN_LEG, port=210):
    # Create a TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(20)
    connections = {}
    sock_data = {}
    print("Server listening on {}:{}".format(host,port))
    
    # List of sockets to monitor for incoming connections
    sockets = [server_socket]
    
    try:
        while True:
            # Use select to wait for activity on any of the sockets

            readable, _, _ = select.select(sockets, [], [], 0.1)
            
            for sock in readable:
                if sock is server_socket:
                    # Accept new connections
                    client_socket, client_address = server_socket.accept()
                    print("New connection from {}".format(client_address))
                    sockets.append(client_socket)
                    sock_data[client_socket] = {'buffer': b'', 'headers_parsed': False}
                    entry = find_proxy_entry(client_address)
                    if entry is None:
                        print("No proxy entry found for client")
                        break
                    server_ip = entry["server_ip"]
                    server_port = entry["server_port"]
                    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    proxy_socket.bind((FW_OUT_LEG, 0))
                    _, proxy_port = proxy_socket.getsockname()
                    send_proxy_request(client_address[0], client_address[1], proxy_port)
                    proxy_socket.connect((server_ip, server_port))
                    sockets.append(proxy_socket)
                    sock_data[proxy_socket] = {'buffer': b'', 'headers_parsed': False}
                    connections[proxy_socket] = client_socket
                    connections[client_socket] = proxy_socket
                elif sock in sockets:
                    try:
                        data = sock.recv(1024)
                        if data:
                            sock_data[sock]["data"] += data
                            ip, port = parse_ftp_command(sock_data[sock]["data"])
                            if ip and port:
                                dst_ip , dst_port = connections[sock].getpeername()
                                set_ftp_con(dst_ip,ip,20,port)
                                sock_data[sock]["data"] = b''
                            connections[sock].send(data)
                        else:# remove connection
                            print("disconnecting ftp client")
                            src_ip , src_port = sock.getpeername()
                            dst_ip, dst_port = connections[sock].getpeername()
                            connections[sock].close()
                            sock.close()
                            if(src_ip.startswith("10.1.1")):
                                send_proxy_request(src_ip, src_port, 0)
                            else:
                                send_proxy_request(dst_ip, dst_port, 0)
                            sockets.remove(connections[sock])
                            sockets.remove(sock)
                            sock_data.pop(sock)
                            sock_data.pop(connections[sock])
                            connections.pop(connections[sock])
                            connections.pop(sock)
                    except Exception as e:
                        print("Error with {}: {}".format(sock.getpeername(), e))
                        sockets.remove(sock)
                        sock.close()
    except KeyboardInterrupt:
        print("\nShutting down server...")
    finally:
        # Close all sockets
        for sock in sockets:
            sock.close()
        print("Server shut down.")

if __name__ == "__main__":
    run_server()
