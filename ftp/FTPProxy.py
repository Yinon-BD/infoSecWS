import sys
import os
import socket
import struct
import select
from infoSecWS.BasicProxy import BasicProxy

FAKE_PORT = 210
FW_IN_LEG = '10.1.1.3'  # used for the firewall to communicate with the inside world
FW_OUT_LEG = '10.1.2.3' # used for the firewall to communicate with the outside world
MAX_CONTENT_LENGTH = 102400

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

def get_proxy_dst(client_address):
    try:
        with open('/sys/class/fw/proxy_con/connect', 'w') as proxy_con:
            proxy_con.write("{} {}\n".format(str_to_ip(client_address[0]), client_address[1]))
        with open('/sys/class/fw/proxy_con/connect', 'r') as proxy_con:
            response = proxy_con.read()
            response_parts = response.split()
            if len(response_parts) == 2:
                proxy_dst_ip = ip_to_str(int(response_parts[0]))
                proxy_dst_port = int(response_parts[1])
                return (proxy_dst_ip, proxy_dst_port)
            raise ValueError("Something went wrong!")
    except FileNotFoundError:
        print("Error: File /sys/class/fw/proxy_con/connect not found.")
    except Exception as e:
        print("An error occurred: {}".format(e))

def set_proxy_port(src_ip, dst_ip, src_port, dst_port, proxy_port):
    try:
        with open('/sys/class/fw/proxy_set/set_port', 'w') as proxy_set:
            proxy_set.write("{} {} {} {} {}\n".format(str_to_ip(src_ip), str_to_ip(dst_ip), src_port, dst_port, proxy_port))
    except FileNotFoundError:
        print("Error: File /sys/class/fw/proxy_con/connect not found.")
    except Exception as e:
        print("An error occurred: {}".format(e))

def set_ftp_con(src_ip, dst_ip, src_port, dst_port):
    try:
        with open('/sys/class/fw/ftp/ftp', 'w') as ftp_set:
            ftp_set.write("{} {} {} {}\n".format(str_to_ip(src_ip), str_to_ip(dst_ip), src_port, dst_port))
    except FileNotFoundError:
        print("Error: File /sys/class/fw/ftp/ftp not found.")
    except Exception as e:
        print("An error occurred: {}".format(e))

def run_server(host='0.0.0.0', port=210):
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
                    sock_data[client_socket] = {"data" : b''}
                    dst = get_proxy_dst(client_address)
                    if dst:
                        dst_ip, dst_port = dst
                        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        proxy_socket.bind((host, 0))
                        local_ip, local_port = proxy_socket.getsockname()
                        set_proxy_port(client_address[0], dst_ip, client_address[1], dst_port, local_port)
                        proxy_socket.connect(dst)
                        sockets.append(proxy_socket)
                        sock_data[proxy_socket] = {"data" : b''}
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
                            set_proxy_port(src_ip, dst_ip, src_port, dst_port, 0)
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
