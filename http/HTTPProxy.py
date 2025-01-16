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

def parse_http_headers(raw_headers):
    headers = {}
    lines = raw_headers.split("\r\n")
    for line in lines[1:]:  # Skip the first line (status line)
        if ": " in line:
            key, value = line.split(": ", 1)
            headers[key] = value
    return headers

def should_block_response(headers):
    # Check for Content-Length
    content_length = headers.get('Content-Length')
    if content_length and int(content_length) > MAX_CONTENT_LENGTH:
        print("Blocked response: Content-Length exceeds {} bytes.".format(MAX_CONTENT_LENGTH))
        return True
    
    # Check for Content-Encoding (e.g., gzip)
    content_encoding = headers.get('Content-Encoding', '').lower()
    if 'gzip' in content_encoding:
        print("Blocked response: Content-Encoding is GZIP.")
        return True

    return False

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

def set_proxy_port(src_ip, dst_ip, src_port, dst_port, proxy_port):
    try:
        with open('/sys/class/fw/proxy_set/set_port', 'w') as proxy_set:
            proxy_set.write("{} {} {} {} {}\n".format(str_to_ip(src_ip), str_to_ip(dst_ip), src_port, dst_port, proxy_port))
    except FileNotFoundError:
        print("Error: File /sys/class/fw/proxy_con/connect not found.")
    except Exception as e:
        print("An error occurred: {}".format(e))

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

def run_server(host=FW_IN_LEG, port=800):
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
                            sock_data[sock]['buffer'] += data
                            if not sock_data[sock]['headers_parsed']:
                                header_end = sock_data[sock]['buffer'].find(b'\r\n\r\n')
                                if header_end != -1:
                                    raw_headers = sock_data[sock]['buffer'][:header_end].decode()
                                    headers = parse_http_headers(raw_headers)
                                    if should_block_response(headers):
                                        src_ip , src_port = sock.getpeername()
                                        dst_ip, dst_port = connections[sock].getpeername()
                                        connections[sock].close()
                                        sock.close()
                                        if(src_ip.startswith("10.1.1")): # client is inside
                                            send_proxy_request(src_ip, src_port, 0)
                                        else:
                                            send_proxy_request(dst_ip, dst_port, 0)
                                        sockets.remove(connections[sock])
                                        sockets.remove(sock)
                                        sock_data.pop(sock)
                                        sock_data.pop(connections[sock])
                                        connections.pop(connections[sock])
                                        connections.pop(sock)
                                        continue
                                    sock_data[sock]['headers_parsed'] = True
                                    connections[sock].send(sock_data[sock]['buffer'])
                                    sock_data[sock]['buffer'] = b''
                            else:
                                connections[sock].send(data)
                        else:# remove connection
                            print("disconnecting someone")
                            src_ip , src_port = sock.getpeername()
                            dst_ip, dst_port = connections[sock].getpeername()
                            connections[sock].close()
                            sock.close()
                            if(src_ip.startswith("10.1.1")): # client is inside
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
                        print("Error {}".format(e))
                        src_ip , src_port = sock.getpeername()
                        dst_ip, dst_port = connections[sock].getpeername()
                        connections[sock].close()
                        sock.close()
                        if(src_ip.startswith("10.1.1")): # client is inside
                            send_proxy_request(src_ip, src_port, 0)
                        else:
                            send_proxy_request(dst_ip, dst_port, 0)
                        sockets.remove(connections[sock])
                        sockets.remove(sock)
                        sock_data.pop(sock)
                        sock_data.pop(connections[sock])

                        connections.pop(connections[sock])
                        connections.pop(sock)
    except KeyboardInterrupt:
        print("\nShutting down server...")
    finally:
        # Close all sockets
        for sock in sockets:
            sock.close()
        print("Server shut down.")

if __name__ == "__main__":
    run_server()


# # import socket
# # import re
# # from infoSecWS.BasicProxy import BasicProxy

# # FAKE_PORT = 800
# # FW_IN_LEG = '10.1.1.3'  # used for the firewall to communicate with the inside world
# # FW_OUT_LEG = '10.1.2.3' # used for the firewall to communicate with the outside world
# # MAX_CONTENT_LENGTH = 102400

# # class HTTPProxy(BasicProxy):
# #     def recv_info(self, sock):
# #         """ Receives information sent to the socket """
# #         total = ''
# #         size = 512
        
# #         while True:
# #             current = sock.recv(size)
# #             total += current.decode()
# #             if len(current) < size:
# #                 break
            
# #         return total
        

    
# #     """ Represents HTTP proxy connection """

# #     def filter_packet(self, message):
# #         """ Enforces the content type """
        
        
# #         header = message
        
# #         # Check if should block

# #         # Check for content length
# #         content_length = re.findall('Content-Length: (\d+)', header)
# #         print('Content length: {}'.format(content_length))

# #         #Check content encoding
# #         content_encoding = re.findall('Content-Encoding: (\S+)', header)

# #         if content_length and int(content_length[0]) > MAX_CONTENT_LENGTH:
# #             return False

# #         #check if encoding in GZIP
# #         if content_encoding and 'gzip' in content_encoding:
# #             return False

# #         return True


# #     def perform_client_connection(self):
# #         while self.is_alive() and not self.done:
# #             request = self.recv_info(self.client_socket)
# #             if request:
# #                 self.server_socket.sendall(request.encode())
# #             else:
# #                 self.done = True


# #     def perform_server_connection(self):
# #         while self.is_alive() and not self.done:
# #             response = self.recv_info(self.server_socket)
# #             if response:
# #                 if self.filter_packet(response):
# #                     self.client_socket.sendall(response.encode())
# #                 else:
# #                     print("HTTP packet dropped")
# #             else:
# #                 self.done = True



# # if __name__ == "__main__":
# #     # Creating an HTTP proxy server
# #     sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# #     sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Enabling reuse the socket without time limitation
# #     sock.bind((FW_IN_LEG, FAKE_PORT))
# #     sock.listen(10)
# #     proxies = []


# #     print("\nStarting")

# #     while True:
# #         try:
# #             connection, addr = sock.accept()
# #         except KeyboardInterrupt:
# #             for proxy in proxies:
# #                 proxy.done = True
# #             for proxy in proxies:
# #                 proxy.join()
# #             break

# #         print("\nConnection accepted")
# #         proxy = HTTPProxy(connection, addr)
# #         proxies.append(proxy)
# #         proxy.start()

# #     print("\nFinished")
# import socket
# from http.client import HTTPResponse
# from io import BytesIO
# from infoSecWS.BasicProxy import BasicProxy  # Assuming BasicProxy is in the same module.

# MAX_CONTENT_LENGTH = 102400  # Define the maximum content length to allow.
# FAKE_PORT = 800
# FW_IN_LEG = '10.1.1.3'  # used for the firewall to communicate with the inside world
# FW_OUT_LEG = '10.1.2.3' # used for the firewall to communicate with the outside world


# class HTTPProxy(BasicProxy):
#     """A Proxy for handling HTTP traffic, extending the BasicProxy class."""

#     def perform_client_connection(self):
#         """Handles incoming client requests and forwards them to the server."""
#         while not self.done:
#             try:
#                 # Receive the HTTP request from the client
#                 request = self.client_socket.recv(1024)
#                 if not request:
#                     self.done = True
#                     break

#                 # Forward the request to the server
#                 self.server_socket.sendall(request)
#             except Exception as e:
#                 print("Error during client communication: {}".format(e))
#                 self.done = True

#     def perform_server_connection(self):
#         """Handles incoming server responses and forwards them to the client."""
#         while not self.done:
#             try:
#                 # Read and parse the response from the server
#                 response = self.read_response(self.server_socket)

#                 if self.filter_packet(response):
#                     # Forward the entire response to the client
#                     self.client_socket.sendall(response.fp.read())
#                 else:
#                     print("HTTP packet dropped.")
#             except Exception as e:
#                 print("Error during server communication: {}".format(e))
#                 self.done = True

#     def filter_packet(self, response):
#         """
#         Filters HTTP packets based on headers like Content-Length and Content-Encoding.
#         :param response: An instance of HTTPResponse.
#         :return: True if the packet is allowed, False otherwise.
#         """
#         content_length = response.getheader('Content-Length')
#         content_encoding = response.getheader('Content-Encoding')

#         # Filter based on Content-Length
#         if content_length and int(content_length) > MAX_CONTENT_LENGTH:
#             print("Blocked: Content-Length exceeds {} bytes.".format(MAX_CONTENT_LENGTH))
#             return False

#         # Filter based on Content-Encoding
#         if content_encoding and 'gzip' in content_encoding.lower():
#             print("Blocked: Content-Encoding is GZIP.")
#             return False

#         return True

#     def read_response(self, sock):
#         """
#         Reads and parses an HTTP response from a socket.
#         :param sock: The server socket.
#         :return: An instance of HTTPResponse.
#         """
#         buffer = b''
#         while True:
#             data = sock.recv(1024)
#             if not data:
#                 break
#             buffer += data
#             # Look for the end of HTTP headers
#             if b'\r\n\r\n' in buffer:
#                 break

#         # Create an HTTPResponse object from the buffered headers
#         response = HTTPResponse(BytesIO(buffer))
#         response.begin()  # Parse headers
#         return response
    
# if __name__ == "__main__":
#     # Creating an HTTP proxy server
#     sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Enabling reuse the socket without time limitation
#     sock.bind((FW_IN_LEG, FAKE_PORT))
#     sock.listen(10)
#     proxies = []


#     print("\nStarting")

#     while True:
#         try:
#             connection, addr = sock.accept()
#         except KeyboardInterrupt:
#             for proxy in proxies:
#                 proxy.done = True
#             for proxy in proxies:
#                 proxy.join()
#             break

#         print("\nConnection accepted")
#         proxy = HTTPProxy(connection, addr)
#         proxies.append(proxy)
#         proxy.start()

#     print("\nFinished")
    