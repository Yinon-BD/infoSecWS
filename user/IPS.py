import sys
import os
import socket
import struct
import select
import re
import json

MAX_CONTENT_LENGTH = 102400
FW_IN_LEG = '10.1.1.3'  # used for the firewall to communicate with the inside world
FW_OUT_LEG = '10.1.2.3' # used for the firewall to communicate with the outside world
DEVICE_PATH = '/sys/class/fw/proxy/proxy' # The path to the proxy device in the firewall.
UINT32_SIZE = 4 # The size of an unsigned int in bytes.
PROXY_ENTRY_SIZE = 4 + 2 + 4 + 2 + 2 # The size of a proxy entry in bytes.


def parse_http_headers(buffer):
    """Parse HTTP headers and extract Content-Length."""
    headers_end = buffer.find(b"\r\n\r\n")
    if headers_end == -1:
        return None, buffer
    headers = buffer[:headers_end].decode(errors="ignore")
    body_start = headers_end + 4
    content_length = 0
    for line in headers.split("\r\n"):
        if line.lower().startswith("content-length:"):
            content_length = int(line.split(":")[1].strip())
    return content_length, buffer[body_start:]

def should_block_response(payload):
    """
    Detects object injection attempts in JSON and raw responses.
    
    :param payload: The response body as a string.
    :return: True if the response should be blocked, False otherwise.
    """
    try:
        # Try to parse as JSON (if applicable)
        data = json.loads(payload)
        
        # Check all values in JSON for suspicious patterns
        for key, value in data.items():
            if isinstance(value, str) and detect_php_object_injection(value):
                print(f"Blocked due to PHP object injection in JSON key: {key}")
                return True
    
    except json.JSONDecodeError:
        # Not JSON, treat as raw text
        pass
    
    # Check raw response payload for PHP object injection
    if detect_php_object_injection(payload):
        print("Blocked due to PHP object injection in raw response")
        return True

    return False

def detect_php_object_injection(text):
    """Detects PHP object injection patterns."""
    php_patterns = [
        r'O:\d+:"[a-zA-Z0-9_\\\\]+"',  # Serialized PHP object
        r's:\d+:"[a-zA-Z0-9_\\\\]+"',  # Serialized PHP string
        r'(\W|\A)unserialize\(',       # Direct unserialize() function
        r'(\W|\A)base64_decode\(',     # Obfuscated base64 payloads
        r'\\O:\d+:',                   # Escaped PHP object notation
    ]
    return any(re.search(pattern, text) for pattern in php_patterns)


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
        # we also want to append to the buffer the number 0 to indicate that the is in the internal network
        buffer += struct.pack('i', 0)
        
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

def run_servers(host=FW_OUT_LEG, HTTP_port=800):
    # Create a TCP socket
    http_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    http_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    http_server_socket.bind((host, HTTP_port))
    http_server_socket.listen(10)
    print("HTTP server listening on {}:{}".format(host,HTTP_port))
    connections = {}
    sock_data = {}
    
    # List of sockets to monitor for incoming connections
    sockets = [http_server_socket]
    
    try:
        while True:
            # Use select to wait for activity on any of the sockets
            readable, _, _ = select.select(sockets, [], [], 0.5)
            
            for sock in readable:
                if sock is http_server_socket:
                    # Accept new connections
                    client_socket, client_address = sock.accept()
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
                                content_length, body = parse_http_headers(sock_data[sock]['buffer'])
                                if content_length:
                                    sock_data[sock]['headers_parsed'] = True
                                    sock_data[sock]['expected_length'] = content_length
                                    sock_data[sock]['body'] = body
                            else:
                                sock_data[sock]['body'] += data
                            if len(sock_data[sock]['body']) >= sock_data[sock]['expected_length']:
                                # we got the full payload
                                payload = sock_data[sock]['body']
                                verdict = should_block_response(payload if isinstance(payload, str) else payload.decode(errors="ignore"))
                                if verdict == True:
                                    # the data contains sensitive information
                                    # we should not send it to the server
                                    print("Blocked sensitive data")
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
                                connections[sock].send(sock_data[sock]['buffer'])
                                sock_data[sock]['buffer'] = b''
                                sock_data[sock]['body'] = b''
                                sock_data[sock]['headers_parsed'] = False
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
    run_servers()
