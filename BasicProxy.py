import threading
import socket
import struct
import sys
import subprocess
import os


class BasicProxy(threading.Thread):
    """This class is a parent class for both HTTPProxy and FTPProxy"""

    FW_IN_LEG = '10.1.1.3'  # used for the firewall to communicate with the inside world
    FW_OUT_LEG = '10.1.2.3' # used for the firewall to communicate with the outside world
    DEVICE_PATH = '/sys/class/fw/proxy/proxy' # The path to the proxy device in the firewall.
    UINT32_SIZE = 4 # The size of an unsigned int in bytes.
    PROXY_ENTRY_SIZE = 4 + 2 + 4 + 2 + 2 # The size of a proxy entry in bytes.

    """
    @param conn: The socket with the client.
    @param adrr: The address list of the client, return by the accept() method of the socket.
    """
    def __init__(self, conn, addr):
        super(BasicProxy, self).__init__()
        self.client_socket = conn # This is the socket with the client, used to send and receive data.
        self.server_socket = None # This is the socket with the server, used to send and receive data.
        self.client_ip = addr[0] # The client's IP address
        self.client_port = addr[1] # The client's port.
        self.server_ip = None # The server's IP address.
        self.server_port = None # The server's port.
        self.done = False
        self.client_connection = None
        self.server_connection = None


    def run(self):
        """
        When using the threading.Thread class, this method is called when the thread starts.
        This method will be called for every new connection we want to create a proxy for.
        It will be called when we call the start() method of the threading.Thread class.
        The function will apply the setup for the proxy connection, and communicate with both the server and client.
        """
        # We first need to do the basic setup for the proxy connection.
        # it will fill the missing fields in the class, and will send the port to the firewall.
        self.setup()

        # After the setup, we have the server's IP and port, and we can start the communication with the server.
        print("connecting to {}:{}".format(self.server_ip, self.server_port))
        self.server_socket.connect((self.server_ip, self.server_port))
        print("Successfully connected to server!")

        # We then start the client and server threads.
        # each of them will be responsible for the communication with the client and server respectively.
        # starting with the client thread:
        self.client_connection = threading.Thread(target=self.perform_client_connection)
        self.client_connection.start()

        # and then the server thread:
        self.server_connection = threading.Thread(target=self.perform_server_connection)
        self.server_connection.start()

        # After the threads are done, we need to close the sockets.
        self.client_connection.join()
        self.server_connection.join()
        self.client_socket.close()
        self.server_socket.close()



    # This function is responsible for communicating with the client.
    # This is an "abstract" method that should be implemented by the child classes.
    
      
    def perform_client_connection(self):
        pass

    # This function is responsible for communicating with the server.
    # This is an "abstract" method that should be implemented by the child classes.
    
    
    def perform_server_connection(self):
        pass


    def parse_proxy_entry(self, buffer):
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

    
    def find_proxy_entry(self, client_ip, client_port):
        """
        Find a proxy entry with the given client IP and port.
        :param client_ip: String of the client IP (e.g., "192.168.1.1").
        :param client_port: Integer of the client port.
        :return: The matching entry as a dictionary, or None if not found.
        """
        try:
            with open(self.DEVICE_PATH, "rb") as device:
                # Read the buffer
                data = device.read()
            
            print("Data length: {}".format(len(data)))
            print("Data content: {}".format(data))
            # Read the number of proxy entries
            num_entries = struct.unpack("I", data[:self.UINT32_SIZE])[0]
            print("I didn't get thrown out, {} entries".format(num_entries))
            offset = self.UINT32_SIZE
            
            # Iterate over each proxy entry
            for i in range(num_entries):
                print(i)
                entry_buffer = data[offset:offset + self.PROXY_ENTRY_SIZE]
                entry = self.parse_proxy_entry(entry_buffer)
                offset += self.PROXY_ENTRY_SIZE

                # Check for a match
                if entry["client_ip"] == client_ip and entry["client_port"] == client_port:
                    return entry
            
            return None  # No matching entry found

        except FileNotFoundError:
            # print(f"Device file {self.DEVICE_PATH} not found.")
            # different print command for python version older than 3.6
            print("Device file {} not found.".format(self.DEVICE_PATH))
            return None
        except Exception as e:
            # print(f"An error occurred: {e}")
            print("An error occurred: {}".format(e))
            return None

    def send_proxy_request(self, client_ip, client_port, proxy_port):
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
            with open(self.DEVICE_PATH, "wb") as device:
                device.write(buffer)
            
            # print(f"Successfully sent: {client_ip}:{client_port}:{proxy_port}")
            print("Successfully sent: {}:{}:{}".format(client_ip, client_port, proxy_port))
        
        except FileNotFoundError:
            # print(f"Device file {self.DEVICE_PATH} not found.")
            # different print command for python version older than 3.6
            print("Device file {} not found.".format(self.DEVICE_PATH))
        except Exception as e:
            # print(f"An error occurred: {e}")
            print("An error occurred: {}".format(e))

    
    def setup(self):
        """
        This method is responsible for the basic setup of the proxy connection.
        It will fill the missing fields in the class, and will send the port to the firewall.
        """
        # We first need to find the server's IP and port.
        entry = self.find_proxy_entry(self.client_ip, self.client_port)
        if entry is None:
            print("Proxy entry not found.")
            return
        
        self.server_ip = entry["server_ip"]
        self.server_port = entry["server_port"]

        # Now we need to create connection with the server, and send our source port to the firewall.
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # TCP socket
        # We need to bind the socket to a port, so we can send the port to the firewall.
        sock.bind((self.FW_OUT_LEG, 0)) 
        self.server_socket = sock

        # get the port we are using from the socket.
        proxy_addr = sock.getsockname()
        proxy_port = proxy_addr[1]

        # and now need to send the port to the firewall.
        # The format of the message we need to send is:
        # <client_ip><client_port><proxy_port>
        # where IP is 4 bytes and the others are 2 bytes.

        self.send_proxy_request(self.client_ip, self.client_port, proxy_port)
        
    

