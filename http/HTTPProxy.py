# import socket
# import re
# from infoSecWS.BasicProxy import BasicProxy

# FAKE_PORT = 800
# FW_IN_LEG = '10.1.1.3'  # used for the firewall to communicate with the inside world
# FW_OUT_LEG = '10.1.2.3' # used for the firewall to communicate with the outside world
# MAX_CONTENT_LENGTH = 102400

# class HTTPProxy(BasicProxy):
#     def recv_info(self, sock):
#         """ Receives information sent to the socket """
#         total = ''
#         size = 512
        
#         while True:
#             current = sock.recv(size)
#             total += current.decode()
#             if len(current) < size:
#                 break
            
#         return total
        

    
#     """ Represents HTTP proxy connection """

#     def filter_packet(self, message):
#         """ Enforces the content type """
        
        
#         header = message
        
#         # Check if should block

#         # Check for content length
#         content_length = re.findall('Content-Length: (\d+)', header)
#         print('Content length: {}'.format(content_length))

#         #Check content encoding
#         content_encoding = re.findall('Content-Encoding: (\S+)', header)

#         if content_length and int(content_length[0]) > MAX_CONTENT_LENGTH:
#             return False

#         #check if encoding in GZIP
#         if content_encoding and 'gzip' in content_encoding:
#             return False

#         return True


#     def perform_client_connection(self):
#         while self.is_alive() and not self.done:
#             request = self.recv_info(self.client_socket)
#             if request:
#                 self.server_socket.sendall(request.encode())
#             else:
#                 self.done = True


#     def perform_server_connection(self):
#         while self.is_alive() and not self.done:
#             response = self.recv_info(self.server_socket)
#             if response:
#                 if self.filter_packet(response):
#                     self.client_socket.sendall(response.encode())
#                 else:
#                     print("HTTP packet dropped")
#             else:
#                 self.done = True



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
import socket
from http.client import HTTPResponse
from io import BytesIO
from infoSecWS.BasicProxy import BasicProxy  # Assuming BasicProxy is in the same module.

MAX_CONTENT_LENGTH = 102400  # Define the maximum content length to allow.
FAKE_PORT = 800
FW_IN_LEG = '10.1.1.3'  # used for the firewall to communicate with the inside world
FW_OUT_LEG = '10.1.2.3' # used for the firewall to communicate with the outside world


class HTTPProxy(BasicProxy):
    """A Proxy for handling HTTP traffic, extending the BasicProxy class."""

    def perform_client_connection(self):
        """Handles incoming client requests and forwards them to the server."""
        while not self.done:
            try:
                # Receive the HTTP request from the client
                request = self.client_socket.recv(1024)
                if not request:
                    self.done = True
                    break

                # Forward the request to the server
                self.server_socket.sendall(request)
            except Exception as e:
                print("Error during client communication: {}".format(e))
                self.done = True

    def perform_server_connection(self):
        """Handles incoming server responses and forwards them to the client."""
        while not self.done:
            try:
                # Read and parse the response from the server
                response = self.read_response(self.server_socket)

                if self.filter_packet(response):
                    # Forward the entire response to the client
                    self.client_socket.sendall(response.fp.read())
                else:
                    print("HTTP packet dropped.")
            except Exception as e:
                print("Error during server communication: {}".format(e))
                self.done = True

    def filter_packet(self, response):
        """
        Filters HTTP packets based on headers like Content-Length and Content-Encoding.
        :param response: An instance of HTTPResponse.
        :return: True if the packet is allowed, False otherwise.
        """
        content_length = response.getheader('Content-Length')
        content_encoding = response.getheader('Content-Encoding')

        # Filter based on Content-Length
        if content_length and int(content_length) > MAX_CONTENT_LENGTH:
            print("Blocked: Content-Length exceeds {} bytes.".format(MAX_CONTENT_LENGTH))
            return False

        # Filter based on Content-Encoding
        if content_encoding and 'gzip' in content_encoding.lower():
            print("Blocked: Content-Encoding is GZIP.")
            return False

        return True

    def read_response(self, sock):
        """
        Reads and parses an HTTP response from a socket.
        :param sock: The server socket.
        :return: An instance of HTTPResponse.
        """
        buffer = b''
        while True:
            data = sock.recv(1024)
            if not data:
                break
            buffer += data
            # Look for the end of HTTP headers
            if b'\r\n\r\n' in buffer:
                break

        # Create an HTTPResponse object from the buffered headers
        response = HTTPResponse(BytesIO(buffer))
        response.begin()  # Parse headers
        return response
    
if __name__ == "__main__":
    # Creating an HTTP proxy server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Enabling reuse the socket without time limitation
    sock.bind((FW_IN_LEG, FAKE_PORT))
    sock.listen(10)
    proxies = []


    print("\nStarting")

    while True:
        try:
            connection, addr = sock.accept()
        except KeyboardInterrupt:
            for proxy in proxies:
                proxy.done = True
            for proxy in proxies:
                proxy.join()
            break

        print("\nConnection accepted")
        proxy = HTTPProxy(connection, addr)
        proxies.append(proxy)
        proxy.start()

    print("\nFinished")
    