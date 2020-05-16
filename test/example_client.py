import socket
import ssl
import struct

host = 'localhost'
port = 8000

ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

with socket.create_connection((host, port)) as sock, \
     ssl_context.wrap_socket(sock) as ssl_sock:

    with open(sys.argv[1], "rb") as f:
        while buf := f.read(1024 * 32):
            ssl_sock.write(struct.pack("!L", len(buf)))
            ssl_sock.write(buf)
            # tell the server we have finished transmitting the file
        ssl_sock.write(struct.pack("!L", 0))

    # we can either close the connection here, or start sending a new file
