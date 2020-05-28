import binascii
import hashlib
import socket
import ssl
import struct
import sys

host = "ptpb.io"
host = "localhost"
port = 26708
http_port = 443
http_port = 8000

ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

with socket.create_connection((host, port)) as sock, \
     ssl_context.wrap_socket(sock) as ssl_sock:

    for filename in sys.argv[1:]:
        digest = hashlib.sha256()

        # request a prefix length of 6
        prefix_length = 6
        ssl_sock.write(struct.pack("!B", prefix_length))

        with open(filename, "rb") as f:
            while buf := f.read(1024 * 64 - 4):
                ssl_sock.write(struct.pack("!L", len(buf)))
                ssl_sock.write(buf)
                digest.update(buf)
            # tell the server we have finished transmitting the file
            ssl_sock.write(struct.pack("!L", 0))

        remote_length, = struct.unpack("!L", ssl_sock.read(4))
        remote_value = ssl_sock.read(remote_length)
        url = "https://" + host + ":" + str(http_port) + "/" \
              + remote_value.decode("utf-8")
        print(filename, url)

        #print("  local: ", digest.hexdigest())
        #print(" remote: ", binascii.hexlify(remote_value).decode("utf-8"))
        # we can either close the connection here, or start sending a new file
