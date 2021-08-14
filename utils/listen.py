import socket
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

sock.bind(('127.0.0.1', int(sys.argv[1])))
sock.listen(0)

conn, addr = sock.accept()
print(conn, addr)