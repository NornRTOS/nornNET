#!/usr/bin/env python3
"""TCP echo server for the tests: tcp_echo.py [BIND_ADDR] [PORT]  (default 0.0.0.0 17008).
Echoes every byte back on each connection, many connections at a time. Runs until killed."""
import socket, sys, threading
addr = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 17008

def serve(c):
    with c:
        while True:
            d = c.recv(65536)
            if not d:
                break
            c.sendall(d)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((addr, port))
s.listen(8)
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
