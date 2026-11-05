#!/usr/bin/env python3
"""UDP echo server for the tests: udp_echo.py [BIND_ADDR] [PORT]  (default 0.0.0.0 17007).
Echoes every datagram back to its sender. Runs until killed."""
import socket, sys
addr = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 17007
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((addr, port))
while True:
    data, peer = s.recvfrom(2048)
    s.sendto(data, peer)
