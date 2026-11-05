#!/usr/bin/env python3
"""Tiny DNS server for the tests: dns_stub.py [BIND_ADDR] [PORT]  (default 0.0.0.0 15353).
Answers A queries for nornos.test with 192.0.2.42 (TTL 60), NXDOMAIN for anything else."""
import socket, struct, sys
addr = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 15353
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((addr, port))
while True:
    q, peer = s.recvfrom(512)
    if len(q) < 12:
        continue
    # parse the question name
    i, labels = 12, []
    while i < len(q) and q[i] != 0:
        n = q[i]; labels.append(q[i+1:i+1+n].decode(errors="replace")); i += 1 + n
    qend = i + 1 + 4
    name = ".".join(labels).lower()
    tid = q[0:2]
    if name == "nornos.test":
        flags = struct.pack(">H", 0x8180)
        hdr = tid + flags + struct.pack(">HHHH", 1, 1, 0, 0)
        answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([192, 0, 2, 42])
        s.sendto(hdr + q[12:qend] + answer, peer)
    else:
        flags = struct.pack(">H", 0x8183)
        s.sendto(tid + flags + struct.pack(">HHHH", 1, 0, 0, 0) + q[12:qend], peer)
