#!/usr/bin/env python3
"""TCP sink and source for throughput tests: tcp_sink.py [BIND_ADDR] [PORT] (default 0.0.0.0 17010).
A client sends a 4 byte big endian count N and then N bytes, which are checked against the
pattern byte[i] = (i * 7 + 3) & 255; the server then sends N bytes of the same pattern back
and closes. The reply's first 4 bytes are the number of pattern errors seen."""
import socket, sys, threading
addr = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 17010

def pattern(n, start=0):
    return bytes(((i * 7 + 3) & 255) for i in range(start, start + n))

def serve(c):
    with c:
        hdr = b""
        while len(hdr) < 4:
            d = c.recv(4 - len(hdr))
            if not d:
                return
            hdr += d
        n = int.from_bytes(hdr, "big")
        got = 0
        bad = 0
        while got < n:
            d = c.recv(min(65536, n - got))
            if not d:
                return
            if d != pattern(len(d), got):
                bad += sum(1 for i, b in enumerate(d) if b != ((got + i) * 7 + 3) & 255)
            got += len(d)
        c.sendall(bad.to_bytes(4, "big"))
        sent = 0
        while sent < n:
            k = min(65536, n - sent)
            c.sendall(pattern(k, sent))
            sent += k

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((addr, port))
s.listen(8)
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
