#!/usr/bin/env python3
"""Client side of the passive open test: tcp_client.py HOST PORT [DELAY_S] [BYTES]
Waits DELAY_S (default 0), connects to HOST:PORT, sends BYTES (default 100000) bytes of
the pattern byte[i] = (i * 7 + 3) & 255 while reading the echo, then half closes and
checks that exactly the same bytes came back. Prints 'tcp_client OK' and exits 0 on
success. Retries the connect for 60 s so it may be started before the server listens."""
import socket, sys, time, threading
host, port = sys.argv[1], int(sys.argv[2])
delay = float(sys.argv[3]) if len(sys.argv) > 3 else 0.0
n = int(sys.argv[4]) if len(sys.argv) > 4 else 100000
time.sleep(delay)
data = bytes(((i * 7 + 3) & 255) for i in range(n))
deadline = time.time() + 60
while True:
    try:
        s = socket.create_connection((host, port), timeout=10)
        break
    except OSError:
        if time.time() > deadline:
            print("tcp_client FAIL connect")
            sys.exit(1)
        time.sleep(0.2)
got = bytearray()
def reader():
    while True:
        d = s.recv(65536)
        if not d:
            break
        got.extend(d)
t = threading.Thread(target=reader)
t.start()
s.sendall(data)
s.shutdown(socket.SHUT_WR)
t.join(30)
s.close()
ok = bytes(got) == data
print("tcp_client", "OK" if ok else "FAIL %d/%d bytes" % (len(got), n))
sys.exit(0 if ok else 1)
