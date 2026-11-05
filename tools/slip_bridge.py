#!/usr/bin/env python3
"""SLIP to TAP bridge for a board on a serial port, so the Linux kernel is its IP peer
without any root privilege (the TAP interface nn0 from tools/tap_setup.sh is reused).

    slip_bridge.py PORT BAUD SECONDS [BOARD_IP] [TAP]

Resets the board like tools/monitor.py, then for SECONDS: IP packets the board sends in
SLIP frames go out on the TAP as Ethernet frames to the kernel's MAC; frames from the
kernel for BOARD_IP go to the board; ARP requests for BOARD_IP are answered here. Bytes
the board sends between SLIP frames are console text and are printed, so the board's
test output and its network share one UART. Defaults: 10.0.77.3 on nn0."""
import sys, os, fcntl, struct, select, time, serial

port, baud, seconds = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
board_ip = sys.argv[4] if len(sys.argv) > 4 else "10.0.77.3"
tap_name = sys.argv[5] if len(sys.argv) > 5 else "nn0"
END, ESC, ESC_END, ESC_ESC = 0xC0, 0xDB, 0xDC, 0xDD
board_mac = bytes.fromhex("024e4e000003")
board_ip_b = bytes(int(x) for x in board_ip.split("."))

with open(f"/sys/class/net/{tap_name}/address") as f:
    tap_mac = bytes.fromhex(f.read().strip().replace(":", ""))
tun = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
fcntl.ioctl(tun, 0x400454CA, struct.pack("16sH", tap_name.encode(), 0x0002 | 0x1000))  # TUNSETIFF, IFF_TAP|IFF_NO_PI

ser = serial.Serial(port, baud, timeout=0, write_timeout=5)
ser.dtr = False
ser.rts = True
time.sleep(0.1)
ser.rts = False

stats = {"toBoard": 0, "toLinux": 0, "arp": 0, "bytesToBoard": 0, "bytesToLinux": 0}

def slip_encode(p):
    out = bytearray([END])
    for b in p:
        if b == END:
            out += bytes([ESC, ESC_END])
        elif b == ESC:
            out += bytes([ESC, ESC_ESC])
        else:
            out.append(b)
    out.append(END)
    return bytes(out)

def to_linux(ip_packet):
    os.write(tun, tap_mac + board_mac + b"\x08\x00" + ip_packet)
    stats["toLinux"] += 1
    stats["bytesToLinux"] += len(ip_packet)

def to_board(ip_packet):
    ser.write(slip_encode(ip_packet))
    stats["toBoard"] += 1
    stats["bytesToBoard"] += len(ip_packet)

def arp_announce():
    # Gratuitous reply so the kernel's neighbour table knows the board at once.
    pkt = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + board_mac + board_ip_b + tap_mac + board_ip_b
    os.write(tun, b"\xff\xff\xff\xff\xff\xff" + board_mac + b"\x08\x06" + pkt)

def handle_tap(frame):
    if len(frame) < 14:
        return
    etype = frame[12:14]
    if etype == b"\x08\x06" and len(frame) >= 42:
        op = frame[20:22]
        target = frame[38:42]
        if op == b"\x00\x01" and target == board_ip_b:
            sender_mac, sender_ip = frame[22:28], frame[28:32]
            reply = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + board_mac + board_ip_b + sender_mac + sender_ip
            os.write(tun, sender_mac + board_mac + b"\x08\x06" + reply)
            stats["arp"] += 1
    elif etype == b"\x08\x00" and len(frame) >= 34:
        ip = frame[14:]
        if ip[16:20] == board_ip_b:
            total = (ip[2] << 8) | ip[3]
            to_board(ip[:total])

in_frame = False
esc = False
frame = bytearray()
text = bytearray()

def flush_text():
    global text
    if text:
        s = text.decode("utf-8", errors="replace")
        s = "".join(c for c in s if c == "\n" or c == "\t" or 32 <= ord(c) < 127)
        if s.strip():
            sys.stdout.write(s if s.endswith("\n") else s + "\n")
            sys.stdout.flush()
        text = bytearray()

def handle_serial(data):
    global in_frame, esc, frame
    for b in data:
        if in_frame:
            if b == END:
                if frame:
                    to_linux(bytes(frame))
                    frame = bytearray()
                    in_frame = False
            elif b == ESC:
                esc = True
            else:
                if esc:
                    b = END if b == ESC_END else ESC if b == ESC_ESC else b
                    esc = False
                frame.append(b)
                if len(frame) > 2000:
                    frame = bytearray()
                    in_frame = False
        else:
            if b == END:
                flush_text()
                in_frame = True
                esc = False
            else:
                text.append(b)
                if b == 10:
                    flush_text()

arp_announce()
t0 = time.time()
try:
    while time.time() - t0 < seconds:
        r, _, _ = select.select([ser.fileno(), tun], [], [], 0.05)
        if ser.fileno() in r:
            data = ser.read(4096)
            if data:
                handle_serial(data)
        if tun in r:
            try:
                while True:
                    handle_tap(os.read(tun, 4096))
            except BlockingIOError:
                pass
except KeyboardInterrupt:
    pass
flush_text()
print("slip_bridge: to board %d packets %d bytes, to linux %d packets %d bytes, arp %d" %
      (stats["toBoard"], stats["bytesToBoard"], stats["toLinux"], stats["bytesToLinux"], stats["arp"]))
