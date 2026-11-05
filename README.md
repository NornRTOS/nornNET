# nornNET

A small, fast TCP/IP stack for [nornCore](../nornCore). Zero-copy packet buffers, one net
task, one lock, no malloc; loosely modelled on
[microps](https://github.com/pandax381/microps) in structure, built for a
microcontroller in substance. Target: ESP32 first, tested on the host and in Espressif's
QEMU before any hardware.

Status: v0.3. Ethernet, ARP, IPv4, ICMP, UDP sockets, DHCP client, DNS resolver and TCP
(RFC 9293 with slow start, fast retransmit, delayed ACK, Nagle, zero window probing, out
of order storage), verified against the Linux kernel (TAP) and QEMU's user mode network,
on the ESP32 board over SLIP on its UART (the Linux kernel as peer through a small
bridge, no extra hardware), plus a mutation fuzzer of the whole receive path. The long
stability gate (day long soaks, loss injection) is deferred and still owed. See
`doc/plan.md`.

## What exists

| part | file | state |
|---|---|---|
| OS contract | `os/nn_os.h` | nornOS and POSIX implementations |
| packet buffers | `nn/nn_buf.[ch]` | pool, push/pull/put/trim, statistics |
| devices, protocols, net task | `nn/nn_net.[ch]` | registry, receive queue, dispatch, link changes (`nn_netdevLinkChanged`) |
| Ethernet II | `nn/nn_eth.[ch]` | filter, dispatch by type, output with padding |
| ARP | `nn/nn_arp.[ch]` | table, requests with retries, one parked packet per address, replies |
| IPv4 | `nn/nn_ip.[ch]` | interfaces, routing, validation, no fragments by design |
| ICMP | `nn/nn_icmp.[ch]` | echo reply in place, echo request (ping), destination unreachable |
| UDP | `nn/nn_udp.[ch]` | sockets with queued buffers, blocking or callback receive, zero copy variants |
| DHCP | `nn/nn_dhcp.[ch]` | client: discover, request, bind, renew, rebind, NAK, lease confirmed on a link return |
| DNS | `nn/nn_dns.[ch]` | stub resolver: A records, retries, small cache, blocking or callback |
| TCP | `nn/nn_tcp.[ch]` | caller owned sockets and rings, listen/accept/connect/send/recv/close, RFC 5681 congestion control, RFC 6298 timer, TIME_WAIT table |
| checksum | `nn/nn_cksum.[ch]` | RFC 1071, portable |
| timers | `nn/nn_timer.[ch]` | sorted list run by the net task |
| drivers | `drv/` | loopback; Linux TAP for the host; OpenCores `open_eth` for QEMU; SLIP over any byte stream (`nn_drv_slip`) |
| host glue | `host/nn_host.c` | real time idle hook for the nornOS host port |

Next: the ESP32's own radio as a separate library over nornOS (no FreeRTOS), W5500 over
SPI when a module exists, the deferred stability gate, extras. See `doc/plan.md`.

## Building and testing

```
make host-test                        # unit tests on the PC
sudo tools/tap_setup.sh               # once: TAP interface nn0 for test_tap
make nn01-sim                         # test application in QEMU
make nn02-sim                         # pings QEMU's gateway through the emulated MAC
make nn03-sim                         # DHCP, UDP echo and DNS against QEMU plus host side servers
make nn04-sim                         # TCP: echo, 1 MB each way, HTTP GET, passive open, refused
make nn05-upload PORT=/dev/ttyUSB0    # the board over SLIP: then
make nn05-slip                        #   bridge UART0 to the TAP, host servers, 40 s of tests
make nn01-upload PORT=/dev/ttyUSB0    # and on the board (nn02 is QEMU only)
make nn01-monitor
make test-all                         # all of the above, one line per result
tools/soak_tap.sh 3600                # one hour of pings from Linux through the TAP
```

Test applications: nn01 exercises the foundation on loopback, nn02 talks to a real
peer (QEMU's slirp answers ARP and ping for 10.0.2.2), nn03 gets its address from
slirp's DHCP and talks UDP and DNS to `tools/udp_echo.py` and `tools/dns_stub.py` on the
host, nn04 talks TCP to `tools/tcp_echo.py`, `tools/tcp_sink.py` and python's
`http.server` and accepts a connection from `tools/tcp_client.py` through a QEMU
`hostfwd` rule; `tools/with_servers.sh` starts all of them around the run. nn05 runs on
the real board with no network hardware: it speaks SLIP on UART0 at 921 600 baud and
`tools/slip_bridge.py` turns that into a peer on the TAP, answering ARP for 10.0.77.3 and
printing the text the board writes between frames. The whole test set runs against the
Linux kernel that way at about 88 kB/s each way, the line rate.

Host tests: `test_buf`, `test_ip`, `test_udp` and `test_tcp` feed synthetic frames into
the stack on the POSIX layer under ASan and UBSan; `test_fuzz` mutates frames of every
protocol (200 000 by default, `NN_FUZZ_ITERS` and `NN_FUZZ_SEED` to change) with a live
connection in place; `test_slip` checks the SLIP framing; `test_net` runs the real net task on the nornOS host port with
loopback, UDP and a TCP echo task; `test_tap` does ping, UDP, DNS, TCP echo, a passive
open, 2 MB each way, an HTTP GET and a refused connect against the Linux kernel.

`NORNOS=/path/to/nornOS` if it is not next to this repository.

## Using it in a nornOS application

In `app.mk`:

```make
NORNNET_DIR = /path/to/nornNET
MODULES    += $(NORNNET_DIR)/nornnet.mk
```

and an `nn_config.h` next to the application with at least `NN_CFG_TASK_PRIO` (the net
task's priority, above every task that uses the stack). All `NN_CFG_*` options and their
defaults are in `nn/nn_cfg.h`. In `main`, after `rtos_init`: `nn_init()`, register the
devices and add their addresses with `nn_ifaceAdd` (or an empty one and `nn_dhcpStart`
from a task), then `rtos_start()`. The socket APIs are in `nn/nn_udp.h` and
`nn/nn_tcp.h`: caller owned sockets (and, for TCP, caller owned send and receive rings),
blocking calls with a timeout from a task, or callbacks that run in the net task. The
stack lock is re-entrant for the net task, so a callback may call the socket API.

A driver whose carrier can go away (WiFi, a cable) reports it with
`nn_netdevLinkChanged(dev, up)` from any task or interrupt. The net task then acts under
the lock: on a loss the device's ARP entries are dropped; on a return every DHCP client
on the device confirms its lease at once (`nn_dhcpLinkUp`: broadcast REQUEST, three
tries, then DISCOVER), keeping the address meanwhile so an outage on the same network
does not disturb the connections. When an interface's address changes or goes
(`nn_ifaceSetAddr`), the TCP connections bound to the old one end with `NN_ERR_DOWN`.
