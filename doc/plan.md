# nornNET design sketch

A small, fast TCP/IP stack for nornOS. This document is the plan before any code exists:
what the stack is for, what it borrows from microps, what it deliberately does differently,
how it is tested and in which order it is built. The order is UDP/IP first, TCP only after
the lower layers have proven stable.

Status: phases 1 to 3 (foundation, v0.1 link and IP, v0.2 UDP/DHCP/DNS) and v0.3 TCP
implemented and verified 2026-11-02 on host, QEMU and the ESP32 board. The stability
gate was deferred on the user's decision (see the phases) and is still owed before any
release. Decided the same day: ESP32 first; whether TCP will ever run on the Mega 2560 is
open, so the small profile is a design constraint, not a deliverable.

## Goals and non-goals

Goals, in priority order:

1. Correct against a real peer (the Linux kernel stack), not just against itself.
2. Small and predictable: static memory, no malloc in the data path, bounded work per
   packet, configurable at compile time down to a few kilobytes.
3. Fast on the targets we have: zero-copy between layers, one task, one lock.
4. Readable in the microps spirit: one file per protocol, built up layer by layer.

Non-goals, at least for the first versions: BSD socket compatibility, IPv6, IP
fragmentation and reassembly, TCP options beyond MSS, multicast beyond what DHCP and
mDNS need, raw sockets, routing between interfaces.

## Facts that shape the design

- **Espressif's QEMU emulates an Ethernet MAC.** `qemu-system-xtensa -machine esp32` offers
  the OpenCores `open_eth` NIC model. The whole stack can therefore run on the ESP32 target
  in CI against QEMU's user-mode network (slirp) or a TAP bridge, without hardware.
- **None of our boards has a network nornOS can reach today.** The NodeMCU-32S has WiFi,
  but driving it means Espressif's closed radio libraries behind an OS adaptation layer: a
  separate project that comes after the stack. The Mega 2560 has no network at all.
- **Real hardware needs an SPI Ethernet board.** The choice is a WIZnet W5500 used in
  MACRAW mode, so it delivers raw Ethernet frames and the stack stays ours. It works with
  both AVR and ESP32. nornOS HAL has no SPI yet; that is part of the hardware phase.
- **RAM.** ESP32: 176 KB DRAM per core in the single-core layout. Mega 2560: 8 KB total,
  shared with the application. UNO: 2 KB, excluded.

## Repository and integration

nornNET is its own repository, `~/dev/gits/nornNET`, same licence as nornOS. Reasons: the
kernel stays small and auditable, the stack has its own release cadence, UNO can never use
it, and the stack is testable on a host without nornOS at all.

Layout:

```
nornNET/
  nn/            protocol code, OS independent
    nn_buf.c     packet buffers
    nn_net.c     devices, protocol dispatch, the net task loop
    nn_eth.c nn_arp.c nn_ip.c nn_icmp.c nn_udp.c
    nn_dhcp.c nn_dns.c
    nn_tcp.c     later
  os/            the OS abstraction, one file per OS
    nn_os.h      the contract (below)
    nn_os_nornos.c
    nn_os_posix.c   host unit tests without nornOS
  drv/           netdev drivers
    nn_drv_loop.c nn_drv_tap.c nn_drv_openeth.c nn_drv_w5500.c
  test/          host tests, QEMU tests, scripts
  doc/
  nornnet.mk     included by a nornOS application
```

nornOS side: `app.mk` may set `MODULES += $(NORNNET_DIR)/nornnet.mk`; the top Makefile
includes each listed file, which adds sources, include paths and `NN_CFG_*` defaults.
That is the only change to nornOS, plus the SPI HAL in the hardware phase.

### The OS contract (`nn_os.h`)

Everything the stack needs from the OS, mapped one to one onto nornOS primitives:

| nn_os | nornOS | used for |
|---|---|---|
| `nn_os_taskCreate` | `rtos_createTask` | the net task |
| `nn_os_lock / unlock` | `rtos_mutexLock / Unlock` | the single stack lock |
| `nn_os_queue*` | `rtos_queue*` incl. `FromIsr` | driver to net task hand-over |
| `nn_os_notify / notifyWait` | `rtos_notify / rtos_notifyWait` | blocking socket calls, driver wake-up |
| `nn_os_now` | `rtos_getTick` | ARP ageing, DHCP leases, RTO |
| `nn_os_pool*` | `rtos_pool*` | packet buffers |
| `nn_os_panic` | `rtos_panic` | invariant violations |
| `nn_os_trace` | `RTOS_TRACE` | optional tracing |

No timers from the OS: the net task sleeps with a timeout equal to the next stack timer,
which is also what tickless idle wants.

## Architecture

```
  application tasks
      |  nn_udp_*, later nn_tcp_*      (take the stack lock, block on notify)
  ----+-------------------------------------------------------------
      |                     stack lock
  net task:  loop { wait(rx queue, next timer) ; dispatch ; run timers }
      |
  nn_net   protocol table by ethertype / IP protocol number
  nn_eth -> nn_arp
         -> nn_ip  -> nn_icmp
                   -> nn_udp -> nn_dhcp, nn_dns, application PCBs
                   -> nn_tcp (later)
      |
  netdev ops: open, close, transmit(buf), link state
      |
  drivers: loop, tap, open_eth, w5500        (rx ISR or poll task -> rx queue)
```

**One task, one lock, run to completion.** All stack state is owned by the net task.
Drivers never touch protocol state; they put a filled buffer on the rx queue and signal.
Application calls take the stack lock, poke the PCB, and if they must wait they park on
their own task's notification and release the lock. This replaces microps' per-protocol
queues, its softirq thread and its per-object mutexes with a model that has no lock
ordering to get wrong.

**Packet buffers (`nn_buf_t`).** Fixed-size blocks from a nornOS pool, one frame per
block, with a configurable headroom so each layer prepends its header in place:

```
  | headroom | eth | ip | udp | payload ............ | tailroom |
             ^data (moves as headers are pushed/pulled)
```

A buffer is handed up or down by pointer; the only copies in the whole stack are the
driver's DMA or SPI transfer and the copy into the application's receive buffer. Buffers
allocated from an ISR use the `FromIsr` pool variants. Pool exhaustion drops the frame and
counts it; it never blocks the driver.

**Net device (`nn_netdev_t`).** Name, type, MTU, hardware address, flags (up, link, promisc),
ops, and a list of interfaces (`nn_iface_t`: one IPv4 address, netmask, gateway). Ethernet
framing is the only device type at first; loopback is an Ethernet device without ARP.

**Timers.** A sorted list inside the stack (ARP entry ageing, DHCP renew, DNS retry, later
TCP RTO and delayed ACK). The net task's wait timeout is the head of the list.

**Checksums.** One pass, 32-bit accumulator on Xtensa, 16-bit with carry on AVR, folded
once. Pseudo header computed in place. The UDP/TCP checksum covers the payload buffer
directly, no gather copy.

## Borrowed from microps and changed

| microps | nornNET | why |
|---|---|---|
| protocol registration by type, netdev ops, iface | kept | clean, small, readable |
| fixed PCB tables | kept | static memory |
| timers as a list walked by one thread | kept | simple |
| memcpy at every layer and into every queue | zero-copy `nn_buf_t` | efficiency, RAM |
| one queue + softirq thread per protocol | one net task, run to completion | fewer locks, fewer tasks |
| mutex per PCB and per table | one stack lock | no lock ordering |
| pthreads, signals, malloc | `nn_os.h` on nornOS, pools | bare metal |
| `sock.c` BSD-like layer | native blocking API, BSD shim maybe later | size |
| TCP without congestion control | slow start, congestion avoidance, Karn/Jacobson RTO | good citizen on real networks |

## Protocol scope by version

**v0.1, link and IP.** Ethernet II, ARP (request, reply, table with ageing, pending queue
of one buffer per unresolved address), IPv4 (no options, no fragments: DF set on send,
fragments dropped and counted), ICMP echo reply and destination unreachable (port) for
UDP. Exit criterion: `ping` from Linux answers through TAP on the host port and through
open_eth in QEMU, for an hour, with zero buffer leaks (pool free count returns to start).

**v0.2, UDP and address acquisition.** UDP with PCB table, bind, sendto, recvfrom with
timeout, ICMP port unreachable on unbound ports. DHCP client (discover, offer, request,
ack, renew, rebind; static address fallback). DNS resolver (A records, one outstanding
query per PCB, retry and timeout). Exit criterion: the stability gate below.

**Stability gate before TCP.** All of these green on host TAP and QEMU open_eth, and
repeated in `test-all`:

- 24 h soak: UDP echo at a steady rate plus ping, no leak, no panic, counters consistent.
- Loss and reorder injected with `tc netem` (10 % loss, 50 ms jitter): echo recovers,
  ARP re-resolves, DHCP renews.
- Fuzzing of the receive path (libFuzzer or AFL on the host build with ASan/UBSan) for at
  least a few CPU hours without a crash.
- Malformed input tests: short frames, bad checksums, IP header length lies, UDP length
  larger than frame, ARP for other hosts, broadcasts and multicasts we do not want.

**v0.3, TCP.** State machine per RFC 9293, passive and active open, data transfer,
graceful and abortive close, TIME_WAIT. Retransmission queue, RTO with Karn and Jacobson,
slow start and congestion avoidance, fast retransmit on three duplicate ACKs, delayed
ACK, optional Nagle, MSS option only. Per-socket send and receive rings of fixed size from
configuration. Exit criterion: iperf3 and an HTTP fetch against Linux through TAP, a 24 h
soak with netem loss, fuzzing of the segment path.

**Later, as wanted:** SNTP, mDNS responder, a minimal HTTP server, BSD socket shim,
IPv6 (the address type is abstracted from the start so it is a new layer, not a rewrite),
WiFi netdev for ESP32 over Espressif's libraries.

## API sketch

Blocking calls with timeouts, errors as negative `nn_err_t`, no hidden allocation.

```c
nn_err_t nn_init(void);                      /* creates the net task */
nn_err_t nn_netdevRegister(nn_netdev_t *pDev);
nn_err_t nn_ifaceAdd(nn_netdev_t *pDev, nn_iface_t *pIf, nn_ip4_t addr, nn_ip4_t mask, nn_ip4_t gw);
nn_err_t nn_dhcpStart(nn_iface_t *pIf);     /* fills pIf when bound, signals an evgroup */

nn_err_t nn_udpOpen(nn_udp_t *pSock);
nn_err_t nn_udpBind(nn_udp_t *pSock, nn_ip4_t addr, uint16_t port);
nn_err_t nn_udpSendTo(nn_udp_t *pSock, const void *p, size_t n, nn_ip4_t to, uint16_t port);
int      nn_udpRecvFrom(nn_udp_t *pSock, void *p, size_t n, nn_ip4_t *pFrom, uint16_t *pPort,
                        uint32_t timeoutTicks);
nn_err_t nn_udpClose(nn_udp_t *pSock);

nn_err_t nn_dnsResolve(const char *name, nn_ip4_t *pAddr, uint32_t timeoutTicks);

/* v0.3 */
nn_err_t nn_tcpOpen(nn_tcp_t *pSock, uint8_t *pRxBuf, size_t rxN, uint8_t *pTxBuf, size_t txN);
nn_err_t nn_tcpConnect/Listen/Accept/Send/Recv/Close(...);
```

Sockets are caller-owned structs, so the application decides where the memory lives.
An optional callback hook per socket (`onReadable`) is cheap to add for event-style apps.

## Memory profiles and configuration

| profile | target | buffers | sockets | approx. RAM |
|---|---|---|---|---|
| full | ESP32 | 16 × 1536 | 8 UDP, 4 TCP × (2 KB + 2 KB) | 45 KB |
| small | Mega 2560 | 2 × 600 (MSS 536) | 2 UDP, 1 TCP × (512 + 512) | 2.5 KB |
| none | UNO | excluded via `ONLY_BOARDS` | | |

All `NN_CFG_*` macros have defaults in `nornnet.mk` chosen by the nornOS `BOARD`, and the
application overrides them in its `rtos_config.h`: `NN_CFG_NUM_BUFS`, `NN_CFG_BUF_SIZE`,
`NN_CFG_HEADROOM`, `NN_CFG_ARP_ENTRIES`, `NN_CFG_UDP_PCBS`, `NN_CFG_TCP_PCBS`,
`NN_CFG_DHCP`, `NN_CFG_DNS`, `NN_CFG_STATS`, `NN_CFG_TRACE`.

Honest note on the small profile: it competes with the brewing application for the same
8 KB. It is kept as a design constraint, because it keeps the code lean, but it is not a
deliverable of any phase until the user says so. ESP32 is the target.

## Drivers

| driver | where | role |
|---|---|---|
| loop | all | tests without a peer, always first |
| tap | host port, Linux `/dev/net/tun` | main development target, peer is the Linux kernel |
| open_eth | QEMU esp32 | CI on the real architecture, slirp `hostfwd` or TAP bridge |
| slip | any UART | the board against Linux with no network hardware: `tools/slip_bridge.py` makes the serial line a peer on the TAP |
| w5500 MACRAW | Mega and ESP32 over SPI | real Ethernet, needs `hal/spi.h` |
| wifi | ESP32 | nornWIF (own repository), Ethernet-framed netdev `wl0` |

Driver receive path: ISR (open_eth, w5500 INT pin) or a poll task (tap) allocates a buffer
from the pool, fills it, queues it, signals the net task. Transmit path: the net task
calls `transmit`, which copies into the device and frees the buffer, or keeps it until a
completion interrupt frees it.

## Testing

Host, no OS: unit tests of checksum, header parse and build, ARP table, timer list, DHCP
option parsing. Run with ASan and UBSan like nornOS host tests.

Host, nornOS host port plus TAP: Python scripts using scapy or plain sockets drive
ping, UDP echo, DHCP (dnsmasq on the TAP), DNS. `tc netem` adds loss, delay, reorder.
Fuzzing: libFuzzer harness feeding `nn_net_input` directly.

QEMU esp32 with open_eth: the same scripts through slirp `hostfwd`, in `tools/test_all.sh`
as `nn01..nnNN` applications printing `RESULT nnNN PASS` like the tcXX tests.

Hardware: W5500 on the Mega and the ESP32 board, same applications, peer is the
development PC.

## Phases

1. **Foundation.** Done 2026-11-02. Repository, `nn_os.h` with nornos and posix
   implementations, buffers, netdev, Ethernet framing, timers, loopback, TAP driver, host
   test harness, test application nn01 for the ESP32, the `MODULES` hook in nornOS. A
   frame goes down and up through the layers with no copy; 57 875 loopback round trips per
   second with 1 KB on the board at 160 MHz.
2. **v0.1.** Done 2026-11-02. Ethernet, ARP, IPv4, ICMP, checksum, open_eth driver,
   unit test of every input path (test_ip), ping both ways against the Linux kernel
   (test_tap) and against QEMU's slirp (nn02: 20 of 20 replies, 12 000 ping soak), the
   TAP soak script. The hour long run (tools/soak_tap.sh 3600, Linux pinging every 2 ms):
   1 798 975 echo requests, 0 lost, round trip max 1.3 ms, every buffer free at the end,
   no bad headers.
3. **v0.2.** Done 2026-11-02. UDP sockets (queued buffers, blocking and callback
   receive, zero copy send and receive), DHCP client (slirp binds it in 1 ms in QEMU),
   DNS resolver, port unreachable; unit test test_udp, UDP over loopback with blocking
   receive in test_net, nn03 in QEMU (200 of 200 echoes against a host side server, DNS
   through a stub), test_tap extended with UDP echo and DNS against Linux.
4. **Stability gate.** Deferred 2026-11-02 (user: save the day long gate for later, it
   stays an open task): 24 h soaks on TAP and QEMU, `tc netem` loss and reorder, long
   fuzzing. The quick parts were pulled into phase 5: the mutation fuzzer `test_fuzz`
   runs on every `host-test` and has done 60 million mutated frames over 20 seeds without
   a finding, and the malformed input cases live in `test_ip`, `test_udp`, `test_tcp`.
   Run 2026-11-03/04 (user: after reconnection). First finding, within minutes of the
   netem part (`test_netem`, new: UDP echo, DNS, 100 KB sink transfers in cycles over
   the TAP with `tc netem loss 10% delay 20ms 50ms reorder 25% 50%` applied by the
   user): 3 of 11 TCP transfers stalled for good in the sending direction. Cause: an ACK
   above `sndNxt` was treated as acknowledging the future and ignored, and after a
   retransmission timeout `sndNxt` is pulled back to `sndUna`, so when the peer already
   held everything sent before the timeout (only its ACKs were lost) its cumulative ACK
   was above `sndNxt` and rejected every time; the same segment was resent at every
   backoff until the retry limit. Fixed: the test is against `sndMax`, an ACK past the
   resend pointer moves it, the zero window probe byte counts into `sndMax`; unit test
   in test_tcp. After the fix 21 of 21 under netem in three minutes, the hour runs. The
   WiFi soak's one stalled send per half hour (nornWIF nw05, step 3) had the same
   shape and the soak was restarted with the fix. Also seen: the host test config has
   six buffers and the pool hits zero under reorder (no failure, but tight). Still to
   run: the clean 24 h TAP soak after netem is removed, the QEMU 24 h soak and the 8 h
   fuzz run are in progress.
5. **v0.3 TCP.** Done 2026-11-02, ahead of hardware because no W5500 exists yet.
   nn_tcp: RFC 9293 state machine (TIME_WAIT in a small table so sockets are reusable
   at once), caller owned rings, one out of order range kept in place, delayed ACK with
   immediate ACK on the second segment and on gap filling, Nagle plus the sender side
   silly window rule, RFC 6298 timer with Karn and backoff, zero window probing, RFC 5681
   slow start, congestion avoidance, fast retransmit and recovery with NewReno partial
   ACKs, MSS option only. Blocking and event APIs, re-entrant stack lock for callbacks.
   Verified: test_tcp (synthetic segments, every path above), test_net (64 KB echo over
   loopback between two tasks through 1 KB rings), test_tap against Linux (200 KB echo,
   passive open from a Python client, 2 MB each way at 28 to 36 MB/s through TAP with
   ASan at -O0, HTTP GET from python's http.server, refused connect, 0 retransmissions),
   nn04 in QEMU (same against slirp and host servers, 100 KB echo in 5 ms, 1 MB each
   way at 33 MB/s of emulated time, a passive open through hostfwd). iperf3 is not
   installed here; tcp_sink.py measures instead.
6. **The board without network hardware.** Done 2026-11-02: SLIP (RFC 1055) driver
   over any byte stream, `NN_DEV_SLIP` devices go straight to IP, nornOS got interrupt
   driven UART receive on the ESP32 (`uart_onReceive`), and `tools/slip_bridge.py`
   bridges the serial port to the TAP without root, answering ARP for the board and
   printing the console text the board writes between frames (so one UART carries both).
   nn05 runs ping, UDP, DNS, TCP echo, 200 KB each way, HTTP and a passive open on the
   real ESP32 against the Linux kernel at 921 600 baud: 88 kB/s each way, 0
   retransmissions, 0 drops; part of `test-all`. Transmit is still polled: a 1500 byte
   frame holds the net task for 16 ms, fine at this rate.
7. **WiFi, the ESP32's own radio.** Started 2026-11-03 as the separate repository
   nornWIF (~/dev/gits/nornWIF, plan in its doc/plan.md), hung in through `MODULES`
   like nornNET. It holds Espressif's binary radio libraries, the adapter table that
   maps their OS calls to `rtos_*`, the chip glue, ESP-IDF's wpa_supplicant built from
   source for WPA2 personal, and a netdev for nornNET ("wl0"). The libraries need
   about 350 KB of code, so nornOS first gained code running from flash through the
   cache (FLASH_OBJS, tc09) rather than new primitives. Verified 2026-11-03 against
   the office access point: scan, WPA2 join, DHCP, DNS, HTTP, and TCP through the sink
   at 400 to 650 kB/s each way with 8 to 16 KB rings (nornWIF doc/plan.md has the
   table). A one-off receive stall of 1 MB in 12 runs is noted there for the stability
   gate. 2026-11-03 later: link changes. A driver reports nn_netdevLinkChanged, the net
   task flushes ARP on a loss and has DHCP confirm the lease on a return
   (nn_dhcpLinkUp, address kept meanwhile); nn_ifaceSetAddr ends the TCP connections of
   an address that went (nn_tcp_addrLost, NN_ERR_DOWN). Host tests in test_udp and
   test_tcp; nornWIF's nw04 runs it on the board (reassociation 160 ms, DHCP confirmed
   within 100 ms, TCP intact).
8. **Hardware.** SPI in nornOS HAL (avr, xtensa), W5500 driver, small profile on the Mega,
   nnXX tests on both boards in `test-all`. Needs a W5500 module.
9. **Finish and extras.** Documentation, Doxygen, SNTP, mDNS, BSD shim as wanted.

Phases 1 to 3 are roughly the size of nornOS phases 1 to 2. TCP turned out about the
size of phases 2 and 3 together. Phase 8 needs a W5500 board to be bought.

## Decisions wanted

- Licence for nornNET (same as nornOS is the natural choice).
- Buy a W5500 module before phase 8, one per board or move it between them.
- Whether the small Mega profile is a real requirement or only a design constraint. It
  changes nothing before phase 8.
- When to run the deferred stability gate (phase 4): it needs a day of machine time on
  the TAP and sudo for `tc netem`.
