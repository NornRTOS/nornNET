# Zero-copy and buffer ownership: implementation plan

Status: planned 2026-11-06, not started. Goal: performance and determinism first, then
simplicity of the OS. No kernel (nornCore) changes; everything lives in nornNET and the
drivers. Measure before and after every step with nornCore `tools/measure.sh` plus the
two new latency figures (step 6).

## What exists today

- `nn_buf_t` (nn/nn_buf.h) is already the owned buffer: fixed size, from a kernel pool
  (nn_buf.c over nn_os_pool), O(1) alloc/free, no heap in the data path.
- Ownership rule is in the nn_buf.h comment: whoever holds the pointer frees it; a
  function that "takes" a buffer frees it on every path, errors included.
- Driver -> net task: `nn_net_rx` / `nn_net_rxFromIsr` put the pointer in `_rxQueue`
  (nn_os_queue of void *, the kernel queue copying 4 bytes); no payload copy.
- UDP has both styles: `nn_udpRecvBuf` / `nn_udpSendBuf` hand the buffer over,
  `nn_udpRecvFrom` / `nn_udpSendTo` copy (convenience for small payloads).
- Remaining copies: nornWIFI `nw_netdev.c` receive (blob rx buffer -> nn_buf), TCP ring
  buffers both ways (stream semantics, kept on purpose).

## Steps

1. **Ownership rules written down.** Per API in nn_buf.h, nn_udp.h, nn_tcp.h,
   nn_netdev.h: who frees in every outcome. Rule in one sentence: whoever holds the
   pointer owns the buffer; every call that receives an `nn_buf_t *` takes ownership in
   all outcomes, including errors. Exactly one owner, no reference counting (a second
   consumer, e.g. multicast to two sockets, copies explicitly).

2. **Optional ownership check** `NN_CFG_BUF_OWNER_CHECK` (default 0): one byte in the
   buffer header with the owning task id (or a "queued"/"free" marker), set on alloc and
   on every hand-over, checked on free, submit and queue get. Mismatch -> nn_os_panic.
   Zero cost when off. Host test that provokes: free by a non-owner, double hand-over,
   use after submit.

3. **Pool alignment contract instead of memcpy links.** nn_buf storage is a struct array
   (pointer aligned, size multiple of 4). Option in nornCore: RTOS_CHECK that storage and
   block size are pointer aligned and keep the plain pointer access in rtos_pool.c,
   removing the +20 cycles (ESP32) / +7 (Mega) pool alloc+free cost from audit fix F3.
   This one touches nornCore: decide together with the user (it rejects odd block sizes).

4. **SPSC pointer ring for driver -> net task.** Single producer (driver/ISR), single
   consumer (net task): ring of `void *`, head written only by the consumer, tail only
   by the producer, barriers as in nornCore hal/xtensa/amp.c, wake-up with
   `rtos_notifyFromIsr` (nn_os_notifyFromIsr). No critical section on the hot path,
   bounded, lock free. Replaces `_rxQueue` for frames; link marks and kicks keep a
   separate small path or the same ring (bit 0 mark already used). Producer never
   blocks: full ring -> drop and count (rxDropped). Several drivers -> one ring each, the
   net task drains them in a fixed order.

5. **Bounded work and quotas.** Net task handles at most N frames per wake-up
   (NN_CFG_RX_BUDGET), then runs timers, so lower tasks get predictable time. Per socket
   quota as today's `rxMax` documented as the back-pressure mechanism. Pool sizing rule
   in the README: NUM_BUFS >= sum of ring/queue depths + buffers in transmission + the
   driver's receive needs, so worst case is computable.

6. **Filter before the WiFi copy.** In nw_netdev.c receive(): check destination MAC
   (unicast to us, broadcast, subscribed multicast) and EtherType (IP, ARP) in the blob's
   buffer before nn_bufAlloc + memcpy; the copy itself stays (the radio's own pool is
   small and must be returned at once).

7. **Latency as contract.** Two figures into the test suite and measure.sh:
   cycles from driver ISR to the net task holding the pointer, and cycles from enqueue to
   `nn_udpRecvBuf` returning. With fixed pool and bounded rings both have a worst case
   number, written in the README.

## Not doing

- A second, generic buffer layer on top of nn_buf (two names for one thing; if nornCrypto
  needs owned buffers, lift nn_buf into its own small module instead).
- Zero-copy TCP (segment lists with varying lifetime work against determinism).
- Holding the WiFi blob's rx buffer across a task boundary (starves the radio).

## Tests per step

nornNET `make host-test` (8 programs + new ownership test), `make nn02-sim` (QEMU),
nornWIFI nw01/nw02 on the board (ping loss, throughput), nornCore regression if step 3
is taken, measure.sh before/after.
