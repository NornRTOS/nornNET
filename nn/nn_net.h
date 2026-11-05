#ifndef NN_NET_INCLUDED
#define NN_NET_INCLUDED
/**
 * @file nn_net.h
 * The core: device registry, protocol dispatch, the receive queue and the net task.
 *
 * Threading model. One net task owns all protocol state. Drivers never touch it: they
 * queue received buffers with nn_net_rx(FromIsr) and the net task processes them one by
 * one with the stack lock held. Application calls (nn_udp_*, ...) take the same lock.
 * Under nornOS the lock is an ICPP mutex whose ceiling is the net task's priority, so a
 * lower task inside the stack simply cannot be preempted by the net task; the lock never
 * blocks.
 */

#include "nn_types.h"
#include "nn_cfg.h"
#include "nn_buf.h"
#include "nn_netdev.h"

/** A protocol above the link layer, keyed by Ethernet type (NN_ETH_TYPE_*). */
typedef struct nn_proto
{
    uint16_t type;
    const char *name;
    /** Takes the buffer: pData points past the link header. */
    void (*input)(nn_buf_t *pB, nn_netdev_t *pDev);
    struct nn_proto *pNext;
#if NN_CFG_STATS
    uint32_t rxFrames;
#endif
} nn_proto_t;

/** Initialise the stack and create the net task. Call once, before rtos_start on
    nornOS (devices may be registered before or after). */
nn_err_t nn_init(void);

/** Hold / release the stack lock. Application level code that reads stack state uses
    these; the socket API takes the lock itself. */
void nn_lock(void);
void nn_unlock(void);

/** Register a device: it is opened and marked up. */
nn_err_t nn_netdevRegister(nn_netdev_t *pDev);
nn_netdev_t *nn_netdevFind(const char *name);
nn_netdev_t *nn_netdevFirst(void);

/** Hand a frame to the device: takes the buffer. pData must point at the link header. */
nn_err_t nn_netdevTransmit(nn_netdev_t *pDev, nn_buf_t *pB);

/** Register a protocol handler for an Ethernet type. */
nn_err_t nn_protoRegister(nn_proto_t *pProto);
nn_proto_t *nn_protoFind(uint16_t type);

/** Driver entry points: queue a received frame for the net task. Takes the buffer: a
    full queue frees it and counts a drop. pData must point at the link header. */
void nn_net_rx(nn_netdev_t *pDev, nn_buf_t *pB);
void nn_net_rxFromIsr(nn_netdev_t *pDev, nn_buf_t *pB);

/** Wake the net task so it re-evaluates its timers (called by nn_timerStart). */
void nn_net_kick(void);

/** Process one received frame synchronously, with the lock held by the caller. This is
    what the net task does per buffer; tests and fuzzers call it directly. Takes the
    buffer. */
void nn_net_input(nn_buf_t *pB);

/** Number of frames the net task has processed; for tests. */
uint32_t nn_net_rxCount(void);

#endif  /* NN_NET_INCLUDED */
