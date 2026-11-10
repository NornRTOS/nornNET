#ifndef NN_CFG_INCLUDED
#define NN_CFG_INCLUDED
/**
 * @file nn_cfg.h
 * Compile time configuration of nornNET with its defaults. An application overrides any
 * NN_CFG_* in its own nn_config.h; the build defines NN_CONFIG_H when that file exists
 * next to the application (nornnet.mk does it for nornOS applications).
 *
 * The defaults are the "full" profile for 32 bit targets with a few hundred kilobytes
 * of RAM (ESP32, host). A smaller profile is a matter of lowering the numbers.
 */

#ifdef NN_CONFIG_H
# include "nn_config.h"
#endif

/** Number of packet buffers in the pool. All frames, received and transmitted, come
    from here. */
#ifndef NN_CFG_NUM_BUFS
# define NN_CFG_NUM_BUFS        16u
#endif

/** Payload bytes per buffer: must hold a full Ethernet frame plus NN_CFG_RX_OFFSET. */
#ifndef NN_CFG_BUF_DATA
# define NN_CFG_BUF_DATA        1536u
#endif

/** Where a driver writes a received frame inside the buffer. 2 puts the IP header,
    which follows the 14 byte Ethernet header, on a 4 byte boundary. */
#ifndef NN_CFG_RX_OFFSET
# define NN_CFG_RX_OFFSET       2u
#endif

/** Headroom reserved in a buffer allocated for transmission, so the layers below the
    application can prepend their headers without moving the payload. 2 + 14 (eth) + 20
    (IP) + 20 (TCP); UDP needs less and leaves a gap. */
#ifndef NN_CFG_TX_HEADROOM
# define NN_CFG_TX_HEADROOM     56u
#endif

/** Depth of the queue between the drivers and the net task, in buffers. */
#ifndef NN_CFG_RX_QUEUE
# define NN_CFG_RX_QUEUE        16u
#endif

/** Priority of the net task. It should be above every task that uses the stack: the
    stack lock then costs nothing but a priority raise (nornOS ICPP). */
#ifndef NN_CFG_TASK_PRIO
# error NN_CFG_TASK_PRIO must be defined in nn_config.h
#endif

/** Stack size of the net task in bytes. */
#ifndef NN_CFG_TASK_STACK
# define NN_CFG_TASK_STACK      3072u
#endif

/** Ceiling of the stack lock: the highest priority of any task calling nornNET. */
#ifndef NN_CFG_LOCK_CEILING
# define NN_CFG_LOCK_CEILING    NN_CFG_TASK_PRIO
#endif

/** ARP table size, how long a resolved entry lives, and how a request is retried. */
#ifndef NN_CFG_ARP_ENTRIES
# define NN_CFG_ARP_ENTRIES     8u
#endif
#ifndef NN_CFG_ARP_TIMEOUT_MS
# define NN_CFG_ARP_TIMEOUT_MS  1200000ul   /* 20 minutes */
#endif
#ifndef NN_CFG_ARP_RETRY_MS
# define NN_CFG_ARP_RETRY_MS    1000ul
#endif
#ifndef NN_CFG_ARP_RETRIES
# define NN_CFG_ARP_RETRIES     3u
#endif

/** UDP: datagrams queued per socket before the oldest is dropped, and the first
    ephemeral port. */
#ifndef NN_CFG_UDP_RXQ
# define NN_CFG_UDP_RXQ         4u
#endif
#ifndef NN_CFG_UDP_EPHEMERAL
# define NN_CFG_UDP_EPHEMERAL   49152u
#endif

/** DNS: outstanding queries, cache entries, retry interval. */
#ifndef NN_CFG_DNS_QUERIES
# define NN_CFG_DNS_QUERIES     2u
#endif
#ifndef NN_CFG_DNS_CACHE
# define NN_CFG_DNS_CACHE       4u
#endif
#ifndef NN_CFG_DNS_RETRY_MS
# define NN_CFG_DNS_RETRY_MS    2000ul
#endif
#ifndef NN_CFG_DNS_MAX_NAME
# define NN_CFG_DNS_MAX_NAME    63u
#endif

/** TCP. The MSS we advertise and the largest we send (1460 fits an Ethernet frame);
    the retransmission timer bounds (RFC 6298 with a LAN friendly floor); how many
    retransmissions before a connection is dropped and how many SYNs before a connect
    fails; the delayed ACK delay; the maximum segment lifetime (TIME_WAIT lasts twice
    that); how many closed connections are remembered in TIME_WAIT (a small table, not a
    socket); the first ephemeral port; the initial congestion window in segments. */
#ifndef NN_CFG_TCP_MSS
# define NN_CFG_TCP_MSS         1460u
#endif
#ifndef NN_CFG_TCP_RTO_INIT_MS
# define NN_CFG_TCP_RTO_INIT_MS 1000ul
#endif
#ifndef NN_CFG_TCP_RTO_MIN_MS
# define NN_CFG_TCP_RTO_MIN_MS  200ul
#endif
#ifndef NN_CFG_TCP_RTO_MAX_MS
# define NN_CFG_TCP_RTO_MAX_MS  60000ul
#endif
#ifndef NN_CFG_TCP_MAX_REXMIT
# define NN_CFG_TCP_MAX_REXMIT  8u
#endif
#ifndef NN_CFG_TCP_SYN_RETRIES
# define NN_CFG_TCP_SYN_RETRIES 5u
#endif
#ifndef NN_CFG_TCP_DELACK_MS
# define NN_CFG_TCP_DELACK_MS   40ul
#endif
#ifndef NN_CFG_TCP_MSL_MS
# define NN_CFG_TCP_MSL_MS      30000ul
#endif
#ifndef NN_CFG_TCP_TIMEWAIT
# define NN_CFG_TCP_TIMEWAIT    4u
#endif
#ifndef NN_CFG_TCP_EPHEMERAL
# define NN_CFG_TCP_EPHEMERAL   49152u
#endif
#ifndef NN_CFG_TCP_IW
# define NN_CFG_TCP_IW          3u
#endif

/** DHCP: host name sent to the server (NULL for none). */
#ifndef NN_CFG_DHCP_HOSTNAME
# define NN_CFG_DHCP_HOSTNAME   "nornos"
#endif

/** Keep per device and per protocol counters. */
#ifndef NN_CFG_STATS
# define NN_CFG_STATS           1
#endif

/** Largest hardware address length supported (Ethernet). */
#define NN_CFG_HWADDR_LEN       6u

#endif  /* NN_CFG_INCLUDED */
