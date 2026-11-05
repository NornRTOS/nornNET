#ifndef NN_IP_INCLUDED
#define NN_IP_INCLUDED
/**
 * @file nn_ip.h
 * IPv4 without options and without fragments. Interfaces give a device an address; the
 * route of an outgoing packet is the interface whose subnet contains the destination,
 * otherwise the first interface with a gateway. Packets for one of our own addresses go
 * through the loopback device when one is registered.
 */

#include "nn_types.h"
#include "nn_cfg.h"
#include "nn_buf.h"
#include "nn_netdev.h"

#define NN_IP_HDR_LEN       20u
#define NN_IP_PROTO_ICMP    1u
#define NN_IP_PROTO_TCP     6u
#define NN_IP_PROTO_UDP     17u
#define NN_IP_DEFAULT_TTL   64u

#define NN_IP4_INIT(a, b, c, d)  { { (a), (b), (c), (d) } }

static inline nn_ip4_t nn_ip4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    nn_ip4_t ip;
    ip.b[0] = a; ip.b[1] = b; ip.b[2] = c; ip.b[3] = d;
    return ip;
}

static inline bool nn_ip4Equal(nn_ip4_t a, nn_ip4_t b)
{
    return a.b[0] == b.b[0] && a.b[1] == b.b[1] && a.b[2] == b.b[2] && a.b[3] == b.b[3];
}

static inline bool nn_ip4IsAny(nn_ip4_t a)
{
    return (a.b[0] | a.b[1] | a.b[2] | a.b[3]) == 0;
}

static inline bool nn_ip4IsLimitedBroadcast(nn_ip4_t a)
{
    return (a.b[0] & a.b[1] & a.b[2] & a.b[3]) == 0xFFu;
}

static inline bool nn_ip4IsMulticast(nn_ip4_t a)
{
    return (a.b[0] & 0xF0u) == 0xE0u;
}

static inline bool nn_ip4IsLoopback(nn_ip4_t a)
{
    return a.b[0] == 127u;
}

/** True if \a a and \a b are in the same subnet under \a mask. */
static inline bool nn_ip4SameNet(nn_ip4_t a, nn_ip4_t b, nn_ip4_t mask)
{
    return ((a.b[0] ^ b.b[0]) & mask.b[0]) == 0 && ((a.b[1] ^ b.b[1]) & mask.b[1]) == 0
        && ((a.b[2] ^ b.b[2]) & mask.b[2]) == 0 && ((a.b[3] ^ b.b[3]) & mask.b[3]) == 0;
}

/** Dotted decimal into \a s (at least 16 bytes); returns \a s. */
char *nn_ip4ToStr(char *s, nn_ip4_t a);

/** Parse dotted decimal; false on a malformed string. */
bool nn_ip4Parse(const char *s, nn_ip4_t *pA);

/** An address on a device. */
typedef struct nn_iface
{
    nn_netdev_t *pDev;
    nn_ip4_t addr;              /**< 0.0.0.0 while unconfigured (DHCP pending). */
    nn_ip4_t mask;
    nn_ip4_t gw;                /**< 0.0.0.0: no gateway through this interface. */
    struct nn_iface *pNext;     /**< Next interface on the same device. */
    struct nn_iface *pNextAll;  /**< Next interface overall. */
    struct nn_dhcp *pDhcp;      /**< The DHCP client on it, if started; told of link changes. */
} nn_iface_t;

/** A protocol above IP, keyed by protocol number. */
typedef struct nn_ipProto
{
    uint8_t proto;
    const char *name;
    /** Takes the buffer: pData points past the IP header, len is the IP payload, aux
        holds the IP header length so nn_bufPush(pB, pB->aux) gets the header back. */
    void (*input)(nn_buf_t *pB, nn_iface_t *pIf, nn_ip4_t src, nn_ip4_t dst);
    struct nn_ipProto *pNext;
#if NN_CFG_STATS
    uint32_t rxPackets;
#endif
} nn_ipProto_t;

typedef struct nn_ipStats
{
    uint32_t rx, rxDelivered, rxBadHeader, rxBadChecksum, rxFragments, rxNotForUs, rxNoProto;
    uint32_t tx, txNoRoute, txNoHeadroom, txErrors;
} nn_ipStats_t;

void nn_ip_init(void);

/** Add an address to a device. With the stack lock, or before rtos_start. */
nn_err_t nn_ifaceAdd(nn_netdev_t *pDev, nn_iface_t *pIf, nn_ip4_t addr, nn_ip4_t mask, nn_ip4_t gw);

/** Change the address of an interface (DHCP). With the stack lock. */
void nn_ifaceSetAddr(nn_iface_t *pIf, nn_ip4_t addr, nn_ip4_t mask, nn_ip4_t gw);

nn_iface_t *nn_ifaceFirst(void);

/** The interface with exactly this address, or NULL. */
nn_iface_t *nn_ifaceByAddr(nn_ip4_t addr);

/** The interface on \a pDev whose subnet contains \a addr, else the first on \a pDev. */
nn_iface_t *nn_ifaceOnDevFor(nn_netdev_t *pDev, nn_ip4_t addr);

/** True if \a addr is one of ours. */
bool nn_ipIsLocal(nn_ip4_t addr);

/** Route \a dst: the interface to send through and the next hop (dst itself on link,
    the gateway otherwise, or a broadcast address). NULL if unroutable. */
nn_iface_t *nn_ipRoute(nn_ip4_t dst, nn_ip4_t *pNextHop);

nn_err_t nn_ipProtoRegister(nn_ipProto_t *pProto);

/** Handler for Ethernet type 0x0800: validate, deliver. Takes the buffer. */
void nn_ip_input(nn_buf_t *pB, nn_netdev_t *pDev);

/** Send: pData points at the payload. Prepends the IP header (needs NN_IP_HDR_LEN plus
    link headroom), routes and hands the packet to ARP or the device. \a src 0.0.0.0
    picks the outgoing interface's address. Takes the buffer. */
nn_err_t nn_ip_output(nn_buf_t *pB, nn_ip4_t src, nn_ip4_t dst, uint8_t proto, uint8_t ttl);

/** As nn_ip_output, but through \a pIf instead of the routing table (NULL: route). DHCP
    uses it to speak from an interface that has no address yet. */
nn_err_t nn_ip_outputVia(nn_buf_t *pB, nn_iface_t *pIf, nn_ip4_t src, nn_ip4_t dst, uint8_t proto, uint8_t ttl);

void nn_ipGetStats(nn_ipStats_t *pStats);

#endif  /* NN_IP_INCLUDED */
