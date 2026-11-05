#ifndef NN_DHCP_INCLUDED
#define NN_DHCP_INCLUDED
/**
 * @file nn_dhcp.h
 * DHCP client (RFC 2131) for one interface: discover, request, bind, renew at T1,
 * rebind at T2, start over on expiry or NAK. The interface's address, mask and gateway
 * are set when bound and cleared when the lease is lost; the DNS server, if offered,
 * becomes the resolver's server.
 */

#include "nn_types.h"
#include "nn_ip.h"
#include "nn_udp.h"
#include "nn_timer.h"

#define NN_DHCP_INIT        0u
#define NN_DHCP_SELECTING   1u  /**< Discover sent, waiting for an offer. */
#define NN_DHCP_REQUESTING  2u  /**< Request sent, waiting for the ack. */
#define NN_DHCP_BOUND       3u
#define NN_DHCP_RENEWING    4u
#define NN_DHCP_REBINDING   5u

typedef struct nn_dhcp nn_dhcp_t;

/** Called in the net task when the client becomes bound (\a bound true, address set)
    or loses its lease (\a bound false, address cleared). */
typedef void (*nn_dhcpChangeFunc_t)(nn_dhcp_t *pD, bool bound, void *arg);

struct nn_dhcp
{
    nn_iface_t *pIf;
    nn_udp_t sock;
    nn_timer_t timer;
    uint8_t state;
    uint8_t retries;
    uint8_t verifying;          /**< Rebinding after nn_dhcpLinkUp: three tries, then over. */
    uint32_t xid;
    nn_ms_t started;            /**< For the "secs" field. */
    nn_ip4_t offered, server, mask, gw, dns;
    uint32_t leaseS, t1S, t2S;
    nn_ms_t boundAt;
    nn_dhcpChangeFunc_t onChange;
    void *cbArg;
    uint32_t discovers, requests, offers, acks, naks;
};

void nn_dhcp_init(void);

/** Start acquiring an address for \a pIf (its address is cleared). \a fn may be NULL.
    From a task. */
nn_err_t nn_dhcpStart(nn_dhcp_t *pD, nn_iface_t *pIf, nn_dhcpChangeFunc_t fn, void *arg);

/** Release the lease (DHCPRELEASE) and clear the address. */
nn_err_t nn_dhcpStop(nn_dhcp_t *pD);

/** The link came back (WiFi reassociated, cable plugged in): a bound client asks the
    server to confirm the lease at once (broadcast REQUEST, three tries 1.5 s apart,
    then it starts over with DISCOVER, which also happens on a NAK from another
    network); a client still looking for an address sends its next DISCOVER now. The
    address stays until the server says otherwise, so connections survive a short
    outage on the same network. The net task calls it for every client on a device
    whose driver reported nn_netdevLinkChanged(up); from a task otherwise. */
nn_err_t nn_dhcpLinkUp(nn_dhcp_t *pD);

uint8_t nn_dhcpState(const nn_dhcp_t *pD);

static inline bool nn_dhcpIsBound(const nn_dhcp_t *pD)
{
    return pD->state >= NN_DHCP_BOUND;
}

#endif  /* NN_DHCP_INCLUDED */
