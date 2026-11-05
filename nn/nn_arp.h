#ifndef NN_ARP_INCLUDED
#define NN_ARP_INCLUDED
/**
 * @file nn_arp.h
 * ARP for IPv4 over Ethernet: a small table, requests with retries, one packet parked per
 * unresolved address (a newer one replaces it), replies to requests for our addresses.
 */

#include "nn_types.h"
#include "nn_cfg.h"
#include "nn_buf.h"
#include "nn_netdev.h"

typedef struct nn_arpStats
{
    uint32_t rxRequests, rxReplies, rxBad, txRequests, txReplies;
    uint32_t resolved, timeouts, pendingReplaced, pendingSent;
} nn_arpStats_t;

void nn_arp_init(void);

/** Handler for Ethernet type 0x0806. Takes the buffer. */
void nn_arp_input(nn_buf_t *pB, nn_netdev_t *pDev);

/** Send an IP packet (link header not yet added) to \a nextHop on \a pDev: at once if
    the address is known, else parked while a request goes out. Takes the buffer. */
nn_err_t nn_arp_output(nn_netdev_t *pDev, nn_ip4_t nextHop, nn_buf_t *pB);

/** Look up a resolved address. */
bool nn_arpLookup(nn_ip4_t ip, uint8_t mac[NN_ETH_ALEN]);

/** Send a request for \a ip (also starts an entry so the reply is kept). */
nn_err_t nn_arpRequest(nn_netdev_t *pDev, nn_ip4_t ip);

/** Forget every entry of \a pDev (NULL: all), parked frames included: the link went
    down or came up on another network. From a task. */
void nn_arpFlush(nn_netdev_t *pDev);

void nn_arpGetStats(nn_arpStats_t *pStats);

#endif  /* NN_ARP_INCLUDED */
