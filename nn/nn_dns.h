#ifndef NN_DNS_INCLUDED
#define NN_DNS_INCLUDED
/**
 * @file nn_dns.h
 * Stub resolver: A records from one server over UDP, a few queries in flight, retries,
 * a small positive cache honouring TTL. Blocking and callback forms.
 */

#include "nn_types.h"
#include "nn_cfg.h"
#include "nn_ip.h"

typedef struct nn_dnsReq nn_dnsReq_t;

/** Called in the net task: \a rc NN_OK with \a addr, NN_ERR_TIMEOUT, or NN_ERR_NODEV
    for a negative answer (no such name or no A record). */
typedef void (*nn_dnsResultFunc_t)(nn_dnsReq_t *pReq, nn_err_t rc, nn_ip4_t addr, void *arg);

typedef struct nn_dnsStats
{
    uint32_t queries, retries, answers, negative, timeouts, bad, cacheHits;
} nn_dnsStats_t;

void nn_dns_init(void);

/** The server to ask (DHCP sets it when the lease carries one). */
void nn_dnsSetServer(nn_ip4_t server);
nn_ip4_t nn_dnsGetServer(void);

/** Override the server port (tests use a stub on a high port). */
void nn_dnsSetServerPort(uint16_t port);

/** Resolve \a name; a dotted decimal literal is accepted without a query. Blocks for
    at most \a timeout ms. From a task. */
nn_err_t nn_dnsResolve(const char *name, nn_ip4_t *pAddr, nn_ms_t timeout);

/** Start a query, result by callback. \a pReq is caller owned until the callback.
    With the stack lock or from a callback. */
nn_err_t nn_dnsQuery(nn_dnsReq_t **ppReq, const char *name, nn_ms_t timeout, nn_dnsResultFunc_t fn, void *arg);

void nn_dnsGetStats(nn_dnsStats_t *pStats);

#endif  /* NN_DNS_INCLUDED */
