/**
 * @file nn_dns.c
 * Stub resolver. Requests live in a fixed table; each has its own timer for retries and
 * the deadline. The first A record of an answer wins (CNAME chains are followed by the
 * server, recursion desired). Names are limited to NN_CFG_DNS_MAX_NAME characters.
 */

#include <string.h>

#include "nn_dns.h"
#include "nn_udp.h"
#include "nn_net.h"
#include "nn_timer.h"
#include "nn_os.h"

#define DNS_PORT        53u
#define HDR_LEN         12u
#define TYPE_A          1u
#define CLASS_IN        1u
#define MAX_ANSWER      512u

struct nn_dnsReq
{
    bool active;
    char name[NN_CFG_DNS_MAX_NAME + 1];
    uint16_t id;
    nn_ms_t deadline;
    nn_timer_t timer;
    nn_dnsResultFunc_t fn;
    void *arg;
    /* Blocking form: */
    bool waiting;
    nn_os_taskId_t waiter;
    nn_err_t result;
    nn_ip4_t addr;
};

typedef struct cacheEntry
{
    char name[NN_CFG_DNS_MAX_NAME + 1];
    nn_ip4_t addr;
    nn_ms_t expires;
} cacheEntry_t;

static nn_dnsReq_t _reqs[NN_CFG_DNS_QUERIES];
static cacheEntry_t _cache[NN_CFG_DNS_CACHE];
static nn_udp_t _sock;
static bool _sockOpen;
static nn_ip4_t _server;
static uint16_t _serverPort;
static uint16_t _nextId;
static nn_dnsStats_t _stats;

static bool nameEqual(const char *a, const char *b)
{
    for(;; ++a, ++b)
    {
        const char ca = (*a >= 'A' && *a <= 'Z') ? (char)(*a + 32) : *a;
        const char cb = (*b >= 'A' && *b <= 'Z') ? (char)(*b + 32) : *b;
        if(ca != cb)
            return false;
        if(ca == '\0')
            return true;
    }
}

static cacheEntry_t *cacheFind(const char *name)
{
    unsigned i;
    const nn_ms_t now = nn_os_now();
    for(i=0; i<NN_CFG_DNS_CACHE; ++i)
        if(_cache[i].name[0] != '\0'  &&  !nn_msBefore(_cache[i].expires, now)  &&  nameEqual(_cache[i].name, name))
            return &_cache[i];
    return NULL;
}

static void cachePut(const char *name, nn_ip4_t addr, uint32_t ttlS)
{
    cacheEntry_t *pE = &_cache[0];
    unsigned i;
    if(ttlS == 0)
        return;
    if(ttlS > 86400ul)
        ttlS = 86400ul;
    for(i=0; i<NN_CFG_DNS_CACHE; ++i)
    {
        if(_cache[i].name[0] == '\0')
        {
            pE = &_cache[i];
            break;
        }
        if(nn_msBefore(_cache[i].expires, pE->expires))
            pE = &_cache[i];
    }
    strncpy(pE->name, name, NN_CFG_DNS_MAX_NAME);
    pE->name[NN_CFG_DNS_MAX_NAME] = '\0';
    pE->addr = addr;
    pE->expires = nn_os_now() + (nn_ms_t)(ttlS * 1000ul);
}

static void finish(nn_dnsReq_t *pReq, nn_err_t rc, nn_ip4_t addr)
{
    nn_timerStop(&pReq->timer);
    pReq->active = false;
    pReq->result = rc;
    pReq->addr = addr;
    if(pReq->fn != NULL)
        pReq->fn(pReq, rc, addr, pReq->arg);
    if(pReq->waiting)
    {
        pReq->waiting = false;
        nn_os_notify(pReq->waiter);
    }
}

/** Encode the name as labels; returns bytes written or 0 on a bad name. */
static uint16_t encodeName(uint8_t *p, const char *name)
{
    uint8_t *pLen = p++;
    uint16_t n = 1;
    *pLen = 0;
    for(;; ++name)
    {
        if(*name == '.'  ||  *name == '\0')
        {
            if(*pLen == 0  ||  *pLen > 63)
                return 0;
            if(*name == '\0')
                break;
            pLen = p++;
            *pLen = 0;
            ++ n;
        }
        else
        {
            *p++ = (uint8_t)*name;
            ++ *pLen;
            ++ n;
        }
    }
    *p = 0;
    return (uint16_t)(n + 1);
}

static nn_err_t sendQuery(nn_dnsReq_t *pReq)
{
    nn_buf_t *pB;
    uint8_t *p;
    uint16_t n;

    if(nn_ip4IsAny(_server))
        return NN_ERR_NODEV;
    pB = nn_bufAlloc(NN_CFG_TX_HEADROOM);
    if(pB == NULL)
        return NN_ERR_NOMEM;
    p = nn_bufPut(pB, (uint16_t)(HDR_LEN + strlen(pReq->name) + 2 + 4));
    memset(p, 0, HDR_LEN);
    nn_put16(p, pReq->id);
    nn_put16(p + 2, 0x0100u);               /* RD */
    nn_put16(p + 4, 1);                     /* one question */
    n = encodeName(p + HDR_LEN, pReq->name);
    if(n == 0)
    {
        nn_bufFree(pB);
        return NN_ERR_INVAL;
    }
    nn_put16(p + HDR_LEN + n, TYPE_A);
    nn_put16(p + HDR_LEN + n + 2, CLASS_IN);
    ++ _stats.queries;
    return nn_udp_sendBuf(&_sock, pB, _server, _serverPort);
}

static void timerCb(nn_timer_t *pT, void *arg)
{
    nn_dnsReq_t * const pReq = arg;
    nn_ms_t now = nn_os_now();
    (void)pT;

    if(!nn_msBefore(now, pReq->deadline))
    {
        ++ _stats.timeouts;
        finish(pReq, NN_ERR_TIMEOUT, nn_ip4(0, 0, 0, 0));
        return;
    }
    ++ _stats.retries;
    sendQuery(pReq);
    nn_timerStart(&pReq->timer, NN_CFG_DNS_RETRY_MS, 0);
}

/** Skip a (possibly compressed) name; returns the new offset or 0 on error. */
static uint16_t skipName(const uint8_t *p, uint16_t len, uint16_t off)
{
    uint8_t hops = 0;
    while(off < len)
    {
        const uint8_t l = p[off];
        if(l == 0)
            return (uint16_t)(off + 1);
        if((l & 0xC0u) == 0xC0u)
            return (uint16_t)(off + 2 <= len ? off + 2 : 0);
        if((l & 0xC0u) != 0  ||  ++hops > 64)
            return 0;
        off = (uint16_t)(off + 1 + l);
    }
    return 0;
}

static void onReadable(nn_udp_t *pSock, void *arg)
{
    nn_buf_t *pB;
    (void)arg;

    while((pB = nn_udp_dequeue(pSock)) != NULL)
    {
        const uint8_t *p = pB->pData;
        const uint16_t len = pB->len;
        uint16_t id, flags, qd, an, off, i;
        nn_dnsReq_t *pReq = NULL;

        if(len < HDR_LEN)
            goto bad;
        id = nn_get16(p);
        flags = nn_get16(p + 2);
        qd = nn_get16(p + 4);
        an = nn_get16(p + 6);
        for(i=0; i<NN_CFG_DNS_QUERIES; ++i)
            if(_reqs[i].active  &&  _reqs[i].id == id)
                pReq = &_reqs[i];
        if(pReq == NULL  ||  !(flags & 0x8000u))
            goto bad;                       /* not ours or not a response */

        if((flags & 0x000Fu) != 0)          /* RCODE: NXDOMAIN etc. */
        {
            ++ _stats.negative;
            finish(pReq, NN_ERR_NODEV, nn_ip4(0, 0, 0, 0));
            nn_bufFree(pB);
            continue;
        }
        off = HDR_LEN;
        for(i=0; i<qd; ++i)
        {
            off = skipName(p, len, off);
            if(off == 0  ||  off + 4 > len)
                goto bad;
            off = (uint16_t)(off + 4);
        }
        for(i=0; i<an; ++i)
        {
            uint16_t type, cls, rdlen;
            uint32_t ttl;
            off = skipName(p, len, off);
            if(off == 0  ||  off + 10 > len)
                goto bad;
            type = nn_get16(p + off);
            cls = nn_get16(p + off + 2);
            ttl = nn_get32(p + off + 4);
            rdlen = nn_get16(p + off + 8);
            off = (uint16_t)(off + 10);
            if(off + rdlen > len)
                goto bad;
            if(type == TYPE_A  &&  cls == CLASS_IN  &&  rdlen == 4)
            {
                nn_ip4_t a;
                memcpy(a.b, p + off, 4);
                ++ _stats.answers;
                cachePut(pReq->name, a, ttl);
                finish(pReq, NN_OK, a);
                pReq = NULL;
                break;
            }
            off = (uint16_t)(off + rdlen);
        }
        if(pReq != NULL)
        {
            ++ _stats.negative;             /* a response without an A record */
            finish(pReq, NN_ERR_NODEV, nn_ip4(0, 0, 0, 0));
        }
        nn_bufFree(pB);
        continue;
bad:
        ++ _stats.bad;
        nn_bufFree(pB);
    }
}

void nn_dns_init(void)
{
    memset(_reqs, 0, sizeof(_reqs));
    memset(_cache, 0, sizeof(_cache));
    memset(&_stats, 0, sizeof(_stats));
    _server = nn_ip4(0, 0, 0, 0);
    _serverPort = DNS_PORT;
    _nextId = 0x4E01u;
    _sockOpen = false;
}

static nn_err_t ensureSocket(void)
{
    nn_err_t rc;
    if(_sockOpen)
        return NN_OK;
    rc = nn_udpOpen(&_sock);
    if(rc == NN_OK)
        rc = nn_udp_bind(&_sock, nn_ip4(0, 0, 0, 0), 0);
    if(rc == NN_OK)
    {
        _sock.onReadable = onReadable;
        _sock.cbArg = NULL;
        _sockOpen = true;
    }
    return rc;
}

void nn_dnsSetServer(nn_ip4_t server)
{
    _server = server;
}

nn_ip4_t nn_dnsGetServer(void)
{
    return _server;
}

void nn_dnsSetServerPort(uint16_t port)
{
    _serverPort = port;
}

nn_err_t nn_dnsQuery(nn_dnsReq_t **ppReq, const char *name, nn_ms_t timeout, nn_dnsResultFunc_t fn, void *arg)
{
    nn_dnsReq_t *pReq = NULL;
    const cacheEntry_t *pC;
    nn_err_t rc;
    unsigned i;

    if(name == NULL  ||  strlen(name) > NN_CFG_DNS_MAX_NAME  ||  name[0] == '\0')
        return NN_ERR_INVAL;
    pC = cacheFind(name);
    if(pC != NULL)
    {
        ++ _stats.cacheHits;
        if(fn != NULL)
            fn(NULL, NN_OK, pC->addr, arg);
        if(ppReq != NULL)
            *ppReq = NULL;
        return NN_OK;
    }
    for(i=0; i<NN_CFG_DNS_QUERIES; ++i)
        if(!_reqs[i].active)
            pReq = &_reqs[i];
    if(pReq == NULL)
        return NN_ERR_FULL;
    rc = ensureSocket();
    if(rc != NN_OK)
        return rc;

    memset(pReq, 0, sizeof(*pReq));
    strncpy(pReq->name, name, NN_CFG_DNS_MAX_NAME);
    pReq->id = _nextId++;
    pReq->fn = fn;
    pReq->arg = arg;
    pReq->deadline = nn_os_now() + timeout;
    pReq->active = true;
    nn_timerSetup(&pReq->timer, timerCb, pReq);
    rc = sendQuery(pReq);
    if(rc != NN_OK)
    {
        pReq->active = false;
        return rc;
    }
    nn_timerStart(&pReq->timer, NN_CFG_DNS_RETRY_MS, 0);
    if(ppReq != NULL)
        *ppReq = pReq;
    return NN_OK;
}

typedef struct { volatile nn_err_t result; nn_ip4_t addr; } blocking_t;

static void blockingCb(nn_dnsReq_t *pReq, nn_err_t rc, nn_ip4_t addr, void *arg)
{
    blocking_t * const pOut = arg;         /* pReq is NULL on a cache hit */
    (void)pReq;
    pOut->addr = addr;
    pOut->result = rc;
}

nn_err_t nn_dnsResolve(const char *name, nn_ip4_t *pAddr, nn_ms_t timeout)
{
    nn_dnsReq_t *pReq = NULL;
    blocking_t out;
    nn_err_t rc;

    if(nn_ip4Parse(name, pAddr))
        return NN_OK;
    out.result = NN_ERR_PENDING;
    nn_lock();
    rc = nn_dnsQuery(&pReq, name, timeout, blockingCb, &out);
    if(rc == NN_OK  &&  pReq != NULL)
    {
        pReq->waiter = nn_os_self();
        pReq->waiting = true;
    }
    nn_unlock();
    if(rc != NN_OK)
        return rc;
    /* The callback stores the result before the notification; the request slot may be
       reused by someone else afterwards, so only our own copy is trusted. */
    while(out.result == NN_ERR_PENDING)
        (void)nn_os_notifyWait(timeout + NN_CFG_DNS_RETRY_MS);
    if(out.result == NN_OK)
        *pAddr = out.addr;
    return out.result;
}

void nn_dnsGetStats(nn_dnsStats_t *pStats)
{
    *pStats = _stats;
}
