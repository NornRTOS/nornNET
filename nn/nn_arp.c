/**
 * @file nn_arp.c
 * ARP table and protocol. A one second timer retries incomplete entries and ages
 * resolved ones. The sender of any valid ARP packet addressed to us is learnt, so the
 * reply to our reply does not need another exchange.
 */

#include <string.h>

#include "nn_arp.h"
#include "nn_ip.h"
#include "nn_eth.h"
#include "nn_net.h"
#include "nn_timer.h"
#include "nn_os.h"

#define ARP_LEN         28u
#define OP_REQUEST      1u
#define OP_REPLY        2u

#define ST_FREE         0u
#define ST_INCOMPLETE   1u
#define ST_RESOLVED     2u

typedef struct entry
{
    nn_ip4_t ip;
    uint8_t mac[NN_ETH_ALEN];
    uint8_t state;
    uint8_t retries;
    nn_ms_t expires;
    nn_netdev_t *pDev;
    nn_buf_t *pPending;
} entry_t;

static entry_t _table[NN_CFG_ARP_ENTRIES];
static nn_timer_t _timer;
static nn_arpStats_t _stats;

static entry_t *find(nn_ip4_t ip)
{
    unsigned i;
    for(i=0; i<NN_CFG_ARP_ENTRIES; ++i)
        if(_table[i].state != ST_FREE  &&  nn_ip4Equal(_table[i].ip, ip))
            return &_table[i];
    return NULL;
}

static void release(entry_t *pE)
{
    if(pE->pPending != NULL)
    {
        nn_bufFree(pE->pPending);
        pE->pPending = NULL;
    }
    pE->state = ST_FREE;
}

/** A free entry, else the one expiring soonest. */
static entry_t *allocate(void)
{
    entry_t *pVictim = &_table[0];
    unsigned i;

    for(i=0; i<NN_CFG_ARP_ENTRIES; ++i)
    {
        if(_table[i].state == ST_FREE)
            return &_table[i];
        if(nn_msBefore(_table[i].expires, pVictim->expires))
            pVictim = &_table[i];
    }
    release(pVictim);
    return pVictim;
}

static nn_err_t sendPacket(nn_netdev_t *pDev, uint16_t op, const uint8_t *dstMac,
                           nn_ip4_t senderIp, const uint8_t *targetMac, nn_ip4_t targetIp)
{
    nn_buf_t *pB = nn_bufAlloc(NN_CFG_TX_HEADROOM);
    uint8_t *p;

    if(pB == NULL)
        return NN_ERR_NOMEM;
    p = nn_bufPut(pB, ARP_LEN);
    nn_put16(p, 1);                     /* Ethernet */
    nn_put16(p + 2, NN_ETH_TYPE_IP);
    p[4] = NN_ETH_ALEN;
    p[5] = 4;
    nn_put16(p + 6, op);
    nn_macCopy(p + 8, pDev->hwaddr);
    memcpy(p + 14, senderIp.b, 4);
    if(targetMac != NULL)
        nn_macCopy(p + 18, targetMac);
    else
        memset(p + 18, 0, NN_ETH_ALEN);
    memcpy(p + 24, targetIp.b, 4);
    return nn_eth_output(pDev, pB, dstMac, NN_ETH_TYPE_ARP);
}

static nn_err_t sendRequest(entry_t *pE)
{
    const nn_iface_t * const pIf = nn_ifaceOnDevFor(pE->pDev, pE->ip);
    const nn_ip4_t src = pIf != NULL ? pIf->addr : nn_ip4(0, 0, 0, 0);
    ++ _stats.txRequests;
    return sendPacket(pE->pDev, OP_REQUEST, nn_eth_broadcast, src, NULL, pE->ip);
}

static void resolved(entry_t *pE, const uint8_t *mac)
{
    nn_macCopy(pE->mac, mac);
    if(pE->state != ST_RESOLVED)
        ++ _stats.resolved;
    pE->state = ST_RESOLVED;
    pE->expires = nn_os_now() + NN_CFG_ARP_TIMEOUT_MS;
    if(pE->pPending != NULL)
    {
        nn_buf_t * const pB = pE->pPending;
        pE->pPending = NULL;
        ++ _stats.pendingSent;
        nn_eth_output(pE->pDev, pB, pE->mac, NN_ETH_TYPE_IP);
    }
}

static void timerCb(nn_timer_t *pT, void *arg)
{
    const nn_ms_t now = nn_os_now();
    unsigned i;
    (void)pT; (void)arg;

    for(i=0; i<NN_CFG_ARP_ENTRIES; ++i)
    {
        entry_t * const pE = &_table[i];
        if(pE->state == ST_FREE  ||  nn_msBefore(now, pE->expires))
            continue;
        if(pE->state == ST_INCOMPLETE  &&  pE->retries < NN_CFG_ARP_RETRIES)
        {
            ++ pE->retries;
            pE->expires = now + NN_CFG_ARP_RETRY_MS;
            sendRequest(pE);
        }
        else
        {
            if(pE->state == ST_INCOMPLETE)
                ++ _stats.timeouts;
            release(pE);
        }
    }
}

void nn_arp_init(void)
{
    memset(_table, 0, sizeof(_table));
    memset(&_stats, 0, sizeof(_stats));
    nn_timerSetup(&_timer, timerCb, NULL);
    nn_timerStart(&_timer, NN_CFG_ARP_RETRY_MS, NN_CFG_ARP_RETRY_MS);
}

void nn_arp_input(nn_buf_t *pB, nn_netdev_t *pDev)
{
    const uint8_t *p = pB->pData;
    uint16_t op;
    nn_ip4_t senderIp, targetIp;
    entry_t *pE;
    bool forUs;

    if(pB->len < ARP_LEN  ||  nn_get16(p) != 1  ||  nn_get16(p + 2) != NN_ETH_TYPE_IP
       ||  p[4] != NN_ETH_ALEN  ||  p[5] != 4)
    {
        ++ _stats.rxBad;
        nn_bufFree(pB);
        return;
    }
    op = nn_get16(p + 6);
    memcpy(senderIp.b, p + 14, 4);
    memcpy(targetIp.b, p + 24, 4);
    forUs = nn_ipIsLocal(targetIp)  &&  nn_ifaceByAddr(targetIp)->pDev == pDev;

    /* Learn or refresh the sender: always if we have an entry, and if it talks to us. */
    pE = find(senderIp);
    if(pE == NULL  &&  forUs  &&  !nn_ip4IsAny(senderIp))
    {
        pE = allocate();
        pE->ip = senderIp;
        pE->pDev = pDev;
        pE->pPending = NULL;
        pE->retries = 0;
        pE->state = ST_INCOMPLETE;
    }
    if(pE != NULL  &&  pE->pDev == pDev)
        resolved(pE, p + 8);

    if(op == OP_REQUEST)
    {
        ++ _stats.rxRequests;
        if(forUs)
        {
            ++ _stats.txReplies;
            sendPacket(pDev, OP_REPLY, p + 8, targetIp, p + 8, senderIp);
        }
    }
    else if(op == OP_REPLY)
        ++ _stats.rxReplies;
    else
        ++ _stats.rxBad;
    nn_bufFree(pB);
}

nn_err_t nn_arp_output(nn_netdev_t *pDev, nn_ip4_t nextHop, nn_buf_t *pB)
{
    entry_t *pE = find(nextHop);

    if(pE != NULL  &&  pE->state == ST_RESOLVED)
        return nn_eth_output(pDev, pB, pE->mac, NN_ETH_TYPE_IP);

    if(pE == NULL)
    {
        pE = allocate();
        pE->ip = nextHop;
        pE->pDev = pDev;
        pE->pPending = NULL;
        pE->state = ST_INCOMPLETE;
        pE->retries = 0;
        pE->expires = nn_os_now() + NN_CFG_ARP_RETRY_MS;
        sendRequest(pE);
    }
    if(pE->pPending != NULL)
    {
        ++ _stats.pendingReplaced;
        nn_bufFree(pE->pPending);
    }
    pE->pPending = pB;
    return NN_OK;
}

bool nn_arpLookup(nn_ip4_t ip, uint8_t mac[NN_ETH_ALEN])
{
    const entry_t * const pE = find(ip);
    if(pE == NULL  ||  pE->state != ST_RESOLVED)
        return false;
    nn_macCopy(mac, pE->mac);
    return true;
}

nn_err_t nn_arpRequest(nn_netdev_t *pDev, nn_ip4_t ip)
{
    entry_t *pE = find(ip);
    if(pE == NULL)
    {
        pE = allocate();
        pE->ip = ip;
        pE->pDev = pDev;
        pE->pPending = NULL;
        pE->state = ST_INCOMPLETE;
        pE->retries = 0;
        pE->expires = nn_os_now() + NN_CFG_ARP_RETRY_MS;
    }
    return sendRequest(pE);
}

void nn_arpFlush(nn_netdev_t *pDev)
{
    unsigned i;
    nn_lock();
    for(i=0; i<NN_CFG_ARP_ENTRIES; ++i)
        if(_table[i].state != ST_FREE  &&  (pDev == NULL  ||  _table[i].pDev == pDev))
            release(&_table[i]);
    nn_unlock();
}

void nn_arpGetStats(nn_arpStats_t *pStats)
{
    *pStats = _stats;
}
