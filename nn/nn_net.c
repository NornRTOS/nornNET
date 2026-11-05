/**
 * @file nn_net.c
 * Device and protocol registries, the receive queue and the net task loop.
 */

#include <string.h>

#include "nn_net.h"
#include "nn_dhcp.h"
#include "nn_eth.h"
#include "nn_ip.h"
#include "nn_arp.h"
#include "nn_icmp.h"
#include "nn_udp.h"
#include "nn_tcp.h"
#include "nn_dhcp.h"
#include "nn_dns.h"
#include "nn_timer.h"
#include "nn_os.h"

static nn_netdev_t *_pDevs;
static nn_proto_t *_pProtos;
static nn_os_lock_t _lock;
static nn_os_queue_t _rxQueue;
static void *_rxStorage[NN_CFG_RX_QUEUE];
static uint32_t _rxCount;
static bool _running;
static nn_proto_t _protoIp, _protoArp;

/* --- Lock ------------------------------------------------------------------------------ */

void nn_lock(void)
{
    nn_os_lock(&_lock);
}

void nn_unlock(void)
{
    nn_os_unlock(&_lock);
}

/* --- Devices -------------------------------------------------------------------------- */

nn_err_t nn_netdevRegister(nn_netdev_t *pDev)
{
    nn_netdev_t **pp;

    if(pDev == NULL  ||  pDev->pOps == NULL  ||  pDev->pOps->transmit == NULL)
        return NN_ERR_INVAL;
    for(pp=&_pDevs; *pp!=NULL; pp=&(*pp)->pNext)
        if(*pp == pDev)
            return NN_ERR_EXIST;

    pDev->pNext = NULL;
    pDev->pIfaces = NULL;
#if NN_CFG_STATS
    memset(&pDev->stats, 0, sizeof(pDev->stats));
#endif
    if(pDev->pOps->open != NULL)
    {
        const nn_err_t rc = pDev->pOps->open(pDev);
        if(rc != NN_OK)
            return rc;
    }
    pDev->flags |= NN_DEVF_UP;
    *pp = pDev;
    return NN_OK;
}

nn_netdev_t *nn_netdevFind(const char *name)
{
    nn_netdev_t *pD;
    for(pD=_pDevs; pD!=NULL; pD=pD->pNext)
        if(strcmp(pD->name, name) == 0)
            return pD;
    return NULL;
}

nn_netdev_t *nn_netdevFirst(void)
{
    return _pDevs;
}

nn_err_t nn_netdevTransmit(nn_netdev_t *pDev, nn_buf_t *pB)
{
    nn_err_t rc;

    if(!(pDev->flags & NN_DEVF_UP))
    {
        nn_bufFree(pB);
        return NN_ERR_DOWN;
    }
    pB->pDev = pDev;
#if NN_CFG_STATS
    ++ pDev->stats.txFrames;
    pDev->stats.txBytes += pB->len;
#endif
    rc = pDev->pOps->transmit(pDev, pB);
    if(rc != NN_OK)
    {
#if NN_CFG_STATS
        ++ pDev->stats.txErrors;
#endif
        nn_bufFree(pB);
    }
    return rc;
}

/* --- Protocols ------------------------------------------------------------------------ */

nn_err_t nn_protoRegister(nn_proto_t *pProto)
{
    if(pProto == NULL  ||  pProto->input == NULL)
        return NN_ERR_INVAL;
    if(nn_protoFind(pProto->type) != NULL)
        return NN_ERR_EXIST;
#if NN_CFG_STATS
    pProto->rxFrames = 0;
#endif
    pProto->pNext = _pProtos;
    _pProtos = pProto;
    return NN_OK;
}

nn_proto_t *nn_protoFind(uint16_t type)
{
    nn_proto_t *pP;
    for(pP=_pProtos; pP!=NULL; pP=pP->pNext)
        if(pP->type == type)
            return pP;
    return NULL;
}

/* --- Receive path --------------------------------------------------------------------- */

void nn_net_rx(nn_netdev_t *pDev, nn_buf_t *pB)
{
    pB->pDev = pDev;
    if(!nn_os_queuePut(&_rxQueue, pB))
    {
#if NN_CFG_STATS
        ++ pDev->stats.rxDropped;
#endif
        nn_bufFree(pB);
    }
}

void nn_net_rxFromIsr(nn_netdev_t *pDev, nn_buf_t *pB)
{
    pB->pDev = pDev;
    if(!nn_os_queuePutFromIsr(&_rxQueue, pB))
    {
#if NN_CFG_STATS
        ++ pDev->stats.rxDropped;
#endif
        nn_bufFreeFromIsr(pB);
    }
}

/* A link change rides the receive queue as the device pointer with bit 0 set, so the
   net task handles it in order with the frames and under the lock. */
#define LINK_MARK(pDev)     ((void *)((uintptr_t)(pDev) | 1u))
#define IS_LINK_MARK(p)     (((uintptr_t)(p) & 1u) != 0)
#define LINK_DEV(p)         ((nn_netdev_t *)((uintptr_t)(p) & ~(uintptr_t)1u))

void nn_netdevLinkChanged(nn_netdev_t *pDev, bool up)
{
    if(up) pDev->flags |= NN_DEVF_LINK; else pDev->flags &= (uint8_t)~NN_DEVF_LINK;
    if(_running)
        (void)nn_os_queuePut(&_rxQueue, LINK_MARK(pDev));
}

void nn_netdevLinkChangedFromIsr(nn_netdev_t *pDev, bool up)
{
    if(up) pDev->flags |= NN_DEVF_LINK; else pDev->flags &= (uint8_t)~NN_DEVF_LINK;
    if(_running)
        (void)nn_os_queuePutFromIsr(&_rxQueue, LINK_MARK(pDev));
}

/* In the net task with the lock. */
static void linkChanged(nn_netdev_t *pDev)
{
    nn_iface_t *pIf;
    if(pDev->flags & NN_DEVF_LINK)
    {
        for(pIf=pDev->pIfaces; pIf!=NULL; pIf=pIf->pNext)
            if(pIf->pDhcp != NULL)
                (void)nn_dhcpLinkUp(pIf->pDhcp);
    }
    else
        nn_arpFlush(pDev);
}

void nn_net_kick(void)
{
    /* A NULL in the queue is "wake up and look at the timers"; dropping it when the
       queue is full is harmless, the task is about to run anyway. */
    if(_running)
        (void)nn_os_queuePut(&_rxQueue, NULL);
}

void nn_net_input(nn_buf_t *pB)
{
    nn_netdev_t * const pDev = pB->pDev;

    ++ _rxCount;
#if NN_CFG_STATS
    ++ pDev->stats.rxFrames;
    pDev->stats.rxBytes += pB->len;
#endif
    switch(pDev->type)
    {
    case NN_DEV_LOOPBACK:
    case NN_DEV_ETHERNET:
        nn_eth_input(pB, pDev);
        break;
    case NN_DEV_SLIP:
        nn_ip_input(pB, pDev);                          /* pData is the IP header */
        break;
    default:
#if NN_CFG_STATS
        ++ pDev->stats.rxDropped;
#endif
        nn_bufFree(pB);
        break;
    }
}

uint32_t nn_net_rxCount(void)
{
    return _rxCount;
}

/* --- The net task --------------------------------------------------------------------- */

static void netTask(void *arg)
{
    (void)arg;
    _running = true;
    for(;;)
    {
        void *p = NULL;
        nn_ms_t wait;

        nn_lock();
        wait = nn_timer_nextMs();
        nn_unlock();

        if(nn_os_queueGet(&_rxQueue, &p, wait)  &&  p != NULL)
        {
            nn_lock();
            if(IS_LINK_MARK(p))
                linkChanged(LINK_DEV(p));
            else
                nn_net_input((nn_buf_t *)p);
            nn_unlock();
        }
        nn_lock();
        nn_timer_run();
        nn_unlock();
    }
}

nn_err_t nn_init(void)
{
    _pDevs = NULL;
    _pProtos = NULL;
    _rxCount = 0;
    _running = false;
    nn_os_lockInit(&_lock);
    nn_os_queueInit(&_rxQueue, _rxStorage, NN_CFG_RX_QUEUE);
    nn_buf_init();
    nn_timer_init();
    nn_eth_init();
    nn_ip_init();
    nn_arp_init();
    nn_icmp_init();
    nn_udp_init();
    nn_tcp_init();
    nn_dhcp_init();
    nn_dns_init();
    _protoIp.type = NN_ETH_TYPE_IP;
    _protoIp.name = "ip";
    _protoIp.input = nn_ip_input;
    nn_protoRegister(&_protoIp);
    _protoArp.type = NN_ETH_TYPE_ARP;
    _protoArp.name = "arp";
    _protoArp.input = nn_arp_input;
    nn_protoRegister(&_protoArp);
    nn_os_taskCreate(netTask, NULL);
    return NN_OK;
}
