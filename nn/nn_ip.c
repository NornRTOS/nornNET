/**
 * @file nn_ip.c
 * IPv4 input validation and delivery, output with routing. No options are generated;
 * received options are skipped (IHL honoured). DF is set on everything we send, and a
 * received fragment is dropped and counted: there is no reassembly, by design.
 */

#include <string.h>

#include "nn_ip.h"
#include "nn_net.h"
#include "nn_eth.h"
#include "nn_arp.h"
#include "nn_tcp.h"
#include "nn_cksum.h"
#include "nn_os.h"

static nn_iface_t *_pIfaces;
static nn_ipProto_t *_pProtos;
static uint16_t _nextId;
static nn_ipStats_t _stats;

/* --- Address text ---------------------------------------------------------------------- */

char *nn_ip4ToStr(char *s, nn_ip4_t a)
{
    char *p = s;
    unsigned i;

    for(i=0; i<4; ++i)
    {
        unsigned v = a.b[i];
        if(v >= 100) *p++ = (char)('0' + v / 100);
        if(v >= 10)  *p++ = (char)('0' + v / 10 % 10);
        *p++ = (char)('0' + v % 10);
        if(i < 3) *p++ = '.';
    }
    *p = '\0';
    return s;
}

bool nn_ip4Parse(const char *s, nn_ip4_t *pA)
{
    unsigned i;

    for(i=0; i<4; ++i)
    {
        unsigned v = 0, digits = 0;
        while(*s >= '0'  &&  *s <= '9')
        {
            v = v * 10u + (unsigned)(*s++ - '0');
            if(++digits > 3  ||  v > 255)
                return false;
        }
        if(digits == 0  ||  (i < 3  &&  *s++ != '.'))
            return false;
        pA->b[i] = (uint8_t)v;
    }
    return *s == '\0';
}

/* --- Interfaces ------------------------------------------------------------------------ */

void nn_ip_init(void)
{
    _pIfaces = NULL;
    _pProtos = NULL;
    _nextId = 1;
    memset(&_stats, 0, sizeof(_stats));
}

nn_err_t nn_ifaceAdd(nn_netdev_t *pDev, nn_iface_t *pIf, nn_ip4_t addr, nn_ip4_t mask, nn_ip4_t gw)
{
    nn_iface_t **pp;

    if(pDev == NULL  ||  pIf == NULL)
        return NN_ERR_INVAL;
    pIf->pDev = pDev;
    pIf->pDhcp = NULL;
    pIf->addr = addr;
    pIf->mask = mask;
    pIf->gw = gw;
    pIf->pNext = NULL;
    pIf->pNextAll = NULL;
    for(pp=&pDev->pIfaces; *pp!=NULL; pp=&(*pp)->pNext)
        if(*pp == pIf)
            return NN_ERR_EXIST;
    *pp = pIf;
    for(pp=&_pIfaces; *pp!=NULL; pp=&(*pp)->pNextAll)
        ;
    *pp = pIf;
    return NN_OK;
}

void nn_ifaceSetAddr(nn_iface_t *pIf, nn_ip4_t addr, nn_ip4_t mask, nn_ip4_t gw)
{
    const nn_ip4_t old = pIf->addr;
    pIf->addr = addr;
    pIf->mask = mask;
    pIf->gw = gw;
    if(!nn_ip4IsAny(old)  &&  !nn_ip4Equal(old, addr))
        nn_tcp_addrLost(old);
}

nn_iface_t *nn_ifaceFirst(void)
{
    return _pIfaces;
}

nn_iface_t *nn_ifaceByAddr(nn_ip4_t addr)
{
    nn_iface_t *pIf;
    if(nn_ip4IsAny(addr))
        return NULL;
    for(pIf=_pIfaces; pIf!=NULL; pIf=pIf->pNextAll)
        if(nn_ip4Equal(pIf->addr, addr))
            return pIf;
    return NULL;
}

nn_iface_t *nn_ifaceOnDevFor(nn_netdev_t *pDev, nn_ip4_t addr)
{
    nn_iface_t *pIf;
    for(pIf=pDev->pIfaces; pIf!=NULL; pIf=pIf->pNext)
        if(!nn_ip4IsAny(pIf->addr)  &&  nn_ip4SameNet(pIf->addr, addr, pIf->mask))
            return pIf;
    return pDev->pIfaces;
}

bool nn_ipIsLocal(nn_ip4_t addr)
{
    return nn_ifaceByAddr(addr) != NULL;
}

static nn_iface_t *loopbackIface(void)
{
    nn_iface_t *pIf;
    for(pIf=_pIfaces; pIf!=NULL; pIf=pIf->pNextAll)
        if(pIf->pDev->type == NN_DEV_LOOPBACK)
            return pIf;
    return NULL;
}

/** Directed broadcast of this interface's subnet? */
static bool isDirectedBroadcast(const nn_iface_t *pIf, nn_ip4_t addr)
{
    unsigned i;
    if(nn_ip4IsAny(pIf->addr)  ||  pIf->mask.b[3] == 0xFFu)
        return false;
    for(i=0; i<4; ++i)
        if((addr.b[i] | pIf->mask.b[i]) != 0xFFu  ||  ((addr.b[i] ^ pIf->addr.b[i]) & pIf->mask.b[i]) != 0)
            return false;
    return true;
}

nn_iface_t *nn_ipRoute(nn_ip4_t dst, nn_ip4_t *pNextHop)
{
    nn_iface_t *pIf;

    if(nn_ipIsLocal(dst)  ||  nn_ip4IsLoopback(dst))
    {
        pIf = loopbackIface();
        *pNextHop = dst;
        return pIf;
    }
    if(nn_ip4IsLimitedBroadcast(dst)  ||  nn_ip4IsMulticast(dst))
    {
        for(pIf=_pIfaces; pIf!=NULL; pIf=pIf->pNextAll)
            if(pIf->pDev->type != NN_DEV_LOOPBACK  &&  (pIf->pDev->flags & NN_DEVF_UP))
                break;
        *pNextHop = dst;
        return pIf;
    }
    for(pIf=_pIfaces; pIf!=NULL; pIf=pIf->pNextAll)
    {
        if(pIf->pDev->type != NN_DEV_LOOPBACK  &&  !nn_ip4IsAny(pIf->addr)
           &&  nn_ip4SameNet(pIf->addr, dst, pIf->mask))
        {
            *pNextHop = dst;
            return pIf;
        }
    }
    for(pIf=_pIfaces; pIf!=NULL; pIf=pIf->pNextAll)
    {
        if(!nn_ip4IsAny(pIf->gw)  &&  (pIf->pDev->flags & NN_DEVF_UP))
        {
            *pNextHop = pIf->gw;
            return pIf;
        }
    }
    return NULL;
}

/* --- Protocols ------------------------------------------------------------------------ */

nn_err_t nn_ipProtoRegister(nn_ipProto_t *pProto)
{
    nn_ipProto_t *pP;

    if(pProto == NULL  ||  pProto->input == NULL)
        return NN_ERR_INVAL;
    for(pP=_pProtos; pP!=NULL; pP=pP->pNext)
        if(pP->proto == pProto->proto)
            return NN_ERR_EXIST;
#if NN_CFG_STATS
    pProto->rxPackets = 0;
#endif
    pProto->pNext = _pProtos;
    _pProtos = pProto;
    return NN_OK;
}

/* --- Input ------------------------------------------------------------------------------ */

void nn_ip_input(nn_buf_t *pB, nn_netdev_t *pDev)
{
    const uint8_t *pH = pB->pData;
    uint16_t hlen, totalLen, fragField;
    nn_ip4_t src, dst;
    nn_iface_t *pIf;
    nn_ipProto_t *pP;

    ++ _stats.rx;
    if(pB->len < NN_IP_HDR_LEN  ||  (pH[0] >> 4) != 4u)
        goto badHeader;
    hlen = (uint16_t)((pH[0] & 0x0Fu) * 4u);
    totalLen = nn_get16(pH + 2);
    if(hlen < NN_IP_HDR_LEN  ||  totalLen < hlen  ||  totalLen > pB->len)
        goto badHeader;
    if(nn_cksum(pH, hlen) != 0)
    {
        ++ _stats.rxBadChecksum;
        nn_bufFree(pB);
        return;
    }
    nn_bufTrim(pB, totalLen);          /* drop link layer padding */

    fragField = nn_get16(pH + 6);
    if((fragField & 0x3FFFu) != 0)     /* MF set or offset != 0 */
    {
        ++ _stats.rxFragments;
        nn_bufFree(pB);
        return;
    }
    memcpy(src.b, pH + 12, 4);
    memcpy(dst.b, pH + 16, 4);

    /* For us? Our own address on any interface (loopback delivers those), a limited
       broadcast, or a directed broadcast of an interface on this device. */
    pIf = nn_ifaceByAddr(dst);
    if(pIf == NULL)
    {
        if(nn_ip4IsLimitedBroadcast(dst))
        {
            pIf = pDev->pIfaces;
            pB->flags |= NN_BUF_BCAST;
        }
        else
        {
            nn_iface_t *p;
            for(p=pDev->pIfaces; p!=NULL; p=p->pNext)
                if(isDirectedBroadcast(p, dst))
                    break;
            pIf = p;
            if(pIf != NULL)
                pB->flags |= NN_BUF_BCAST;
        }
        if(pIf == NULL  &&  pH[9] == NN_IP_PROTO_UDP)
        {
            /* An interface without an address yet (DHCP in progress) accepts unicast
               UDP: the server may send OFFER and ACK to the address it is offering. */
            nn_iface_t *p;
            for(p=pDev->pIfaces; p!=NULL; p=p->pNext)
                if(nn_ip4IsAny(p->addr))
                    break;
            pIf = p;
        }
        if(pIf == NULL)
        {
            ++ _stats.rxNotForUs;
            nn_bufFree(pB);
            return;
        }
    }

    for(pP=_pProtos; pP!=NULL; pP=pP->pNext)
        if(pP->proto == pH[9])
            break;
    if(pP == NULL)
    {
        ++ _stats.rxNoProto;
        nn_bufFree(pB);
        return;
    }
    nn_bufPull(pB, hlen);
    pB->aux = hlen;                    /* so a transport can push the IP header back for ICMP errors */
    ++ _stats.rxDelivered;
#if NN_CFG_STATS
    ++ pP->rxPackets;
#endif
    pP->input(pB, pIf, src, dst);
    return;

badHeader:
    ++ _stats.rxBadHeader;
    nn_bufFree(pB);
}

/* --- Output ----------------------------------------------------------------------------- */

nn_err_t nn_ip_output(nn_buf_t *pB, nn_ip4_t src, nn_ip4_t dst, uint8_t proto, uint8_t ttl)
{
    return nn_ip_outputVia(pB, NULL, src, dst, proto, ttl);
}

nn_err_t nn_ip_outputVia(nn_buf_t *pB, nn_iface_t *pIf, nn_ip4_t src, nn_ip4_t dst, uint8_t proto, uint8_t ttl)
{
    nn_ip4_t nextHop;
    uint8_t *pH;
    uint16_t totalLen;

    if(pIf == NULL)
        pIf = nn_ipRoute(dst, &nextHop);
    else if(nn_ip4IsLimitedBroadcast(dst)  ||  nn_ip4IsMulticast(dst)  ||  nn_ip4IsAny(pIf->addr)
            ||  nn_ip4SameNet(pIf->addr, dst, pIf->mask)  ||  nn_ip4IsAny(pIf->gw))
        nextHop = dst;
    else
        nextHop = pIf->gw;
    if(pIf == NULL)
    {
        ++ _stats.txNoRoute;
        nn_bufFree(pB);
        return NN_ERR_NODEV;
    }
    if(nn_ip4IsAny(src))
        src = pIf->addr;
    totalLen = (uint16_t)(pB->len + NN_IP_HDR_LEN);

    pH = nn_bufPush(pB, NN_IP_HDR_LEN);
    if(pH == NULL)
    {
        ++ _stats.txNoHeadroom;
        nn_bufFree(pB);
        return NN_ERR_NOMEM;
    }
    pH[0] = 0x45;
    pH[1] = 0;
    nn_put16(pH + 2, totalLen);
    nn_put16(pH + 4, _nextId++);
    nn_put16(pH + 6, 0x4000u);         /* DF */
    pH[8] = ttl;
    pH[9] = proto;
    pH[10] = pH[11] = 0;
    memcpy(pH + 12, src.b, 4);
    memcpy(pH + 16, dst.b, 4);
    nn_put16(pH + 10, nn_cksum(pH, NN_IP_HDR_LEN));
    ++ _stats.tx;

    if(pIf->pDev->type == NN_DEV_SLIP)
        return nn_netdevTransmit(pIf->pDev, pB);        /* no link header at all */
    if(pIf->pDev->flags & NN_DEVF_NOARP)
        return nn_eth_output(pIf->pDev, pB, pIf->pDev->hwaddr, NN_ETH_TYPE_IP);
    if(nn_ip4IsLimitedBroadcast(nextHop)  ||  isDirectedBroadcast(pIf, nextHop))
        return nn_eth_output(pIf->pDev, pB, nn_eth_broadcast, NN_ETH_TYPE_IP);
    return nn_arp_output(pIf->pDev, nextHop, pB);
}

void nn_ipGetStats(nn_ipStats_t *pStats)
{
    *pStats = _stats;
}
