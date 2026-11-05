/**
 * @file nn_udp.c
 * UDP. Input finds the socket by local port, local address and the optional connected
 * peer, queues the buffer and wakes the reader. A datagram for no socket gets an ICMP
 * port unreachable. Output always carries a checksum.
 */

#include <string.h>

#include "nn_udp.h"
#include "nn_net.h"
#include "nn_icmp.h"
#include "nn_cksum.h"

static nn_udp_t *_pSockets;
static uint16_t _nextEphemeral;
static nn_udpStats_t _stats;

static nn_udp_t *findByPort(uint16_t port)
{
    nn_udp_t *pS;
    for(pS=_pSockets; pS!=NULL; pS=pS->pNext)
        if(pS->localPort == port)
            return pS;
    return NULL;
}

/** Best match: port must match; a specific local address beats any; a connected peer
    beats unconnected. */
static nn_udp_t *lookup(nn_ip4_t src, uint16_t srcPort, nn_ip4_t dst, uint16_t dstPort)
{
    nn_udp_t *pS, *pBest = NULL;
    int bestScore = -1;

    for(pS=_pSockets; pS!=NULL; pS=pS->pNext)
    {
        int score = 0;
        if(pS->localPort != dstPort)
            continue;
        if(!nn_ip4IsAny(pS->localAddr))
        {
            if(!nn_ip4Equal(pS->localAddr, dst))
                continue;
            score += 2;
        }
        if(pS->remotePort != 0)
        {
            if(pS->remotePort != srcPort  ||  !nn_ip4Equal(pS->remoteAddr, src))
                continue;
            score += 4;
        }
        if(score > bestScore)
        {
            bestScore = score;
            pBest = pS;
        }
    }
    return pBest;
}

static void input(nn_buf_t *pB, nn_iface_t *pIf, nn_ip4_t src, nn_ip4_t dst)
{
    const uint8_t *pH = pB->pData;
    uint16_t len, srcPort, dstPort, csum;
    nn_udp_t *pS;
    (void)pIf;

    ++ _stats.rx;
    if(pB->len < NN_UDP_HDR_LEN)
        goto bad;
    len = nn_get16(pH + 4);
    if(len < NN_UDP_HDR_LEN  ||  len > pB->len)
        goto bad;
    nn_bufTrim(pB, len);
    csum = nn_get16(pH + 6);
    if(csum != 0)
    {
        uint32_t sum = nn_cksumPseudo(src, dst, NN_IP_PROTO_UDP, len);
        if(nn_cksumFinish(nn_cksumAdd(sum, pH, len)) != 0)
        {
            ++ _stats.rxBadChecksum;
            nn_bufFree(pB);
            return;
        }
    }
    srcPort = nn_get16(pH);
    dstPort = nn_get16(pH + 2);

    pS = lookup(src, srcPort, dst, dstPort);
    if(pS == NULL)
    {
        ++ _stats.rxNoSocket;
        if(!(pB->flags & (NN_BUF_BCAST | NN_BUF_MCAST)))
        {
            nn_bufPush(pB, (uint16_t)pB->aux);          /* back to the IP header */
            nn_icmp_sendError(pB, NN_ICMP_UNREACHABLE, NN_ICMP_UNREACH_PORT);
        }
        nn_bufFree(pB);
        return;
    }

    nn_bufPull(pB, NN_UDP_HDR_LEN);
    pB->aux = nn_get32(src.b);
    pB->pNext = NULL;
    if(pS->rxCount >= pS->rxMax)
    {
        ++ _stats.rxQueueFull;
        ++ pS->rxDropped;
        nn_bufFree(pB);
        return;
    }
    if(pS->pRxTail != NULL)
        pS->pRxTail->pNext = pB;
    else
        pS->pRxHead = pB;
    pS->pRxTail = pB;
    ++ pS->rxCount;
    ++ pS->rxDatagrams;
    if(pS->waiting)
    {
        pS->waiting = false;
        nn_os_notify(pS->waiter);
    }
    if(pS->onReadable != NULL)
        pS->onReadable(pS, pS->cbArg);
    return;

bad:
    ++ _stats.rxBad;
    nn_bufFree(pB);
}

static nn_ipProto_t _proto = { NN_IP_PROTO_UDP, "udp", input, NULL
#if NN_CFG_STATS
    , 0
#endif
};

void nn_udp_init(void)
{
    _pSockets = NULL;
    _nextEphemeral = NN_CFG_UDP_EPHEMERAL;
    memset(&_stats, 0, sizeof(_stats));
    nn_ipProtoRegister(&_proto);
}

/* --- Socket API: every function takes the stack lock itself ----------------------------- */

nn_err_t nn_udpOpen(nn_udp_t *pSock)
{
    if(pSock == NULL)
        return NN_ERR_INVAL;
    memset(pSock, 0, sizeof(*pSock));
    pSock->rxMax = NN_CFG_UDP_RXQ;
    pSock->open = true;
    return NN_OK;
}

static uint16_t ephemeralPort(void)
{
    uint16_t tries;
    for(tries=0; tries<1000; ++tries)
    {
        const uint16_t port = _nextEphemeral++;
        if(_nextEphemeral < NN_CFG_UDP_EPHEMERAL  ||  _nextEphemeral == 0)
            _nextEphemeral = NN_CFG_UDP_EPHEMERAL;
        if(findByPort(port) == NULL)
            return port;
    }
    return 0;
}

nn_err_t nn_udp_bind(nn_udp_t *pSock, nn_ip4_t addr, uint16_t port)
{
    nn_udp_t *pS;

    if(port == 0)
    {
        port = ephemeralPort();
        if(port == 0)
            return NN_ERR_FULL;
    }
    else
    {
        /* The same port may be bound twice only with different specific addresses. */
        for(pS=_pSockets; pS!=NULL; pS=pS->pNext)
            if(pS != pSock  &&  pS->localPort == port
               &&  (nn_ip4IsAny(pS->localAddr)  ||  nn_ip4IsAny(addr)  ||  nn_ip4Equal(pS->localAddr, addr)))
                return NN_ERR_EXIST;
    }
    if(pSock->localPort == 0)
    {
        pSock->pNext = _pSockets;
        _pSockets = pSock;
    }
    pSock->localAddr = addr;
    pSock->localPort = port;
    return NN_OK;
}

nn_err_t nn_udpBind(nn_udp_t *pSock, nn_ip4_t addr, uint16_t port)
{
    nn_err_t rc;
    if(pSock == NULL  ||  !pSock->open)
        return NN_ERR_INVAL;
    nn_lock();
    rc = nn_udp_bind(pSock, addr, port);
    nn_unlock();
    return rc;
}

nn_err_t nn_udpConnect(nn_udp_t *pSock, nn_ip4_t addr, uint16_t port)
{
    nn_err_t rc = NN_OK;
    if(pSock == NULL  ||  !pSock->open)
        return NN_ERR_INVAL;
    nn_lock();
    if(pSock->localPort == 0)
        rc = nn_udp_bind(pSock, nn_ip4(0, 0, 0, 0), 0);
    if(rc == NN_OK)
    {
        pSock->remoteAddr = addr;
        pSock->remotePort = port;
    }
    nn_unlock();
    return rc;
}

nn_err_t nn_udp_sendBuf(nn_udp_t *pSock, nn_buf_t *pB, nn_ip4_t to, uint16_t port)
{
    uint8_t *pH;
    nn_iface_t *pIf;
    nn_ip4_t hop, src;
    uint16_t len;
    uint32_t sum;
    nn_err_t rc;

    if(pSock->localPort == 0)
    {
        rc = nn_udp_bind(pSock, nn_ip4(0, 0, 0, 0), 0);
        if(rc != NN_OK)
        {
            nn_bufFree(pB);
            return rc;
        }
    }
    pIf = pSock->pIf != NULL ? pSock->pIf : nn_ipRoute(to, &hop);
    if(pIf == NULL)
    {
        ++ _stats.txErrors;
        nn_bufFree(pB);
        return NN_ERR_NODEV;
    }
    src = nn_ip4IsAny(pSock->localAddr) ? pIf->addr : pSock->localAddr;

    len = (uint16_t)(pB->len + NN_UDP_HDR_LEN);
    pH = nn_bufPush(pB, NN_UDP_HDR_LEN);
    if(pH == NULL)
    {
        ++ _stats.txErrors;
        nn_bufFree(pB);
        return NN_ERR_NOMEM;
    }
    nn_put16(pH, pSock->localPort);
    nn_put16(pH + 2, port);
    nn_put16(pH + 4, len);
    pH[6] = pH[7] = 0;
    sum = nn_cksumPseudo(src, to, NN_IP_PROTO_UDP, len);
    sum = nn_cksumFinish(nn_cksumAdd(sum, pH, len));
    nn_put16(pH + 6, sum == 0 ? 0xFFFFu : (uint16_t)sum);
    ++ _stats.tx;
    ++ pSock->txDatagrams;
    return nn_ip_outputVia(pB, pSock->pIf, src, to, NN_IP_PROTO_UDP, NN_IP_DEFAULT_TTL);
}

nn_err_t nn_udpSendBuf(nn_udp_t *pSock, nn_buf_t *pB, nn_ip4_t to, uint16_t port)
{
    nn_err_t rc;
    if(pSock == NULL  ||  !pSock->open  ||  pB == NULL)
    {
        nn_bufFree(pB);
        return NN_ERR_INVAL;
    }
    nn_lock();
    rc = nn_udp_sendBuf(pSock, pB, to, port);
    nn_unlock();
    return rc;
}

nn_err_t nn_udpSendTo(nn_udp_t *pSock, const void *p, size_t n, nn_ip4_t to, uint16_t port)
{
    nn_buf_t *pB;
    uint8_t *pPayload;

    if(pSock == NULL  ||  !pSock->open  ||  n > NN_CFG_BUF_DATA - NN_CFG_TX_HEADROOM)
        return NN_ERR_INVAL;
    pB = nn_bufAlloc(NN_CFG_TX_HEADROOM);
    if(pB == NULL)
        return NN_ERR_NOMEM;
    pPayload = nn_bufPut(pB, (uint16_t)n);
    if(n != 0)
        memcpy(pPayload, p, n);
    return nn_udpSendBuf(pSock, pB, to, port);
}

nn_err_t nn_udpSend(nn_udp_t *pSock, const void *p, size_t n)
{
    if(pSock == NULL  ||  pSock->remotePort == 0)
        return NN_ERR_INVAL;
    return nn_udpSendTo(pSock, p, n, pSock->remoteAddr, pSock->remotePort);
}

nn_buf_t *nn_udp_dequeue(nn_udp_t *pSock)
{
    nn_buf_t * const pB = pSock->pRxHead;
    if(pB != NULL)
    {
        pSock->pRxHead = pB->pNext;
        if(pSock->pRxHead == NULL)
            pSock->pRxTail = NULL;
        -- pSock->rxCount;
        pB->pNext = NULL;
    }
    return pB;
}

nn_buf_t *nn_udpRecvBuf(nn_udp_t *pSock, nn_ip4_t *pFrom, uint16_t *pPort, nn_ms_t timeout)
{
    nn_buf_t *pB = NULL;
    const nn_ms_t start = nn_os_now();

    if(pSock == NULL  ||  !pSock->open)
        return NULL;
    for(;;)
    {
        nn_ms_t waited, remaining;

        nn_lock();
        if(!pSock->open)
        {
            nn_unlock();
            return NULL;
        }
        pB = nn_udp_dequeue(pSock);
        if(pB != NULL)
        {
            nn_unlock();
            break;
        }
        waited = nn_os_now() - start;
        if(timeout != NN_FOREVER  &&  waited >= timeout)
        {
            nn_unlock();
            return NULL;
        }
        remaining = timeout == NN_FOREVER ? NN_FOREVER : timeout - waited;
        pSock->waiter = nn_os_self();
        pSock->waiting = true;
        nn_unlock();
        (void)nn_os_notifyWait(remaining);
    }
    if(pFrom != NULL)
        *pFrom = nn_udpBufFrom(pB);
    if(pPort != NULL)
        *pPort = nn_udpBufPort(pB);
    return pB;
}

int32_t nn_udpRecvFrom(nn_udp_t *pSock, void *p, size_t n, nn_ip4_t *pFrom, uint16_t *pPort, nn_ms_t timeout)
{
    nn_buf_t *pB;
    int32_t len;

    if(pSock == NULL  ||  !pSock->open)
        return NN_ERR_INVAL;
    pB = nn_udpRecvBuf(pSock, pFrom, pPort, timeout);
    if(pB == NULL)
        return pSock->open ? NN_ERR_TIMEOUT : NN_ERR_INVAL;
    len = pB->len;
    if(n > pB->len)
        n = pB->len;
    if(n != 0)
        memcpy(p, pB->pData, n);
    nn_bufFree(pB);
    return len;
}

uint8_t nn_udpAvailable(const nn_udp_t *pSock)
{
    return pSock->rxCount;
}

void nn_udpOnReadable(nn_udp_t *pSock, nn_udpReadableFunc_t fn, void *arg)
{
    nn_lock();
    pSock->onReadable = fn;
    pSock->cbArg = arg;
    nn_unlock();
}

nn_err_t nn_udpClose(nn_udp_t *pSock)
{
    nn_udp_t **pp;
    nn_buf_t *pB;

    if(pSock == NULL  ||  !pSock->open)
        return NN_ERR_INVAL;
    nn_lock();
    for(pp=&_pSockets; *pp!=NULL; pp=&(*pp)->pNext)
    {
        if(*pp == pSock)
        {
            *pp = pSock->pNext;
            break;
        }
    }
    while((pB = nn_udp_dequeue(pSock)) != NULL)
        nn_bufFree(pB);
    pSock->open = false;
    pSock->localPort = 0;
    if(pSock->waiting)
    {
        pSock->waiting = false;
        nn_os_notify(pSock->waiter);
    }
    nn_unlock();
    return NN_OK;
}

void nn_udpGetStats(nn_udpStats_t *pStats)
{
    *pStats = _stats;
}
