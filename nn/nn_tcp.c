/**
 * @file nn_tcp.c
 * TCP. The segment processing follows RFC 9293 section 3.10, in its order: find the
 * socket, check the acceptability of the sequence number, trim the segment to the
 * window, RST, SYN, ACK, data, FIN. Everything runs in the net task with the stack lock
 * held; the application API takes the lock and sleeps on task notifications.
 *
 * Sending: output() sends as much of the send ring as the smaller of the peer's window
 * and the congestion window allows, in MSS sized segments, Nagle unless NODELAY. One
 * timer per socket serves retransmission (RFC 6298, Karn, exponential backoff), the SYN
 * retries and zero window probes; a second one delays ACKs. Loss recovery is fast
 * retransmit and fast recovery after three duplicate ACKs (RFC 5681, with the NewReno
 * partial ACK rule) or a retransmission timeout that resends from the oldest byte.
 */

#include <string.h>

#include "nn_tcp.h"
#include "nn_net.h"
#include "nn_cksum.h"

#define SEQ_LT(a, b)    ((int32_t)((a) - (b)) < 0)
#define SEQ_LE(a, b)    ((int32_t)((a) - (b)) <= 0)
#define SEQ_GT(a, b)    ((int32_t)((a) - (b)) > 0)
#define SEQ_GE(a, b)    ((int32_t)((a) - (b)) >= 0)

#define MIN_MSS         536u
#define OPT_MSS_LEN     4u

/** A connection in TIME_WAIT: enough to answer a retransmitted FIN. */
typedef struct
{
    nn_ip4_t local, remote;
    uint16_t lport, rport;
    uint32_t sndNxt, rcvNxt;
    nn_ms_t expires;
    bool used;
} tw_t;

static nn_tcp_t *_pSockets;         /**< Every socket that is not CLOSED. */
static tw_t _tw[NN_CFG_TCP_TIMEWAIT];
static nn_timer_t _twTimer;
static uint16_t _nextEphemeral;
static uint32_t _issCounter;
static nn_tcpStats_t _stats;

static void output(nn_tcp_t *pS);
static void timerCb(nn_timer_t *pT, void *arg);
static void delAckCb(nn_timer_t *pT, void *arg);

/* --- Small helpers ---------------------------------------------------------------------- */

static uint32_t minU32(uint32_t a, uint32_t b) { return a < b ? a : b; }
static uint32_t maxU32(uint32_t a, uint32_t b) { return a > b ? a : b; }

static uint16_t rcvWindow(const nn_tcp_t *pS)
{
    return (uint16_t)(pS->rxSize - pS->rxLen);
}

static void wakeRx(nn_tcp_t *pS)
{
    if(pS->flags & NN_TCPF_RXWAIT)
    {
        pS->flags &= (uint16_t)~NN_TCPF_RXWAIT;
        nn_os_notify(pS->rxWaiter);
    }
}

static void wakeTx(nn_tcp_t *pS)
{
    if(pS->flags & NN_TCPF_TXWAIT)
    {
        pS->flags &= (uint16_t)~NN_TCPF_TXWAIT;
        nn_os_notify(pS->txWaiter);
    }
}

static void event(nn_tcp_t *pS, uint8_t ev)
{
    if(pS->onEvent != NULL)
        pS->onEvent(pS, ev, pS->cbArg);
}

static void link(nn_tcp_t *pS)
{
    pS->pNext = _pSockets;
    _pSockets = pS;
}

static void unlink(nn_tcp_t *pS)
{
    nn_tcp_t **pp;
    for(pp=&_pSockets; *pp!=NULL; pp=&(*pp)->pNext)
    {
        if(*pp == pS)
        {
            *pp = pS->pNext;
            break;
        }
    }
    pS->pNext = NULL;
}

static bool portInUse(uint16_t port)
{
    const nn_tcp_t *pS;
    unsigned i;
    for(pS=_pSockets; pS!=NULL; pS=pS->pNext)
        if(pS->localPort == port)
            return true;
    for(i=0; i<NN_CFG_TCP_TIMEWAIT; ++i)
        if(_tw[i].used  &&  _tw[i].lport == port)
            return true;
    return false;
}

static uint16_t ephemeralPort(void)
{
    uint16_t tries;
    for(tries=0; tries<1000; ++tries)
    {
        const uint16_t port = _nextEphemeral++;
        if(_nextEphemeral < NN_CFG_TCP_EPHEMERAL  ||  _nextEphemeral == 0)
            _nextEphemeral = NN_CFG_TCP_EPHEMERAL;
        if(!portInUse(port))
            return port;
    }
    return 0;
}

static uint32_t newIss(void)
{
    _issCounter += 0x9E3779B9u;
    return (nn_os_now() << 12) ^ _issCounter;
}

/** Leave every connection state behind: CLOSED, out of the list, timers off, waiters
    woken, event delivered. */
static void closeSocket(nn_tcp_t *pS, nn_err_t err)
{
    unlink(pS);
    nn_timerStop(&pS->timer);
    nn_timerStop(&pS->delAck);
    pS->state = NN_TCP_CLOSED;
    pS->err = err;
    pS->pListener = NULL;
    pS->flags &= (uint16_t)(NN_TCPF_NODELAY | NN_TCPF_RXWAIT | NN_TCPF_TXWAIT);
    if(err != NN_OK)
    {
        pS->rxLen = 0;
        pS->oooLen = 0;
    }
    pS->txLen = 0;
    wakeRx(pS);
    wakeTx(pS);
    event(pS, NN_TCP_EV_CLOSED);
}

void nn_tcp_addrLost(nn_ip4_t addr)
{
    nn_tcp_t *pS, *pNext;
    for(pS=_pSockets; pS!=NULL; pS=pNext)
    {
        pNext = pS->pNext;                              /* closeSocket unlinks */
        if(pS->state != NN_TCP_LISTEN  &&  pS->state != NN_TCP_CLOSED  &&  nn_ip4Equal(pS->localAddr, addr))
            closeSocket(pS, NN_ERR_DOWN);
    }
}

/* --- Segment output --------------------------------------------------------------------- */

/** Copy \a n bytes that start \a seq in the stream out of the send ring. */
static void ringCopyOut(const nn_tcp_t *pS, uint32_t seq, uint8_t *pOut, uint16_t n)
{
    uint32_t idx = ((uint32_t)pS->txHead + (seq - pS->sndUna)) % pS->txSize;
    const uint32_t first = minU32(n, (uint32_t)pS->txSize - idx);
    memcpy(pOut, pS->pTx + idx, first);
    if(first < n)
        memcpy(pOut + first, pS->pTx, n - first);
}

/** Build and send one segment of this connection: \a dataLen bytes from \a seq of the
    send ring, an MSS option when \a withMss. Every ACK carries the current window. */
static nn_err_t sendSegment(nn_tcp_t *pS, uint8_t flags, uint32_t seq, uint16_t dataLen, bool withMss)
{
    const uint16_t optLen = withMss ? OPT_MSS_LEN : 0u;
    const uint16_t hdrLen = (uint16_t)(NN_TCP_HDR_LEN + optLen);
    const uint16_t wnd = rcvWindow(pS);
    nn_buf_t * const pB = nn_bufAlloc(NN_CFG_TX_HEADROOM + OPT_MSS_LEN);
    uint8_t *pH;
    uint32_t sum;

    if(pB == NULL)
    {
        ++ _stats.txNoBuf;
        return NN_ERR_NOMEM;
    }
    if(dataLen != 0)
        ringCopyOut(pS, seq, nn_bufPut(pB, dataLen), dataLen);
    pH = nn_bufPush(pB, hdrLen);
    nn_put16(pH, pS->localPort);
    nn_put16(pH + 2, pS->remotePort);
    nn_put32(pH + 4, seq);
    nn_put32(pH + 8, (flags & NN_TCP_ACK) ? pS->rcvNxt : 0u);
    pH[12] = (uint8_t)((hdrLen / 4u) << 4);
    pH[13] = flags;
    nn_put16(pH + 14, wnd);
    pH[16] = pH[17] = 0;
    pH[18] = pH[19] = 0;
    if(withMss)
    {
        const uint16_t ourMss = (uint16_t)minU32(NN_CFG_TCP_MSS, pS->rxSize);
        pH[20] = 2; pH[21] = 4;
        nn_put16(pH + 22, ourMss);
    }
    sum = nn_cksumPseudo(pS->localAddr, pS->remoteAddr, NN_IP_PROTO_TCP, pB->len);
    nn_put16(pH + 16, nn_cksumFinish(nn_cksumAdd(sum, pH, pB->len)));

    if(flags & NN_TCP_ACK)
    {
        pS->rcvAdv = pS->rcvNxt + wnd;
        if(pS->flags & NN_TCPF_DELACK)
        {
            pS->flags &= (uint16_t)~NN_TCPF_DELACK;
            nn_timerStop(&pS->delAck);
        }
    }
    if(flags & NN_TCP_RST)
        ++ _stats.txResets;
    ++ _stats.tx;
    return nn_ip_output(pB, pS->localAddr, pS->remoteAddr, NN_IP_PROTO_TCP, NN_IP_DEFAULT_TTL);
}

static void sendAck(nn_tcp_t *pS)
{
    (void)sendSegment(pS, NN_TCP_ACK, pS->sndNxt, 0, false);
}

/** A RST (or RST+ACK) in reply to a segment that has no connection, with the addresses
    and ports swapped (RFC 9293 3.10.7.1). */
static void sendResetFor(nn_ip4_t src, nn_ip4_t dst, uint16_t sport, uint16_t dport,
                         uint32_t seq, uint32_t ack, uint8_t flags, uint32_t segLen)
{
    nn_buf_t * const pB = nn_bufAlloc(NN_CFG_TX_HEADROOM);
    uint8_t *pH;
    uint32_t sum;

    if(pB == NULL)
    {
        ++ _stats.txNoBuf;
        return;
    }
    pH = nn_bufPut(pB, NN_TCP_HDR_LEN);
    if(pH == NULL)                                      /* cannot happen with a fresh buffer */
    {
        nn_bufFree(pB);
        return;
    }
    memset(pH, 0, NN_TCP_HDR_LEN);
    nn_put16(pH, dport);
    nn_put16(pH + 2, sport);
    if(flags & NN_TCP_ACK)
    {
        nn_put32(pH + 4, ack);
        pH[13] = NN_TCP_RST;
    }
    else
    {
        nn_put32(pH + 8, seq + segLen);
        pH[13] = NN_TCP_RST | NN_TCP_ACK;
    }
    pH[12] = (NN_TCP_HDR_LEN / 4u) << 4;
    sum = nn_cksumPseudo(dst, src, NN_IP_PROTO_TCP, NN_TCP_HDR_LEN);
    nn_put16(pH + 16, nn_cksumFinish(nn_cksumAdd(sum, pH, NN_TCP_HDR_LEN)));
    ++ _stats.txResets;
    ++ _stats.tx;
    (void)nn_ip_output(pB, dst, src, NN_IP_PROTO_TCP, NN_IP_DEFAULT_TTL);
}

/* --- Timers ----------------------------------------------------------------------------- */

static void startTimer(nn_tcp_t *pS)
{
    nn_timerStart(&pS->timer, pS->rto, 0);
}

static void backoff(nn_tcp_t *pS)
{
    pS->rto = (nn_ms_t)minU32(pS->rto * 2u, NN_CFG_TCP_RTO_MAX_MS);
}

/** RFC 6298 with srtt scaled by 8 and rttvar by 4, in milliseconds. */
static void updateRtt(nn_tcp_t *pS, nn_ms_t r)
{
    int32_t m = (int32_t)r;
    uint32_t rto;
    if(pS->srtt == 0)
    {
        pS->srtt = m << 3;
        pS->rttvar = m << 1;
    }
    else
    {
        int32_t delta = m - (pS->srtt >> 3);
        pS->srtt += delta;
        if(delta < 0)
            delta = -delta;
        pS->rttvar += delta - (pS->rttvar >> 2);
    }
    rto = (uint32_t)(pS->srtt >> 3) + (uint32_t)pS->rttvar;
    pS->rto = (nn_ms_t)minU32(maxU32(rto, NN_CFG_TCP_RTO_MIN_MS), NN_CFG_TCP_RTO_MAX_MS);
}

static bool finPending(const nn_tcp_t *pS)
{
    return pS->state == NN_TCP_FIN_WAIT_1  ||  pS->state == NN_TCP_CLOSING  ||  pS->state == NN_TCP_LAST_ACK;
}

/** Resend the oldest unacknowledged segment (fast retransmit, partial ACK). */
static void retransmitOne(nn_tcp_t *pS)
{
    const uint16_t len = (uint16_t)minU32(pS->txLen, pS->mss);
    uint8_t flags = NN_TCP_ACK;
    if(len == 0  &&  finPending(pS)  &&  (pS->flags & NN_TCPF_FINSENT))
        flags |= NN_TCP_FIN;
    else if(len == 0)
        return;
    if(len != 0  &&  len == pS->txLen)
        flags |= NN_TCP_PSH;
    pS->flags &= (uint16_t)~NN_TCPF_RTT;             /* Karn: never time a retransmission */
    if(sendSegment(pS, flags, pS->sndUna, len, false) == NN_OK)
    {
        ++ _stats.rexmits;
        ++ pS->rexmitCount;
    }
}

static void timerCb(nn_timer_t *pT, void *arg)
{
    nn_tcp_t * const pS = arg;
    (void)pT;

    if(pS->state == NN_TCP_SYN_SENT  ||  pS->state == NN_TCP_SYN_RCVD)
    {
        if(++pS->rexmits > NN_CFG_TCP_SYN_RETRIES)
        {
            ++ _stats.timeouts;
            closeSocket(pS, NN_ERR_TIMEOUT);
            return;
        }
        backoff(pS);
        ++ _stats.rexmits;
        (void)sendSegment(pS, pS->state == NN_TCP_SYN_SENT ? NN_TCP_SYN : (NN_TCP_SYN | NN_TCP_ACK), pS->iss, 0, true);
        startTimer(pS);
        return;
    }
    if(pS->flags & NN_TCPF_PERSIST)
    {
        /* Zero window probe: one byte of unsent data, beyond the window on purpose,
           repeated with backoff until the peer acknowledges it or opens the window. */
        if(pS->sndWnd == 0  &&  pS->txLen != 0)
        {
            if(sendSegment(pS, NN_TCP_ACK, pS->sndUna, 1, false) == NN_OK  &&  pS->sndNxt == pS->sndUna)
            {
                pS->sndNxt += 1;
                if(SEQ_GT(pS->sndNxt, pS->sndMax))
                    pS->sndMax = pS->sndNxt;
            }
            backoff(pS);
            startTimer(pS);
        }
        else
        {
            pS->flags &= (uint16_t)~NN_TCPF_PERSIST;
            output(pS);
            if(pS->sndNxt != pS->sndUna  &&  !nn_timerIsActive(&pS->timer))
                startTimer(pS);
        }
        return;
    }
    if(pS->sndNxt == pS->sndUna)
        return;                                         /* nothing outstanding after all */
    if(++pS->rexmits > NN_CFG_TCP_MAX_REXMIT)
    {
        ++ _stats.timeouts;
        closeSocket(pS, NN_ERR_TIMEOUT);
        return;
    }
    ++ _stats.timeouts;
    {
        const uint32_t flight = pS->sndNxt - pS->sndUna;
        pS->ssthresh = maxU32(flight / 2u, 2u * pS->mss);
    }
    pS->cwnd = pS->mss;
    pS->dupAcks = 0;
    pS->flags &= (uint16_t)~(NN_TCPF_FASTREC | NN_TCPF_RTT | NN_TCPF_FINSENT);
    backoff(pS);
    pS->sndNxt = pS->sndUna;                            /* go back to the oldest byte */
    ++ _stats.rexmits;
    ++ pS->rexmitCount;
    output(pS);
    if(!nn_timerIsActive(&pS->timer))
        startTimer(pS);                                 /* output had no buffer: try later */
}

static void delAckCb(nn_timer_t *pT, void *arg)
{
    nn_tcp_t * const pS = arg;
    (void)pT;
    pS->flags &= (uint16_t)~NN_TCPF_DELACK;
    ++ _stats.delAcks;
    sendAck(pS);
}

/** Send what the windows allow. Called after anything that may have opened a window:
    new data from the application, an ACK, a timer. */
static void output(nn_tcp_t *pS)
{
    if(pS->state != NN_TCP_ESTABLISHED  &&  pS->state != NN_TCP_CLOSE_WAIT  &&  !finPending(pS))
        return;
    for(;;)
    {
        const uint32_t inFlight = pS->sndNxt - pS->sndUna;
        const uint32_t unsent = inFlight < pS->txLen ? pS->txLen - inFlight : 0u;
        const uint32_t wnd = minU32(pS->sndWnd, pS->cwnd);
        const uint32_t usable = wnd > inFlight ? wnd - inFlight : 0u;
        uint32_t len = minU32(minU32(unsent, usable), pS->mss);
        const bool fin = finPending(pS)  &&  !(pS->flags & NN_TCPF_FINSENT)  &&  unsent == len;
        uint8_t flags = NN_TCP_ACK;

        if(len == 0  &&  !fin)
        {
            if(unsent != 0  &&  inFlight == 0  &&  pS->sndWnd == 0  &&  !nn_timerIsActive(&pS->timer))
            {
                pS->flags |= NN_TCPF_PERSIST;
                startTimer(pS);
            }
            return;
        }
        if(len < pS->mss  &&  !fin  &&  inFlight != 0  &&  !(pS->flags & NN_TCPF_NODELAY)
           &&  len < pS->sndWndMax / 2u)
            return;                                     /* Nagle and sender SWS avoidance:
                                                           a small segment waits for the ACK */
        if(len != 0  &&  len == unsent)
            flags |= NN_TCP_PSH;
        if(fin)
            flags |= NN_TCP_FIN;
        if(sendSegment(pS, flags, pS->sndNxt, (uint16_t)len, false) != NN_OK)
        {
            if(!nn_timerIsActive(&pS->timer))
                startTimer(pS);                         /* no buffer: the timer retries */
            return;
        }
        if(len != 0  &&  !(pS->flags & NN_TCPF_RTT)  &&  SEQ_GE(pS->sndNxt, pS->sndMax))
        {
            pS->flags |= NN_TCPF_RTT;
            pS->rttStart = nn_os_now();
            pS->rttSeq = pS->sndNxt + len;
        }
        pS->sndNxt += len + (fin ? 1u : 0u);
        if(SEQ_GT(pS->sndNxt, pS->sndMax))
            pS->sndMax = pS->sndNxt;
        if(fin)
            pS->flags |= NN_TCPF_FINSENT;
        pS->txBytes += len;
        if(!nn_timerIsActive(&pS->timer)  ||  (pS->flags & NN_TCPF_PERSIST))
        {
            pS->flags &= (uint16_t)~NN_TCPF_PERSIST;
            startTimer(pS);
        }
        if(fin)
            return;
    }
}

/* --- TIME_WAIT table ---------------------------------------------------------------------- */

static void twTimerCb(nn_timer_t *pT, void *arg)
{
    const nn_ms_t now = nn_os_now();
    unsigned i, used = 0;
    (void)pT; (void)arg;
    for(i=0; i<NN_CFG_TCP_TIMEWAIT; ++i)
    {
        if(_tw[i].used  &&  !nn_msBefore(now, _tw[i].expires))
            _tw[i].used = false;
        if(_tw[i].used)
            ++ used;
    }
    if(used == 0)
        nn_timerStop(&_twTimer);
}

static void enterTimeWait(nn_tcp_t *pS)
{
    tw_t *pE = NULL;
    unsigned i;
    for(i=0; i<NN_CFG_TCP_TIMEWAIT; ++i)
    {
        if(!_tw[i].used)
        {
            pE = &_tw[i];
            break;
        }
        if(pE == NULL  ||  nn_msBefore(_tw[i].expires, pE->expires))
            pE = &_tw[i];                               /* full: replace the oldest */
    }
    pE->local = pS->localAddr;
    pE->remote = pS->remoteAddr;
    pE->lport = pS->localPort;
    pE->rport = pS->remotePort;
    pE->sndNxt = pS->sndNxt;
    pE->rcvNxt = pS->rcvNxt;
    pE->expires = nn_os_now() + (nn_ms_t)(2u * NN_CFG_TCP_MSL_MS);
    pE->used = true;
    ++ _stats.timeWaits;
    if(!nn_timerIsActive(&_twTimer))
        nn_timerStart(&_twTimer, 1000, 1000);
    closeSocket(pS, NN_OK);
}

static tw_t *twFind(nn_ip4_t src, uint16_t sport, nn_ip4_t dst, uint16_t dport)
{
    unsigned i;
    for(i=0; i<NN_CFG_TCP_TIMEWAIT; ++i)
        if(_tw[i].used  &&  _tw[i].lport == dport  &&  _tw[i].rport == sport
           &&  nn_ip4Equal(_tw[i].local, dst)  &&  nn_ip4Equal(_tw[i].remote, src))
            return &_tw[i];
    return NULL;
}

/* --- Receive ring ------------------------------------------------------------------------- */

/** Store \a n bytes that belong \a off bytes after rcvNxt. */
static void ringCopyIn(nn_tcp_t *pS, uint32_t off, const uint8_t *p, uint16_t n)
{
    uint32_t idx = ((uint32_t)pS->rxHead + pS->rxLen + off) % pS->rxSize;
    const uint32_t first = minU32(n, (uint32_t)pS->rxSize - idx);
    memcpy(pS->pRx + idx, p, first);
    if(first < n)
        memcpy(pS->pRx, p + first, n - first);
}

/** Data at rcvNxt: it is in order. Absorb the out of order range when it is reached. */
static void acceptInOrder(nn_tcp_t *pS, const uint8_t *p, uint16_t n)
{
    ringCopyIn(pS, 0, p, n);
    pS->rxLen = (uint16_t)(pS->rxLen + n);
    pS->rcvNxt += n;
    pS->rxBytes += n;
    if(pS->oooLen != 0)
    {
        if(pS->oooOff <= n)
        {
            const uint32_t covered = (uint32_t)n - pS->oooOff;
            if(covered < pS->oooLen)
            {
                const uint16_t rest = (uint16_t)(pS->oooLen - covered);
                pS->rxLen = (uint16_t)(pS->rxLen + rest);
                pS->rcvNxt += rest;
                pS->rxBytes += rest;
            }
            pS->oooLen = 0;
            pS->oooOff = 0;
        }
        else
            pS->oooOff = (uint16_t)(pS->oooOff - n);
    }
}

/** Data beyond rcvNxt inside the window: keep it when it fits the one range we track. */
static void acceptOutOfOrder(nn_tcp_t *pS, uint32_t off, const uint8_t *p, uint16_t n)
{
    ++ _stats.rxOoo;
    if(off + n > rcvWindow(pS)  ||  off > 0xFFFFu)
    {
        ++ _stats.rxOooDropped;
        return;
    }
    if(pS->oooLen == 0)
    {
        ringCopyIn(pS, off, p, n);
        pS->oooOff = (uint16_t)off;
        pS->oooLen = n;
    }
    else if(off <= (uint32_t)pS->oooOff + pS->oooLen  &&  off + n >= pS->oooOff)
    {
        /* Overlaps or touches the range: the union is still one range. */
        const uint32_t start = minU32(off, pS->oooOff);
        const uint32_t end = maxU32(off + n, (uint32_t)pS->oooOff + pS->oooLen);
        ringCopyIn(pS, off, p, n);
        pS->oooOff = (uint16_t)start;
        pS->oooLen = (uint16_t)(end - start);
    }
    else
        ++ _stats.rxOooDropped;
}

/* --- Opening a passive connection ---------------------------------------------------------- */

static void initConnection(nn_tcp_t *pS, nn_ip4_t local, uint16_t lport, nn_ip4_t remote, uint16_t rport)
{
    pS->localAddr = local;
    pS->localPort = lport;
    pS->remoteAddr = remote;
    pS->remotePort = rport;
    pS->rxHead = pS->rxLen = pS->oooOff = pS->oooLen = 0;
    pS->txHead = pS->txLen = 0;
    pS->iss = newIss();
    pS->sndUna = pS->sndNxt = pS->sndMax = pS->iss;
    pS->sndWnd = pS->sndWndMax = 0;
    pS->mss = MIN_MSS;
    pS->ssthresh = 0xFFFFu;
    pS->dupAcks = pS->rexmits = 0;
    pS->srtt = pS->rttvar = 0;
    pS->rto = NN_CFG_TCP_RTO_INIT_MS;
    pS->flags &= (NN_TCPF_NODELAY | NN_TCPF_RXWAIT | NN_TCPF_TXWAIT);   /* a task may wait in accept */
    pS->err = NN_OK;
    pS->rxBytes = pS->txBytes = pS->rexmitCount = 0;
}

static void setPeerMss(nn_tcp_t *pS, uint16_t mss)
{
    if(mss < MIN_MSS)
        mss = MIN_MSS;
    pS->mss = (uint16_t)minU32(mss, NN_CFG_TCP_MSS);
    pS->cwnd = (uint32_t)NN_CFG_TCP_IW * pS->mss;
}

/** Parse the MSS option of a SYN; 536 when absent. */
static uint16_t parseMss(const uint8_t *pOpt, uint16_t optLen)
{
    uint16_t i = 0;
    while(i < optLen)
    {
        const uint8_t kind = pOpt[i];
        uint8_t len;
        if(kind == 0)
            break;
        if(kind == 1)
        {
            ++ i;
            continue;
        }
        if(i + 1 >= optLen)
            break;
        len = pOpt[i + 1];
        if(len < 2  ||  i + len > optLen)
            break;
        if(kind == 2  &&  len == 4)
            return nn_get16(pOpt + i + 2);
        i = (uint16_t)(i + len);
    }
    return MIN_MSS;
}

/* --- Segment input ------------------------------------------------------------------------- */

static nn_tcp_t *lookup(nn_ip4_t src, uint16_t sport, nn_ip4_t dst, uint16_t dport)
{
    nn_tcp_t *pS, *pListener = NULL;
    for(pS=_pSockets; pS!=NULL; pS=pS->pNext)
    {
        if(pS->localPort != dport)
            continue;
        if(pS->state == NN_TCP_LISTEN)
        {
            if(nn_ip4IsAny(pS->localAddr)  ||  nn_ip4Equal(pS->localAddr, dst))
                if(pListener == NULL  ||  !nn_ip4IsAny(pS->localAddr))
                    pListener = pS;
        }
        else if(pS->remotePort == sport  &&  nn_ip4Equal(pS->remoteAddr, src)  &&  nn_ip4Equal(pS->localAddr, dst))
            return pS;
    }
    return pListener;
}

/** A new ACK: free the ring, time the round trip, grow cwnd, manage the timer. */
static void processAck(nn_tcp_t *pS, uint32_t ack)
{
    const uint32_t acked = ack - pS->sndUna;
    const uint32_t dataAcked = minU32(acked, pS->txLen);

    pS->txHead = (uint16_t)(((uint32_t)pS->txHead + dataAcked) % pS->txSize);
    pS->txLen = (uint16_t)(pS->txLen - dataAcked);
    pS->sndUna = ack;
    if(SEQ_GT(ack, pS->sndNxt))
        pS->sndNxt = ack;                               /* acknowledged past the resend pointer */
    pS->rexmits = 0;
    if((pS->flags & NN_TCPF_RTT)  &&  SEQ_GE(ack, pS->rttSeq))
    {
        pS->flags &= (uint16_t)~NN_TCPF_RTT;
        updateRtt(pS, nn_os_now() - pS->rttStart);
    }
    if(pS->flags & NN_TCPF_FASTREC)
    {
        if(SEQ_LT(ack, pS->recover))
        {
            /* Partial ACK (NewReno): the next segment was lost too. */
            pS->cwnd = (pS->cwnd > dataAcked ? pS->cwnd - dataAcked : 0u) + pS->mss;
            retransmitOne(pS);
        }
        else
        {
            pS->cwnd = pS->ssthresh;
            pS->flags &= (uint16_t)~NN_TCPF_FASTREC;
        }
    }
    else if(pS->cwnd < pS->ssthresh)
        pS->cwnd += minU32(acked, pS->mss);               /* slow start */
    else
        pS->cwnd += maxU32(((uint32_t)pS->mss * pS->mss) / pS->cwnd, 1u);
    pS->dupAcks = 0;
    if(pS->sndUna == pS->sndNxt)
    {
        nn_timerStop(&pS->timer);
        pS->flags &= (uint16_t)~NN_TCPF_PERSIST;
    }
    else
    {
        pS->flags &= (uint16_t)~NN_TCPF_PERSIST;
        startTimer(pS);
    }
    if(dataAcked != 0)
    {
        wakeTx(pS);
        event(pS, NN_TCP_EV_WRITABLE);
    }
}

static void input(nn_buf_t *pB, nn_iface_t *pIf, nn_ip4_t src, nn_ip4_t dst)
{
    const uint8_t *pH = pB->pData;
    uint16_t hlen, sport, dport, wnd, dataLen;
    uint32_t seq, ack, segLen;
    uint8_t flags;
    const uint8_t *pData;
    nn_tcp_t *pS;
    bool ackNow = false;
    (void)pIf;

    ++ _stats.rx;
    if(pB->len < NN_TCP_HDR_LEN)
        goto bad;
    hlen = (uint16_t)((pH[12] >> 4) * 4u);
    if(hlen < NN_TCP_HDR_LEN  ||  hlen > pB->len)
        goto bad;
    {
        const uint32_t sum = nn_cksumPseudo(src, dst, NN_IP_PROTO_TCP, pB->len);
        if(nn_cksumFinish(nn_cksumAdd(sum, pH, pB->len)) != 0)
        {
            ++ _stats.rxBadChecksum;
            nn_bufFree(pB);
            return;
        }
    }
    if(pB->flags & (NN_BUF_BCAST | NN_BUF_MCAST))
        goto bad;                                       /* TCP is unicast only */
    sport = nn_get16(pH);
    dport = nn_get16(pH + 2);
    seq = nn_get32(pH + 4);
    ack = nn_get32(pH + 8);
    flags = pH[13] & 0x3Fu;
    wnd = nn_get16(pH + 14);
    pData = pH + hlen;
    dataLen = (uint16_t)(pB->len - hlen);
    segLen = (uint32_t)dataLen + ((flags & NN_TCP_SYN) ? 1u : 0u) + ((flags & NN_TCP_FIN) ? 1u : 0u);

    pS = lookup(src, sport, dst, dport);
    if(pS == NULL)
    {
        tw_t * const pE = twFind(src, sport, dst, dport);
        if(pE != NULL)
        {
            if(flags & NN_TCP_RST)
                pE->used = false;
            else if((flags & NN_TCP_SYN)  &&  SEQ_GT(seq, pE->rcvNxt))
                pE->used = false;                       /* a new incarnation: let it fail
                                                           here and succeed on the retry */
            else
            {
                /* Answer a retransmitted FIN so the peer leaves LAST_ACK. */
                nn_tcp_t tmp;
                memset(&tmp, 0, sizeof(tmp));
                tmp.localAddr = dst; tmp.remoteAddr = src;
                tmp.localPort = dport; tmp.remotePort = sport;
                tmp.sndNxt = pE->sndNxt; tmp.rcvNxt = pE->rcvNxt;
                sendAck(&tmp);
                pE->expires = nn_os_now() + (nn_ms_t)(2u * NN_CFG_TCP_MSL_MS);
            }
            nn_bufFree(pB);
            return;
        }
        ++ _stats.rxNoSocket;
        if(!(flags & NN_TCP_RST))
            sendResetFor(src, dst, sport, dport, seq, ack, flags, segLen);
        nn_bufFree(pB);
        return;
    }

    /* --- LISTEN ------------------------------------------------------------------------ */
    if(pS->state == NN_TCP_LISTEN)
    {
        nn_tcp_t *pNew;
        if(flags & NN_TCP_RST)
            goto done;
        if(flags & NN_TCP_ACK)
        {
            sendResetFor(src, dst, sport, dport, seq, ack, flags, segLen);
            goto done;
        }
        if(!(flags & NN_TCP_SYN))
            goto done;
        pNew = pS->pAcceptQ;
        if(pNew == NULL)
        {
            ++ _stats.rxAcceptDropped;                  /* the peer retries its SYN */
            goto done;
        }
        pS->pAcceptQ = pNew->pNext;
        pNew->pNext = NULL;
        initConnection(pNew, dst, dport, src, sport);
        pNew->irs = seq;
        pNew->rcvNxt = seq + 1;
        pNew->rcvAdv = pNew->rcvNxt;
        pNew->sndWnd = pNew->sndWndMax = wnd;
        pNew->sndWl1 = seq;
        pNew->sndWl2 = ack;
        setPeerMss(pNew, parseMss(pH + NN_TCP_HDR_LEN, (uint16_t)(hlen - NN_TCP_HDR_LEN)));
        pNew->state = NN_TCP_SYN_RCVD;
        link(pNew);
        ++ _stats.passiveOpens;
        (void)sendSegment(pNew, NN_TCP_SYN | NN_TCP_ACK, pNew->iss, 0, true);
        pNew->sndNxt = pNew->sndMax = pNew->iss + 1;
        startTimer(pNew);
        goto done;
    }

    /* --- SYN_SENT ---------------------------------------------------------------------- */
    if(pS->state == NN_TCP_SYN_SENT)
    {
        if(flags & NN_TCP_ACK)
        {
            if(SEQ_LE(ack, pS->iss)  ||  SEQ_GT(ack, pS->sndNxt))
            {
                if(!(flags & NN_TCP_RST))
                    sendResetFor(src, dst, sport, dport, seq, ack, flags, segLen);
                goto done;
            }
        }
        if(flags & NN_TCP_RST)
        {
            if(flags & NN_TCP_ACK)
            {
                ++ _stats.rxResets;
                closeSocket(pS, NN_ERR_REFUSED);
            }
            goto done;
        }
        if(!(flags & NN_TCP_SYN))
            goto done;
        pS->irs = seq;
        pS->rcvNxt = seq + 1;
        pS->rcvAdv = pS->rcvNxt;
        setPeerMss(pS, parseMss(pH + NN_TCP_HDR_LEN, (uint16_t)(hlen - NN_TCP_HDR_LEN)));
        if(flags & NN_TCP_ACK)
        {
            pS->sndUna = ack;
            pS->sndWnd = pS->sndWndMax = wnd;
            pS->sndWl1 = seq;
            pS->sndWl2 = ack;
            if((pS->flags & NN_TCPF_RTT)  &&  SEQ_GE(ack, pS->rttSeq))
                updateRtt(pS, nn_os_now() - pS->rttStart);
            pS->flags &= (uint16_t)~NN_TCPF_RTT;
            pS->rexmits = 0;
            nn_timerStop(&pS->timer);
            pS->state = NN_TCP_ESTABLISHED;
            ++ _stats.established;
            sendAck(pS);
            wakeRx(pS);
            event(pS, NN_TCP_EV_CONNECTED);
            /* Data with the SYN-ACK is unusual but legal: fall through to step 6. */
            seq += 1;
            flags &= (uint8_t)~NN_TCP_SYN;
            segLen -= 1;
        }
        else
        {
            pS->state = NN_TCP_SYN_RCVD;                /* simultaneous open */
            (void)sendSegment(pS, NN_TCP_SYN | NN_TCP_ACK, pS->iss, 0, true);
            startTimer(pS);
            goto done;
        }
    }

    /* --- Step 1: acceptability, and trimming to the window ------------------------------- */
    {
        const uint16_t rwnd = rcvWindow(pS);
        bool ok;
        if(segLen == 0)
            ok = rwnd == 0 ? seq == pS->rcvNxt : (SEQ_GE(seq, pS->rcvNxt)  &&  SEQ_LT(seq, pS->rcvNxt + rwnd));
        else
            ok = rwnd != 0  &&  ((SEQ_GE(seq, pS->rcvNxt)  &&  SEQ_LT(seq, pS->rcvNxt + rwnd))
                                 ||  (SEQ_GE(seq + segLen - 1, pS->rcvNxt)  &&  SEQ_LT(seq + segLen - 1, pS->rcvNxt + rwnd)));
        if(!ok)
        {
            if(flags & NN_TCP_RST)
                goto done;
            ++ _stats.rxDup;
            if(pS->state == NN_TCP_SYN_RCVD  &&  (flags & NN_TCP_SYN)  &&  seq == pS->irs)
                (void)sendSegment(pS, NN_TCP_SYN | NN_TCP_ACK, pS->iss, 0, true);   /* our SYN-ACK was lost */
            else
                sendAck(pS);
            goto done;
        }
        if(SEQ_LT(seq, pS->rcvNxt))
        {
            uint32_t skip = pS->rcvNxt - seq;
            if(flags & NN_TCP_SYN)
            {
                flags &= (uint8_t)~NN_TCP_SYN;
                -- skip;
                ++ seq;
            }
            if(skip > dataLen)
            {
                skip = dataLen;
                flags &= (uint8_t)~NN_TCP_FIN;          /* the FIN was received before */
            }
            if(skip != 0)
                ++ _stats.rxDup;
            pData += skip;
            dataLen = (uint16_t)(dataLen - skip);
            seq += skip;
        }
        if(SEQ_GT(seq + dataLen, pS->rcvNxt + rwnd))
        {
            dataLen = (uint16_t)(pS->rcvNxt + rwnd - seq);
            flags &= (uint8_t)~NN_TCP_FIN;
        }
    }

    /* --- Step 2: RST ------------------------------------------------------------------- */
    if(flags & NN_TCP_RST)
    {
        ++ _stats.rxResets;
        closeSocket(pS, NN_ERR_RESET);
        goto done;
    }

    /* --- Step 4: SYN in a synchronized state --------------------------------------------- */
    if(flags & NN_TCP_SYN)
    {
        (void)sendSegment(pS, NN_TCP_RST, pS->sndNxt, 0, false);
        closeSocket(pS, NN_ERR_RESET);
        goto done;
    }

    /* --- Step 5: ACK ------------------------------------------------------------------- */
    if(!(flags & NN_TCP_ACK))
        goto done;
    if(pS->state == NN_TCP_SYN_RCVD)
    {
        if(SEQ_LT(ack, pS->sndUna)  ||  SEQ_GT(ack, pS->sndNxt))
        {
            sendResetFor(src, dst, sport, dport, seq, ack, flags, segLen);
            goto done;
        }
        pS->sndUna = ack;
        pS->sndWnd = pS->sndWndMax = wnd;
        pS->sndWl1 = seq;
        pS->sndWl2 = ack;
        pS->rexmits = 0;
        nn_timerStop(&pS->timer);
        pS->state = NN_TCP_ESTABLISHED;
        ++ _stats.established;
        wakeRx(pS);
        event(pS, NN_TCP_EV_CONNECTED);
    }
    else
    {
        /* Valid up to the highest sequence ever sent, not the resend pointer: after a
           timeout sndNxt is back at sndUna while the peer may hold, and acknowledge,
           everything sent before it (its ACKs were what got lost). */
        if(SEQ_GT(ack, pS->sndMax))
        {
            sendAck(pS);                                /* acknowledges the future */
            goto done;
        }
        if(SEQ_GT(ack, pS->sndUna))
            processAck(pS, ack);
        else if(ack == pS->sndUna  &&  dataLen == 0  &&  !(flags & NN_TCP_FIN)
                &&  wnd == pS->sndWnd  &&  pS->sndNxt != pS->sndUna  &&  !(pS->flags & NN_TCPF_PERSIST))
        {
            /* Duplicate ACK (RFC 5681 3.2). */
            ++ pS->dupAcks;
            if(pS->dupAcks == 3)
            {
                const uint32_t flight = pS->sndNxt - pS->sndUna;
                pS->ssthresh = maxU32(flight / 2u, 2u * pS->mss);
                pS->recover = pS->sndNxt;
                pS->flags |= NN_TCPF_FASTREC;
                retransmitOne(pS);
                ++ _stats.fastRexmits;
                pS->cwnd = pS->ssthresh + 3u * pS->mss;
            }
            else if(pS->dupAcks > 3)
                pS->cwnd += pS->mss;
        }
        /* Window update (RFC 9293 3.10.7.4, step 5, ESTABLISHED). */
        if(SEQ_LT(pS->sndWl1, seq)  ||  (pS->sndWl1 == seq  &&  SEQ_LE(pS->sndWl2, ack)))
        {
            pS->sndWnd = wnd;
            pS->sndWl1 = seq;
            pS->sndWl2 = ack;
            if(wnd > pS->sndWndMax)
                pS->sndWndMax = wnd;
        }
    }
    /* Our FIN acknowledged? */
    if(finPending(pS)  &&  (pS->flags & NN_TCPF_FINSENT)  &&  pS->txLen == 0  &&  pS->sndUna == pS->sndNxt)
    {
        if(pS->state == NN_TCP_FIN_WAIT_1)
            pS->state = NN_TCP_FIN_WAIT_2;
        else if(pS->state == NN_TCP_CLOSING)
        {
            enterTimeWait(pS);
            goto done;
        }
        else                                            /* LAST_ACK */
        {
            closeSocket(pS, NN_OK);
            goto done;
        }
    }

    /* --- Step 6: data -------------------------------------------------------------------- */
    if(dataLen != 0)
    {
        if(pS->state == NN_TCP_ESTABLISHED  ||  pS->state == NN_TCP_FIN_WAIT_1  ||  pS->state == NN_TCP_FIN_WAIT_2)
        {
            if(seq == pS->rcvNxt)
            {
                const bool fillsGap = pS->oooLen != 0;
                acceptInOrder(pS, pData, dataLen);
                if(fillsGap  ||  (pS->flags & NN_TCPF_DELACK))
                    ackNow = true;                      /* every second segment, and at once
                                                           after a gap (RFC 5681 4.2) */
                else
                {
                    pS->flags |= NN_TCPF_DELACK;
                    nn_timerStart(&pS->delAck, NN_CFG_TCP_DELACK_MS, 0);
                }
                wakeRx(pS);
                event(pS, NN_TCP_EV_READABLE);
            }
            else
            {
                acceptOutOfOrder(pS, seq - pS->rcvNxt, pData, dataLen);
                ackNow = true;                          /* tells the sender what we miss */
                flags &= (uint8_t)~NN_TCP_FIN;          /* the FIN is beyond the gap too */
            }
        }
        else
            flags &= (uint8_t)~NN_TCP_FIN;
    }

    /* --- Step 7: FIN ----------------------------------------------------------------------- */
    if((flags & NN_TCP_FIN)  &&  seq + dataLen == pS->rcvNxt)
    {
        pS->rcvNxt += 1;
        pS->flags |= NN_TCPF_RXEOF;
        ackNow = true;
        switch(pS->state)
        {
        case NN_TCP_SYN_RCVD:
        case NN_TCP_ESTABLISHED:
            pS->state = NN_TCP_CLOSE_WAIT;
            break;
        case NN_TCP_FIN_WAIT_1:
            pS->state = NN_TCP_CLOSING;
            break;
        case NN_TCP_FIN_WAIT_2:
            sendAck(pS);
            ackNow = false;
            enterTimeWait(pS);
            goto done;
        default:
            break;
        }
        wakeRx(pS);
        event(pS, NN_TCP_EV_READABLE);
    }

    if(ackNow)
        sendAck(pS);
    output(pS);
done:
    nn_bufFree(pB);
    return;

bad:
    ++ _stats.rxBad;
    nn_bufFree(pB);
}

static nn_ipProto_t _proto = { NN_IP_PROTO_TCP, "tcp", input, NULL
#if NN_CFG_STATS
    , 0
#endif
};

void nn_tcp_init(void)
{
    _pSockets = NULL;
    memset(_tw, 0, sizeof(_tw));
    memset(&_stats, 0, sizeof(_stats));
    _nextEphemeral = NN_CFG_TCP_EPHEMERAL;
    _issCounter = 0;
    nn_timerSetup(&_twTimer, twTimerCb, NULL);
    nn_ipProtoRegister(&_proto);
}

/* --- Socket API: every function takes the stack lock itself ------------------------------ */

nn_err_t nn_tcpOpen(nn_tcp_t *pSock, void *pRxRing, uint16_t rxSize, void *pTxRing, uint16_t txSize)
{
    if(pSock == NULL  ||  (pRxRing == NULL) != (rxSize == 0)  ||  (pTxRing == NULL) != (txSize == 0))
        return NN_ERR_INVAL;
    memset(pSock, 0, sizeof(*pSock));
    pSock->pRx = pRxRing;
    pSock->rxSize = rxSize;
    pSock->pTx = pTxRing;
    pSock->txSize = txSize;
    pSock->state = NN_TCP_CLOSED;
    pSock->mss = MIN_MSS;
    nn_timerSetup(&pSock->timer, timerCb, pSock);
    nn_timerSetup(&pSock->delAck, delAckCb, pSock);
    return NN_OK;
}

static nn_err_t bindPort(nn_tcp_t *pSock, nn_ip4_t addr, uint16_t port)
{
    const nn_tcp_t *pS;
    if(port == 0)
    {
        port = ephemeralPort();
        if(port == 0)
            return NN_ERR_FULL;
    }
    else
    {
        for(pS=_pSockets; pS!=NULL; pS=pS->pNext)
            if(pS != pSock  &&  pS->localPort == port  &&  pS->state == NN_TCP_LISTEN
               &&  (nn_ip4IsAny(pS->localAddr)  ||  nn_ip4IsAny(addr)  ||  nn_ip4Equal(pS->localAddr, addr)))
                return NN_ERR_EXIST;
    }
    pSock->localAddr = addr;
    pSock->localPort = port;
    return NN_OK;
}

nn_err_t nn_tcpBind(nn_tcp_t *pSock, nn_ip4_t addr, uint16_t port)
{
    nn_err_t rc;
    if(pSock == NULL  ||  pSock->state != NN_TCP_CLOSED)
        return NN_ERR_INVAL;
    nn_lock();
    rc = bindPort(pSock, addr, port);
    nn_unlock();
    return rc;
}

nn_err_t nn_tcpListen(nn_tcp_t *pSock)
{
    if(pSock == NULL  ||  pSock->state != NN_TCP_CLOSED  ||  pSock->localPort == 0)
        return NN_ERR_INVAL;
    nn_lock();
    pSock->state = NN_TCP_LISTEN;
    pSock->pAcceptQ = NULL;
    link(pSock);
    nn_unlock();
    return NN_OK;
}

/** Sleep on the receive side notification until \a timeout; the caller holds the lock
    and loops. Returns false when the time is up. */
static bool waitRx(nn_tcp_t *pSock, nn_ms_t start, nn_ms_t timeout)
{
    const nn_ms_t waited = nn_os_now() - start;
    nn_ms_t remaining;
    if(timeout != NN_FOREVER  &&  waited >= timeout)
        return false;
    remaining = timeout == NN_FOREVER ? NN_FOREVER : timeout - waited;
    pSock->rxWaiter = nn_os_self();
    pSock->flags |= NN_TCPF_RXWAIT;
    nn_unlock();
    (void)nn_os_notifyWait(remaining);
    nn_lock();
    return true;
}

nn_err_t nn_tcpAccept(nn_tcp_t *pListen, nn_tcp_t *pNew, nn_ms_t timeout)
{
    const nn_ms_t start = nn_os_now();
    nn_tcp_t **pp;
    nn_err_t rc;

    if(pListen == NULL  ||  pNew == NULL  ||  pNew->pRx == NULL  ||  pNew->pTx == NULL)
        return NN_ERR_INVAL;
    nn_lock();
    if(pListen->state != NN_TCP_LISTEN  ||  pNew->state != NN_TCP_CLOSED)
    {
        nn_unlock();
        return NN_ERR_INVAL;
    }
    pNew->pListener = pListen;
    pNew->pNext = NULL;
    for(pp=&pListen->pAcceptQ; *pp!=NULL; pp=&(*pp)->pNext)
        ;
    *pp = pNew;
    if(timeout == 0)
    {
        nn_unlock();
        return NN_ERR_PENDING;
    }
    for(;;)
    {
        if(pNew->state == NN_TCP_ESTABLISHED  ||  pNew->state == NN_TCP_CLOSE_WAIT)
        {
            rc = NN_OK;
            break;
        }
        if(pNew->state == NN_TCP_CLOSED  &&  pNew->pListener == NULL)
        {
            rc = pNew->err != NN_OK ? pNew->err : NN_ERR_CLOSED;   /* reset or listener closed */
            break;
        }
        if(!waitRx(pNew, start, timeout))
        {
            if(pNew->state == NN_TCP_CLOSED)
            {
                for(pp=&pListen->pAcceptQ; *pp!=NULL; pp=&(*pp)->pNext)
                    if(*pp == pNew) { *pp = pNew->pNext; break; }
                pNew->pListener = NULL;
                rc = NN_ERR_TIMEOUT;
            }
            else
                rc = NN_ERR_PENDING;                    /* handshake under way */
            break;
        }
    }
    nn_unlock();
    return rc;
}

nn_err_t nn_tcpConnect(nn_tcp_t *pSock, nn_ip4_t addr, uint16_t port, nn_ms_t timeout)
{
    const nn_ms_t start = nn_os_now();
    nn_iface_t *pIf;
    nn_ip4_t hop;
    nn_err_t rc = NN_OK;

    if(pSock == NULL  ||  pSock->pRx == NULL  ||  pSock->pTx == NULL  ||  port == 0)
        return NN_ERR_INVAL;
    nn_lock();
    if(pSock->state != NN_TCP_CLOSED)
        rc = NN_ERR_INVAL;
    else if((pIf = nn_ipRoute(addr, &hop)) == NULL)
        rc = NN_ERR_NODEV;
    else if(pSock->localPort == 0)
        rc = bindPort(pSock, nn_ip4(0, 0, 0, 0), 0);
    if(rc == NN_OK)
    {
        const nn_ip4_t local = nn_ip4IsAny(pSock->localAddr) ? pIf->addr : pSock->localAddr;
        initConnection(pSock, local, pSock->localPort, addr, port);
        pSock->pListener = NULL;
        pSock->state = NN_TCP_SYN_SENT;
        pSock->cwnd = (uint32_t)NN_CFG_TCP_IW * pSock->mss;
        link(pSock);
        ++ _stats.activeOpens;
        pSock->flags |= NN_TCPF_RTT;
        pSock->rttStart = nn_os_now();
        pSock->rttSeq = pSock->iss + 1;
        (void)sendSegment(pSock, NN_TCP_SYN, pSock->iss, 0, true);
        pSock->sndNxt = pSock->sndMax = pSock->iss + 1;
        startTimer(pSock);
        if(timeout == 0)
            rc = NN_ERR_PENDING;
        else
        {
            for(;;)
            {
                if(pSock->state == NN_TCP_ESTABLISHED  ||  pSock->state == NN_TCP_CLOSE_WAIT)
                    break;
                if(pSock->state == NN_TCP_CLOSED)
                {
                    rc = pSock->err;
                    break;
                }
                if(!waitRx(pSock, start, timeout))
                {
                    closeSocket(pSock, NN_ERR_TIMEOUT);
                    rc = NN_ERR_TIMEOUT;
                    break;
                }
            }
        }
    }
    nn_unlock();
    return rc;
}

static bool canSend(const nn_tcp_t *pS)
{
    return pS->state == NN_TCP_ESTABLISHED  ||  pS->state == NN_TCP_CLOSE_WAIT;
}

int32_t nn_tcpSend(nn_tcp_t *pSock, const void *p, size_t n, nn_ms_t timeout)
{
    const nn_ms_t start = nn_os_now();
    const uint8_t *pIn = p;
    size_t done = 0;
    int32_t rc = 0;

    if(pSock == NULL  ||  (p == NULL  &&  n != 0))
        return NN_ERR_INVAL;
    nn_lock();
    for(;;)
    {
        uint32_t space;
        if(!canSend(pSock))
        {
            rc = pSock->state == NN_TCP_CLOSED  &&  pSock->err != NN_OK ? pSock->err : NN_ERR_CLOSED;
            break;
        }
        space = (uint32_t)pSock->txSize - pSock->txLen;
        if(space != 0  &&  done < n)
        {
            const uint32_t chunk = minU32(space, (uint32_t)(n - done));
            uint32_t idx = ((uint32_t)pSock->txHead + pSock->txLen) % pSock->txSize;
            const uint32_t first = minU32(chunk, (uint32_t)pSock->txSize - idx);
            memcpy(pSock->pTx + idx, pIn + done, first);
            if(first < chunk)
                memcpy(pSock->pTx, pIn + done + first, chunk - first);
            pSock->txLen = (uint16_t)(pSock->txLen + chunk);
            done += chunk;
            output(pSock);
        }
        if(done == n)
        {
            rc = (int32_t)done;
            break;
        }
        {
            const nn_ms_t waited = nn_os_now() - start;
            nn_ms_t remaining;
            if(timeout != NN_FOREVER  &&  waited >= timeout)
            {
                rc = done != 0 ? (int32_t)done : NN_ERR_TIMEOUT;
                break;
            }
            remaining = timeout == NN_FOREVER ? NN_FOREVER : timeout - waited;
            pSock->txWaiter = nn_os_self();
            pSock->flags |= NN_TCPF_TXWAIT;
            nn_unlock();
            (void)nn_os_notifyWait(remaining);
            nn_lock();
        }
    }
    nn_unlock();
    return rc;
}

/** After the application took data: advertise the room when it is worth a segment. */
static void windowUpdate(nn_tcp_t *pS)
{
    const uint32_t edge = pS->rcvNxt + rcvWindow(pS);
    const uint32_t gain = edge - pS->rcvAdv;
    if(canSend(pS)  ||  pS->state == NN_TCP_FIN_WAIT_1  ||  pS->state == NN_TCP_FIN_WAIT_2)
        if(gain >= minU32(pS->mss, (uint32_t)pS->rxSize / 2u))
            sendAck(pS);
}

int32_t nn_tcpRecv(nn_tcp_t *pSock, void *p, size_t n, nn_ms_t timeout)
{
    const nn_ms_t start = nn_os_now();
    int32_t rc;

    if(pSock == NULL  ||  p == NULL  ||  n == 0)
        return NN_ERR_INVAL;
    nn_lock();
    for(;;)
    {
        if(pSock->rxLen != 0)
        {
            const uint32_t chunk = minU32(pSock->rxLen, (uint32_t)(n > 0xFFFFu ? 0xFFFFu : n));
            const uint32_t first = minU32(chunk, (uint32_t)pSock->rxSize - pSock->rxHead);
            memcpy(p, pSock->pRx + pSock->rxHead, first);
            if(first < chunk)
                memcpy((uint8_t *)p + first, pSock->pRx, chunk - first);
            pSock->rxHead = (uint16_t)(((uint32_t)pSock->rxHead + chunk) % pSock->rxSize);
            pSock->rxLen = (uint16_t)(pSock->rxLen - chunk);
            windowUpdate(pSock);
            rc = (int32_t)chunk;
            break;
        }
        if(pSock->flags & NN_TCPF_RXEOF)
        {
            rc = 0;
            break;
        }
        if(pSock->state == NN_TCP_CLOSED  ||  pSock->state == NN_TCP_LISTEN
           ||  pSock->state == NN_TCP_CLOSING  ||  pSock->state == NN_TCP_LAST_ACK)
        {
            rc = pSock->state == NN_TCP_CLOSED  &&  pSock->err != NN_OK ? pSock->err : NN_ERR_CLOSED;
            break;
        }
        if(!waitRx(pSock, start, timeout))
        {
            rc = NN_ERR_TIMEOUT;
            break;
        }
    }
    nn_unlock();
    return rc;
}

uint16_t nn_tcpAvailable(const nn_tcp_t *pSock)
{
    return pSock->rxLen;
}

uint16_t nn_tcpSendSpace(const nn_tcp_t *pSock)
{
    return canSend(pSock) ? (uint16_t)(pSock->txSize - pSock->txLen) : 0u;
}

static void abortConnection(nn_tcp_t *pS, nn_err_t err)
{
    if(pS->state >= NN_TCP_SYN_RCVD)
        (void)sendSegment(pS, NN_TCP_RST | NN_TCP_ACK, pS->sndNxt, 0, false);
    closeSocket(pS, err);
}

nn_err_t nn_tcpClose(nn_tcp_t *pSock)
{
    if(pSock == NULL)
        return NN_ERR_INVAL;
    nn_lock();
    switch(pSock->state)
    {
    case NN_TCP_CLOSED:
        if(pSock->pListener != NULL)                    /* withdraw an accept offer */
        {
            nn_tcp_t **pp;
            for(pp=&pSock->pListener->pAcceptQ; *pp!=NULL; pp=&(*pp)->pNext)
                if(*pp == pSock) { *pp = pSock->pNext; break; }
            pSock->pListener = NULL;
        }
        break;
    case NN_TCP_LISTEN:
        while(pSock->pAcceptQ != NULL)
        {
            nn_tcp_t * const pQ = pSock->pAcceptQ;
            pSock->pAcceptQ = pQ->pNext;
            pQ->pNext = NULL;
            pQ->pListener = NULL;
            pQ->err = NN_ERR_CLOSED;
            wakeRx(pQ);
        }
        closeSocket(pSock, NN_OK);
        break;
    case NN_TCP_SYN_SENT:
        closeSocket(pSock, NN_OK);
        break;
    case NN_TCP_SYN_RCVD:
    case NN_TCP_ESTABLISHED:
        if(pSock->rxLen != 0  ||  pSock->oooLen != 0)
            abortConnection(pSock, NN_OK);              /* unread data: RFC says reset */
        else
        {
            pSock->state = NN_TCP_FIN_WAIT_1;
            output(pSock);
        }
        break;
    case NN_TCP_CLOSE_WAIT:
        if(pSock->rxLen != 0)
            abortConnection(pSock, NN_OK);
        else
        {
            pSock->state = NN_TCP_LAST_ACK;
            output(pSock);
        }
        break;
    default:
        break;                                          /* already closing */
    }
    nn_unlock();
    return NN_OK;
}

nn_err_t nn_tcpAbort(nn_tcp_t *pSock)
{
    if(pSock == NULL)
        return NN_ERR_INVAL;
    nn_lock();
    if(pSock->state == NN_TCP_LISTEN  ||  pSock->state == NN_TCP_CLOSED)
    {
        nn_unlock();
        return nn_tcpClose(pSock);
    }
    abortConnection(pSock, NN_OK);
    nn_unlock();
    return NN_OK;
}

uint8_t nn_tcpState(const nn_tcp_t *pSock)
{
    return pSock->state;
}

const char *nn_tcpStateName(uint8_t state)
{
    static const char * const names[] =
    { "CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD", "ESTABLISHED", "FIN_WAIT_1", "FIN_WAIT_2",
      "CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT" };
    return state <= NN_TCP_TIME_WAIT ? names[state] : "?";
}

void nn_tcpSetNoDelay(nn_tcp_t *pSock, bool noDelay)
{
    nn_lock();
    if(noDelay)
        pSock->flags |= NN_TCPF_NODELAY;
    else
        pSock->flags &= (uint16_t)~NN_TCPF_NODELAY;
    if(noDelay)
        output(pSock);
    nn_unlock();
}

void nn_tcpOnEvent(nn_tcp_t *pSock, nn_tcpEventFunc_t fn, void *arg)
{
    nn_lock();
    pSock->onEvent = fn;
    pSock->cbArg = arg;
    nn_unlock();
}

void nn_tcpGetStats(nn_tcpStats_t *pStats)
{
    *pStats = _stats;
}
