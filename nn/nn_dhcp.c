/**
 * @file nn_dhcp.c
 * DHCP client. Messages are built in a packet buffer and sent through a UDP socket on
 * port 68; replies arrive via the socket's readable callback in the net task. One timer
 * drives retransmission with doubling intervals and the lease clock.
 *
 * The BROADCAST flag is set in every message sent without an address, so servers that
 * honour it broadcast the reply; servers that unicast to the offered address are handled
 * by nn_ip_input, which accepts unicast UDP on an interface that has no address yet.
 */

#include <string.h>

#include "nn_dhcp.h"
#include "nn_dns.h"
#include "nn_net.h"
#include "nn_os.h"

#define PORT_SERVER     67u
#define PORT_CLIENT     68u
#define MAGIC           0x63825363ul

#define OP_REQUEST      1u
#define OP_REPLY        2u
#define MSG_DISCOVER    1u
#define MSG_OFFER       2u
#define MSG_REQUEST     3u
#define MSG_DECLINE     4u
#define MSG_ACK         5u
#define MSG_NAK         6u
#define MSG_RELEASE     7u

#define OPT_PAD         0u
#define OPT_MASK        1u
#define OPT_ROUTER      3u
#define OPT_DNS         6u
#define OPT_HOSTNAME    12u
#define OPT_REQ_IP      50u
#define OPT_LEASE       51u
#define OPT_MSG_TYPE    53u
#define OPT_SERVER_ID   54u
#define OPT_PARAM_LIST  55u
#define OPT_T1          58u
#define OPT_T2          59u
#define OPT_CLIENT_ID   61u
#define OPT_END         255u

#define HDR_LEN         240u    /* fixed fields + magic */
#define FIRST_RETRY_MS  2000ul
#define MAX_RETRY_MS    64000ul

static void setState(nn_dhcp_t *pD, uint8_t state)
{
    pD->state = state;
}

static uint8_t *putOpt(uint8_t *p, uint8_t code, uint8_t len, const void *data)
{
    *p++ = code;
    *p++ = len;
    memcpy(p, data, len);
    return p + len;
}

static nn_err_t sendMessage(nn_dhcp_t *pD, uint8_t type, bool toServer)
{
    nn_buf_t *pB = nn_bufAlloc(NN_CFG_TX_HEADROOM);
    uint8_t *p, *pOpt;
    uint8_t clientId[1 + NN_ETH_ALEN];
    static const uint8_t paramList[] = { OPT_MASK, OPT_ROUTER, OPT_DNS };
    nn_ip4_t dst;

    if(pB == NULL)
        return NN_ERR_NOMEM;
    p = nn_bufPut(pB, HDR_LEN);
    memset(p, 0, HDR_LEN);
    p[0] = OP_REQUEST;
    p[1] = 1;                               /* Ethernet */
    p[2] = NN_ETH_ALEN;
    nn_put32(p + 4, pD->xid);
    nn_put16(p + 8, (uint16_t)((nn_os_now() - pD->started) / 1000u));
    if(pD->state < NN_DHCP_BOUND)
        nn_put16(p + 10, 0x8000u);          /* BROADCAST */
    if(pD->state >= NN_DHCP_BOUND)
        memcpy(p + 12, pD->pIf->addr.b, 4); /* ciaddr */
    memcpy(p + 28, pD->pIf->pDev->hwaddr, NN_ETH_ALEN);
    nn_put32(p + 236, MAGIC);

    pOpt = nn_bufPut(pB, 64);
    p = pOpt;
    p = putOpt(p, OPT_MSG_TYPE, 1, &type);
    clientId[0] = 1;
    nn_macCopy(clientId + 1, pD->pIf->pDev->hwaddr);
    p = putOpt(p, OPT_CLIENT_ID, (uint8_t)sizeof(clientId), clientId);
    if(type == MSG_REQUEST  &&  pD->state == NN_DHCP_REQUESTING)
    {
        p = putOpt(p, OPT_REQ_IP, 4, pD->offered.b);
        p = putOpt(p, OPT_SERVER_ID, 4, pD->server.b);
    }
    if(type == MSG_RELEASE)
        p = putOpt(p, OPT_SERVER_ID, 4, pD->server.b);
    if(type == MSG_DISCOVER  ||  type == MSG_REQUEST)
    {
        p = putOpt(p, OPT_PARAM_LIST, (uint8_t)sizeof(paramList), paramList);
#ifdef NN_CFG_DHCP_HOSTNAME
        if(NN_CFG_DHCP_HOSTNAME != NULL  &&  strlen(NN_CFG_DHCP_HOSTNAME) <= 16)
            p = putOpt(p, OPT_HOSTNAME, (uint8_t)strlen(NN_CFG_DHCP_HOSTNAME), NN_CFG_DHCP_HOSTNAME);
#endif
    }
    *p++ = OPT_END;
    nn_bufTrim(pB, (uint16_t)(HDR_LEN + (p - pOpt)));
    /* BOOTP servers like a 300 byte minimum; pad. */
    if(pB->len < 300)
        memset(nn_bufPut(pB, (uint16_t)(300 - pB->len)), 0, (size_t)(300 - pB->len));

    dst = toServer ? pD->server : nn_ip4(255, 255, 255, 255);
    return nn_udp_sendBuf(&pD->sock, pB, dst, PORT_SERVER);
}

#define VERIFY_MS   1500u       /* between the REQUESTs after nn_dhcpLinkUp */

static void armRetry(nn_dhcp_t *pD)
{
    nn_ms_t ms = FIRST_RETRY_MS << (pD->retries > 5 ? 5 : pD->retries);
    if(ms > MAX_RETRY_MS)
        ms = MAX_RETRY_MS;
    nn_timerStart(&pD->timer, ms, 0);
}

static void discover(nn_dhcp_t *pD)
{
    setState(pD, NN_DHCP_SELECTING);
    ++ pD->discovers;
    sendMessage(pD, MSG_DISCOVER, false);
    armRetry(pD);
}

static void unbind(nn_dhcp_t *pD, bool notify)
{
    const bool wasBound = nn_dhcpIsBound(pD);
    nn_ifaceSetAddr(pD->pIf, nn_ip4(0, 0, 0, 0), nn_ip4(0, 0, 0, 0), nn_ip4(0, 0, 0, 0));
    setState(pD, NN_DHCP_INIT);
    if(wasBound  &&  notify  &&  pD->onChange != NULL)
        pD->onChange(pD, false, pD->cbArg);
}

static void restart(nn_dhcp_t *pD)
{
    unbind(pD, true);
    pD->retries = 0;
    pD->verifying = 0;
    pD->xid += 0x10001ul;
    pD->started = nn_os_now();
    discover(pD);
}

static void bound(nn_dhcp_t *pD)
{
    const bool wasBound = nn_dhcpIsBound(pD);
    nn_ifaceSetAddr(pD->pIf, pD->offered, pD->mask, pD->gw);
    if(!nn_ip4IsAny(pD->dns))
        nn_dnsSetServer(pD->dns);
    pD->boundAt = nn_os_now();
    setState(pD, NN_DHCP_BOUND);
    pD->retries = 0;
    pD->verifying = 0;
    nn_timerStart(&pD->timer, (nn_ms_t)(pD->t1S * 1000ul), 0);
    if(!wasBound  &&  pD->onChange != NULL)
        pD->onChange(pD, true, pD->cbArg);
}

static void timerCb(nn_timer_t *pT, void *arg)
{
    nn_dhcp_t * const pD = arg;
    (void)pT;

    switch(pD->state)
    {
    case NN_DHCP_SELECTING:
        ++ pD->retries;
        ++ pD->discovers;
        sendMessage(pD, MSG_DISCOVER, false);
        armRetry(pD);
        break;
    case NN_DHCP_REQUESTING:
        if(++pD->retries > 4)
            restart(pD);
        else
        {
            ++ pD->requests;
            sendMessage(pD, MSG_REQUEST, false);
            armRetry(pD);
        }
        break;
    case NN_DHCP_BOUND:
        setState(pD, NN_DHCP_RENEWING);
        ++ pD->requests;
        sendMessage(pD, MSG_REQUEST, true);
        nn_timerStart(&pD->timer, (nn_ms_t)((pD->t2S - pD->t1S) * 1000ul / 2u + 1000ul), 0);
        break;
    case NN_DHCP_RENEWING:
        if(nn_os_now() - pD->boundAt >= pD->t2S * 1000ul)
        {
            setState(pD, NN_DHCP_REBINDING);
            ++ pD->requests;
            sendMessage(pD, MSG_REQUEST, false);
            nn_timerStart(&pD->timer, (nn_ms_t)((pD->leaseS - pD->t2S) * 1000ul / 2u + 1000ul), 0);
        }
        else
        {
            ++ pD->requests;
            sendMessage(pD, MSG_REQUEST, true);
            nn_timerStart(&pD->timer, (nn_ms_t)((pD->t2S - pD->t1S) * 1000ul / 4u + 1000ul), 0);
        }
        break;
    case NN_DHCP_REBINDING:
        if(nn_os_now() - pD->boundAt >= pD->leaseS * 1000ul  ||  (pD->verifying  &&  ++pD->retries >= 3))
            restart(pD);                    /* lease expired, or unconfirmed after a link up */
        else
        {
            ++ pD->requests;
            sendMessage(pD, MSG_REQUEST, false);
            nn_timerStart(&pD->timer, pD->verifying ? VERIFY_MS : (nn_ms_t)((pD->leaseS - pD->t2S) * 1000ul / 4u + 1000ul), 0);
        }
        break;
    default:
        break;
    }
}

/** Parse a reply; returns the message type or 0 if it is not for us. */
static uint8_t parse(nn_dhcp_t *pD, const nn_buf_t *pB, nn_ip4_t *pYi, nn_ip4_t *pServer,
                     nn_ip4_t *pMask, nn_ip4_t *pGw, nn_ip4_t *pDns,
                     uint32_t *pLease, uint32_t *pT1, uint32_t *pT2)
{
    const uint8_t *p = pB->pData;
    const uint8_t * const pEnd = p + pB->len;
    uint8_t type = 0;

    if(pB->len < HDR_LEN  ||  p[0] != OP_REPLY  ||  nn_get32(p + 4) != pD->xid
       ||  nn_get32(p + 236) != MAGIC  ||  memcmp(p + 28, pD->pIf->pDev->hwaddr, NN_ETH_ALEN) != 0)
        return 0;
    memcpy(pYi->b, p + 16, 4);
    *pServer = *pMask = *pGw = *pDns = nn_ip4(0, 0, 0, 0);
    *pLease = *pT1 = *pT2 = 0;

    p += HDR_LEN;
    while(p < pEnd  &&  *p != OPT_END)
    {
        uint8_t code = *p++, len;
        if(code == OPT_PAD)
            continue;
        if(p >= pEnd)
            return 0;
        len = *p++;
        if(p + len > pEnd)
            return 0;
        switch(code)
        {
        case OPT_MSG_TYPE:  if(len == 1) type = p[0]; break;
        case OPT_SERVER_ID: if(len == 4) memcpy(pServer->b, p, 4); break;
        case OPT_MASK:      if(len == 4) memcpy(pMask->b, p, 4); break;
        case OPT_ROUTER:    if(len >= 4) memcpy(pGw->b, p, 4); break;
        case OPT_DNS:       if(len >= 4) memcpy(pDns->b, p, 4); break;
        case OPT_LEASE:     if(len == 4) *pLease = nn_get32(p); break;
        case OPT_T1:        if(len == 4) *pT1 = nn_get32(p); break;
        case OPT_T2:        if(len == 4) *pT2 = nn_get32(p); break;
        default: break;
        }
        p += len;
    }
    return type;
}

static void onReadable(nn_udp_t *pSock, void *arg)
{
    nn_dhcp_t * const pD = arg;
    nn_buf_t *pB;

    while((pB = nn_udp_dequeue(pSock)) != NULL)
    {
        nn_ip4_t yi, server, mask, gw, dns;
        uint32_t lease, t1, t2;
        const uint8_t type = parse(pD, pB, &yi, &server, &mask, &gw, &dns, &lease, &t1, &t2);
        nn_bufFree(pB);

        if(type == MSG_OFFER  &&  pD->state == NN_DHCP_SELECTING)
        {
            ++ pD->offers;
            pD->offered = yi;
            pD->server = server;
            setState(pD, NN_DHCP_REQUESTING);
            pD->retries = 0;
            ++ pD->requests;
            sendMessage(pD, MSG_REQUEST, false);
            armRetry(pD);
        }
        else if(type == MSG_ACK  &&  pD->state >= NN_DHCP_REQUESTING)
        {
            ++ pD->acks;
            if(pD->state == NN_DHCP_REQUESTING)
                pD->offered = yi;
            pD->mask = nn_ip4IsAny(mask) ? nn_ip4(255, 255, 255, 0) : mask;
            pD->gw = gw;
            pD->dns = dns;
            pD->leaseS = lease == 0 ? 3600ul : lease;
            pD->t1S = (t1 != 0  &&  t1 < pD->leaseS) ? t1 : pD->leaseS / 2u;
            pD->t2S = (t2 != 0  &&  t2 < pD->leaseS  &&  t2 > pD->t1S) ? t2 : pD->leaseS * 7u / 8u;
            if(pD->t1S == 0) pD->t1S = 1;
            if(pD->t2S <= pD->t1S) pD->t2S = pD->t1S + 1;
            if(pD->leaseS <= pD->t2S) pD->leaseS = pD->t2S + 1;
            bound(pD);
        }
        else if(type == MSG_NAK  &&  pD->state >= NN_DHCP_REQUESTING)
        {
            ++ pD->naks;
            restart(pD);
        }
    }
}

void nn_dhcp_init(void)
{
}

nn_err_t nn_dhcpStart(nn_dhcp_t *pD, nn_iface_t *pIf, nn_dhcpChangeFunc_t fn, void *arg)
{
    nn_err_t rc;

    if(pD == NULL  ||  pIf == NULL)
        return NN_ERR_INVAL;
    memset(pD, 0, sizeof(*pD));
    pD->onChange = fn;
    pD->cbArg = arg;
    pD->pIf = pIf;
    nn_udpOpen(&pD->sock);
    nn_lock();
    rc = nn_udp_bind(&pD->sock, nn_ip4(0, 0, 0, 0), PORT_CLIENT);
    if(rc != NN_OK)
    {
        nn_unlock();
        return rc;
    }
    pD->sock.onReadable = onReadable;
    pD->sock.cbArg = pD;
    pD->sock.pIf = pIf;
    pIf->pDhcp = pD;
    nn_timerSetup(&pD->timer, timerCb, pD);
    pD->xid = (uint32_t)nn_os_now() ^ ((uint32_t)pIf->pDev->hwaddr[5] << 24) ^ ((uint32_t)pIf->pDev->hwaddr[4] << 16);
    pD->started = nn_os_now();
    unbind(pD, false);
    discover(pD);
    nn_unlock();
    return NN_OK;
}

nn_err_t nn_dhcpLinkUp(nn_dhcp_t *pD)
{
    if(pD == NULL  ||  pD->pIf == NULL)
        return NN_ERR_INVAL;
    nn_lock();
    if(nn_dhcpIsBound(pD))
    {
        setState(pD, NN_DHCP_REBINDING);
        pD->verifying = 1;
        pD->retries = 0;
        ++ pD->requests;
        sendMessage(pD, MSG_REQUEST, false);
        nn_timerStart(&pD->timer, VERIFY_MS, 0);
    }
    else
    {
        pD->retries = 0;
        pD->xid += 0x10001ul;
        pD->started = nn_os_now();
        discover(pD);
    }
    nn_unlock();
    return NN_OK;
}

nn_err_t nn_dhcpStop(nn_dhcp_t *pD)
{
    if(pD == NULL  ||  pD->pIf == NULL)
        return NN_ERR_INVAL;
    nn_lock();
    if(nn_dhcpIsBound(pD))
        sendMessage(pD, MSG_RELEASE, true);
    nn_timerStop(&pD->timer);
    unbind(pD, true);
    pD->pIf->pDhcp = NULL;
    nn_unlock();
    nn_udpClose(&pD->sock);
    return NN_OK;
}

uint8_t nn_dhcpState(const nn_dhcp_t *pD)
{
    return pD->state;
}
