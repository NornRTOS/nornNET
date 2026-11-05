/**
 * @file nn_icmp.c
 * ICMP. An echo request becomes its own reply in place: type changed, checksum adjusted
 * incrementally, addresses swapped by nn_ip_output.
 */

#include <string.h>

#include "nn_icmp.h"
#include "nn_net.h"
#include "nn_cksum.h"

static nn_icmpStats_t _stats;
static nn_icmpEchoReplyFunc_t _onEchoReply;
static void *_onEchoReplyArg;

static void input(nn_buf_t *pB, nn_iface_t *pIf, nn_ip4_t src, nn_ip4_t dst)
{
    uint8_t *p = pB->pData;
    (void)pIf;

    ++ _stats.rx;
    if(pB->len < 8  ||  nn_cksum(p, pB->len) != 0)
    {
        ++ _stats.rxBad;
        nn_bufFree(pB);
        return;
    }
    switch(p[0])
    {
    case NN_ICMP_ECHO_REQUEST:
        ++ _stats.rxEchoRequests;
        if(pB->flags & NN_BUF_BCAST)
        {
            nn_bufFree(pB);
            return;
        }
        {
            /* type 8 -> 0: the sum loses 0x0800, so the checksum gains it. */
            uint32_t sum = (uint32_t)nn_get16(p + 2) + 0x0800u;
            p[0] = NN_ICMP_ECHO_REPLY;
            sum = (sum & 0xFFFFu) + (sum >> 16);
            nn_put16(p + 2, (uint16_t)sum);
        }
        ++ _stats.txEchoReplies;
        nn_ip_output(pB, dst, src, NN_IP_PROTO_ICMP, NN_IP_DEFAULT_TTL);
        return;

    case NN_ICMP_ECHO_REPLY:
        ++ _stats.rxEchoReplies;
        if(_onEchoReply != NULL)
            _onEchoReply(src, nn_get16(p + 4), nn_get16(p + 6), p + 8, (uint16_t)(pB->len - 8), _onEchoReplyArg);
        break;

    case NN_ICMP_UNREACHABLE:
    case NN_ICMP_TIME_EXCEEDED:
        ++ _stats.rxErrors;
        break;

    default:
        ++ _stats.rxOther;
        break;
    }
    nn_bufFree(pB);
}

static nn_ipProto_t _proto = { NN_IP_PROTO_ICMP, "icmp", input, NULL
#if NN_CFG_STATS
    , 0
#endif
};

void nn_icmp_init(void)
{
    memset(&_stats, 0, sizeof(_stats));
    _onEchoReply = NULL;
    nn_ipProtoRegister(&_proto);
}

nn_err_t nn_icmpEchoRequest(nn_ip4_t dst, uint16_t id, uint16_t seq, const uint8_t *payload, uint16_t n)
{
    nn_buf_t *pB = nn_bufAlloc(NN_CFG_TX_HEADROOM);
    uint8_t *p;
    uint16_t i;

    if(pB == NULL)
        return NN_ERR_NOMEM;
    p = nn_bufPut(pB, (uint16_t)(8u + n));
    if(p == NULL)
    {
        nn_bufFree(pB);
        return NN_ERR_INVAL;
    }
    p[0] = NN_ICMP_ECHO_REQUEST;
    p[1] = 0;
    p[2] = p[3] = 0;
    nn_put16(p + 4, id);
    nn_put16(p + 6, seq);
    if(payload != NULL)
        memcpy(p + 8, payload, n);
    else
        for(i=0; i<n; ++i)
            p[8 + i] = (uint8_t)i;
    nn_put16(p + 2, nn_cksum(p, (uint16_t)(8u + n)));
    ++ _stats.txEchoRequests;
    return nn_ip_output(pB, nn_ip4(0, 0, 0, 0), dst, NN_IP_PROTO_ICMP, NN_IP_DEFAULT_TTL);
}

void nn_icmpOnEchoReply(nn_icmpEchoReplyFunc_t fn, void *arg)
{
    _onEchoReply = fn;
    _onEchoReplyArg = arg;
}

nn_err_t nn_icmp_sendError(const nn_buf_t *pOrig, uint8_t type, uint8_t code)
{
    const uint8_t * const pIp = pOrig->pData;
    uint16_t hlen, quote;
    nn_ip4_t src;
    nn_buf_t *pB;
    uint8_t *p;

    if(pOrig->len < NN_IP_HDR_LEN  ||  (pOrig->flags & (NN_BUF_BCAST | NN_BUF_MCAST)))
        return NN_ERR_INVAL;
    hlen = (uint16_t)((pIp[0] & 0x0Fu) * 4u);
    if(pIp[9] == NN_IP_PROTO_ICMP  &&  pOrig->len >= hlen + 1u  &&  pIp[hlen] != NN_ICMP_ECHO_REQUEST)
        return NN_ERR_INVAL;            /* never an error about an error */
    memcpy(src.b, pIp + 12, 4);
    if(nn_ip4IsAny(src)  ||  nn_ip4IsLimitedBroadcast(src)  ||  nn_ip4IsMulticast(src))
        return NN_ERR_INVAL;

    quote = (uint16_t)(hlen + 8u);
    if(quote > pOrig->len)
        quote = pOrig->len;
    pB = nn_bufAlloc(NN_CFG_TX_HEADROOM);
    if(pB == NULL)
        return NN_ERR_NOMEM;
    p = nn_bufPut(pB, (uint16_t)(8u + quote));
    p[0] = type;
    p[1] = code;
    memset(p + 2, 0, 6);
    memcpy(p + 8, pIp, quote);
    nn_put16(p + 2, nn_cksum(p, (uint16_t)(8u + quote)));
    ++ _stats.txErrors;
    return nn_ip_output(pB, nn_ip4(0, 0, 0, 0), src, NN_IP_PROTO_ICMP, NN_IP_DEFAULT_TTL);
}

void nn_icmpGetStats(nn_icmpStats_t *pStats)
{
    *pStats = _stats;
}
