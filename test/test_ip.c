/**
 * @file test_ip.c
 * Pure unit test (POSIX OS layer, frames fed straight into nn_net_input, transmitted
 * frames captured from a fake device): checksum, IPv4 header validation, routing and
 * delivery, ARP request/reply/learning/pending/retry/timeout, ICMP echo both ways and
 * destination unreachable.
 */

#include <string.h>

#include "nn_net.h"
#include "nn_eth.h"
#include "nn_ip.h"
#include "nn_arp.h"
#include "nn_icmp.h"
#include "nn_cksum.h"
#include "nn_timer.h"
#include "nn_os.h"
#include "testutil.h"

static const uint8_t _ourMac[6]  = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
static const uint8_t _peerMac[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };
static const uint8_t _gwMac[6]   = { 0x02, 0x00, 0x00, 0x00, 0x00, 0xFE };
static const nn_ip4_t _ourIp  = NN_IP4_INIT(10, 0, 77, 2);
static const nn_ip4_t _peerIp = NN_IP4_INIT(10, 0, 77, 1);
static const nn_ip4_t _gwIp   = NN_IP4_INIT(10, 0, 77, 254);
static const nn_ip4_t _farIp  = NN_IP4_INIT(8, 8, 8, 8);
static const nn_ip4_t _mask   = NN_IP4_INIT(255, 255, 255, 0);

static nn_netdev_t _dev;
static nn_iface_t _if;

/* Captured transmissions: a small FIFO of buffers the test frees. */
static nn_buf_t *_tx[8];
static unsigned _nTx;

static nn_err_t fakeTransmit(nn_netdev_t *pDev, nn_buf_t *pB)
{
    (void)pDev;
    if(_nTx < 8)
        _tx[_nTx++] = pB;
    else
        nn_bufFree(pB);
    return NN_OK;
}

static const nn_netdevOps_t _ops = { NULL, NULL, fakeTransmit };

static void clearTx(void)
{
    unsigned i;
    for(i=0; i<_nTx; ++i)
        nn_bufFree(_tx[i]);
    _nTx = 0;
}

/* --- Frame builders -------------------------------------------------------------------- */

static nn_buf_t *ethFrame(const uint8_t *dst, const uint8_t *src, uint16_t type)
{
    nn_buf_t *pB = nn_bufAlloc(NN_CFG_RX_OFFSET);
    nn_ethHdr_t *pH = (nn_ethHdr_t *)nn_bufPut(pB, NN_ETH_HDR_LEN);
    nn_macCopy(pH->dst, dst);
    nn_macCopy(pH->src, src);
    nn_put16(pH->type, type);
    pB->pDev = &_dev;
    return pB;
}

static uint8_t *ipHeader(nn_buf_t *pB, nn_ip4_t src, nn_ip4_t dst, uint8_t proto, uint16_t payloadLen)
{
    uint8_t *p = nn_bufPut(pB, NN_IP_HDR_LEN);
    memset(p, 0, NN_IP_HDR_LEN);
    p[0] = 0x45;
    nn_put16(p + 2, (uint16_t)(NN_IP_HDR_LEN + payloadLen));
    nn_put16(p + 4, 0x1234);
    p[8] = 64;
    p[9] = proto;
    memcpy(p + 12, src.b, 4);
    memcpy(p + 16, dst.b, 4);
    nn_put16(p + 10, nn_cksum(p, NN_IP_HDR_LEN));
    return p;
}

static nn_buf_t *arpFrame(uint16_t op, const uint8_t *srcMac, nn_ip4_t srcIp, const uint8_t *dstMac, nn_ip4_t dstIp)
{
    nn_buf_t *pB = ethFrame(op == 1 ? nn_eth_broadcast : _ourMac, srcMac, NN_ETH_TYPE_ARP);
    uint8_t *p = nn_bufPut(pB, 28);
    nn_put16(p, 1); nn_put16(p + 2, 0x0800); p[4] = 6; p[5] = 4; nn_put16(p + 6, op);
    nn_macCopy(p + 8, srcMac); memcpy(p + 14, srcIp.b, 4);
    nn_macCopy(p + 18, dstMac); memcpy(p + 24, dstIp.b, 4);
    return pB;
}

static nn_buf_t *echoFrame(nn_ip4_t src, nn_ip4_t dst, const uint8_t *dstMac, uint8_t type, uint16_t id, uint16_t seq, uint16_t n)
{
    nn_buf_t *pB = ethFrame(dstMac, _peerMac, NN_ETH_TYPE_IP);
    uint8_t *p;
    uint16_t i;
    ipHeader(pB, src, dst, NN_IP_PROTO_ICMP, (uint16_t)(8 + n));
    p = nn_bufPut(pB, (uint16_t)(8 + n));
    p[0] = type; p[1] = 0; p[2] = p[3] = 0;
    nn_put16(p + 4, id); nn_put16(p + 6, seq);
    for(i=0; i<n; ++i) p[8 + i] = (uint8_t)(i * 3);
    nn_put16(p + 2, nn_cksum(p, (uint16_t)(8 + n)));
    return pB;
}

static const uint8_t *ipOf(const nn_buf_t *pB) { return pB->pData + NN_ETH_HDR_LEN; }

/* --- Tests ------------------------------------------------------------------------------ */

static void testCksum(void)
{
    /* RFC 1071 example: 00 01 f2 03 f4 f5 f6 f7 -> sum ddf2, checksum 220d */
    static const uint8_t d[] = { 0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7 };
    static const uint8_t odd[] = { 0x01, 0x02, 0x03 };
    uint8_t hdr[20];
    CHECK_EQ(nn_cksum(d, 8), 0x220d);
    CHECK_EQ(nn_cksumFinish(nn_cksumAdd(nn_cksumAdd(0, d, 4), d + 4, 4)), 0x220d);
    CHECK_EQ(nn_cksum(odd, 3), (uint16_t)~(0x0102u + 0x0300u));
    memset(hdr, 0x11, 20);
    nn_put16(hdr + 10, 0);
    nn_put16(hdr + 10, nn_cksum(hdr, 20));
    CHECK_EQ(nn_cksum(hdr, 20), 0);
}

static void testAddr(void)
{
    char s[16];
    nn_ip4_t a;
    CHECK(strcmp(nn_ip4ToStr(s, nn_ip4(10, 0, 77, 254)), "10.0.77.254") == 0);
    CHECK(strcmp(nn_ip4ToStr(s, nn_ip4(0, 0, 0, 0)), "0.0.0.0") == 0);
    CHECK(nn_ip4Parse("192.168.1.100", &a)  &&  nn_ip4Equal(a, nn_ip4(192, 168, 1, 100)));
    CHECK(!nn_ip4Parse("256.1.1.1", &a));
    CHECK(!nn_ip4Parse("1.2.3", &a));
    CHECK(!nn_ip4Parse("1.2.3.4.5", &a));
    CHECK(nn_ip4SameNet(_ourIp, _peerIp, _mask)  &&  !nn_ip4SameNet(_ourIp, _farIp, _mask));
}

static void testRouting(void)
{
    nn_ip4_t hop;
    nn_iface_t *pIf;
    pIf = nn_ipRoute(_peerIp, &hop);
    CHECK(pIf == &_if  &&  nn_ip4Equal(hop, _peerIp));
    pIf = nn_ipRoute(_farIp, &hop);
    CHECK(pIf == &_if  &&  nn_ip4Equal(hop, _gwIp));
    pIf = nn_ipRoute(nn_ip4(255, 255, 255, 255), &hop);
    CHECK(pIf == &_if);
    pIf = nn_ipRoute(_ourIp, &hop);
    CHECK(pIf == NULL);                /* no loopback device registered here */
    CHECK(nn_ipIsLocal(_ourIp)  &&  !nn_ipIsLocal(_peerIp));
    CHECK(nn_ifaceOnDevFor(&_dev, _peerIp) == &_if);
}

static void testArp(void)
{
    nn_arpStats_t st;
    nn_buf_t *pB;
    uint8_t mac[6];
    const uint8_t *p;
    unsigned i;

    /* Request for us: reply unicast to the asker, asker learnt. */
    nn_net_input(arpFrame(1, _peerMac, _peerIp, (const uint8_t *)"\0\0\0\0\0\0", _ourIp));
    CHECK_EQ(_nTx, 1);
    p = ipOf(_tx[0]);
    CHECK(nn_macEqual(_tx[0]->pData, _peerMac));           /* eth dst */
    CHECK_EQ(nn_get16(p + 6), 2);                           /* reply */
    CHECK(nn_macEqual(p + 8, _ourMac)  &&  memcmp(p + 14, _ourIp.b, 4) == 0);
    CHECK(nn_macEqual(p + 18, _peerMac)  &&  memcmp(p + 24, _peerIp.b, 4) == 0);
    CHECK(nn_arpLookup(_peerIp, mac)  &&  nn_macEqual(mac, _peerMac));
    clearTx();

    /* Request for someone else: ignored, not learnt. */
    nn_net_input(arpFrame(1, _gwMac, _gwIp, (const uint8_t *)"\0\0\0\0\0\0", nn_ip4(10, 0, 77, 9)));
    CHECK_EQ(_nTx, 0);
    CHECK(!nn_arpLookup(_gwIp, mac));

    /* Output to an unknown host: parked, request sent. A second packet replaces it. */
    pB = nn_bufAlloc(NN_CFG_TX_HEADROOM);
    nn_bufPut(pB, 10);
    CHECK_EQ(nn_ip_output(pB, nn_ip4(0, 0, 0, 0), _farIp, 200, 64), NN_OK);
    CHECK_EQ(_nTx, 1);
    p = ipOf(_tx[0]);
    CHECK_EQ(nn_get16(ipOf(_tx[0]) - 2), NN_ETH_TYPE_ARP);
    CHECK_EQ(nn_get16(p + 6), 1);
    CHECK(memcmp(p + 24, _gwIp.b, 4) == 0  &&  memcmp(p + 14, _ourIp.b, 4) == 0);
    CHECK(nn_macIsBroadcast(_tx[0]->pData));
    clearTx();
    pB = nn_bufAlloc(NN_CFG_TX_HEADROOM);
    nn_bufPut(pB, 20);
    CHECK_EQ(nn_ip_output(pB, nn_ip4(0, 0, 0, 0), _farIp, 201, 64), NN_OK);
    CHECK_EQ(_nTx, 0);                                      /* no second request yet */
    nn_arpGetStats(&st);
    CHECK_EQ(st.pendingReplaced, 1);

    /* The reply arrives: the parked packet goes out to the gateway's MAC. */
    nn_net_input(arpFrame(2, _gwMac, _gwIp, _ourMac, _ourIp));
    CHECK_EQ(_nTx, 1);
    CHECK(nn_macEqual(_tx[0]->pData, _gwMac));
    CHECK_EQ(nn_get16(ipOf(_tx[0]) - 2), NN_ETH_TYPE_IP);
    CHECK_EQ(ipOf(_tx[0])[9], 201);
    CHECK_EQ(nn_get16(ipOf(_tx[0]) + 2), 40);
    CHECK(memcmp(ipOf(_tx[0]) + 16, _farIp.b, 4) == 0);
    CHECK_EQ(nn_get16(ipOf(_tx[0]) + 6), 0x4000);           /* DF */
    CHECK_EQ(nn_cksum(ipOf(_tx[0]), 20), 0);
    clearTx();

    /* Resolved now: direct. */
    pB = nn_bufAlloc(NN_CFG_TX_HEADROOM);
    nn_bufPut(pB, 4);
    CHECK_EQ(nn_ip_output(pB, nn_ip4(0, 0, 0, 0), _farIp, 202, 64), NN_OK);
    CHECK_EQ(_nTx, 1);
    CHECK(nn_macEqual(_tx[0]->pData, _gwMac));
    clearTx();

    /* Unanswered: retries then timeout frees the parked packet. */
    pB = nn_bufAlloc(NN_CFG_TX_HEADROOM);
    nn_bufPut(pB, 4);
    CHECK_EQ(nn_ip_output(pB, nn_ip4(0, 0, 0, 0), nn_ip4(10, 0, 77, 77), 203, 64), NN_OK);
    CHECK_EQ(_nTx, 1);
    clearTx();
    for(i=0; i<NN_CFG_ARP_RETRIES + 1; ++i)
    {
        /* Pretend a second passed, then run the timers as the net task would. */
        nn_os_testAdvance(NN_CFG_ARP_RETRY_MS);
        nn_timer_run();
    }
    CHECK_EQ(_nTx, NN_CFG_ARP_RETRIES);
    clearTx();
    nn_arpGetStats(&st);
    CHECK_EQ(st.timeouts, 1);
    CHECK_EQ(st.rxBad, 0);
    {
        nn_bufStats_t bs;
        nn_bufGetStats(&bs);
        CHECK_EQ(bs.free, NN_CFG_NUM_BUFS);
    }
    /* Malformed ARP. */
    pB = arpFrame(1, _peerMac, _peerIp, _ourMac, _ourIp);
    nn_bufTrim(pB, NN_ETH_HDR_LEN + 20);
    nn_net_input(pB);
    pB = arpFrame(1, _peerMac, _peerIp, _ourMac, _ourIp);
    pB->pData[NN_ETH_HDR_LEN + 4] = 8;                      /* hlen */
    nn_net_input(pB);
    nn_arpGetStats(&st);
    CHECK_EQ(st.rxBad, 2);
    CHECK_EQ(_nTx, 0);
}

static unsigned _nReplies;
static uint16_t _lastSeq, _lastLen;
static void onReply(nn_ip4_t from, uint16_t id, uint16_t seq, const uint8_t *p, uint16_t len, void *arg)
{
    (void)arg;
    CHECK(nn_ip4Equal(from, _peerIp));
    CHECK_EQ(id, 0xBEEF);
    CHECK(len == 0  ||  p[1] == 3);
    _lastSeq = seq;
    _lastLen = len;
    ++ _nReplies;
}

static void testIpAndIcmp(void)
{
    nn_ipStats_t ist;
    nn_icmpStats_t cst;
    nn_buf_t *pB;
    uint8_t *p;
    const uint8_t *q;

    /* Echo request to us: reply, in place, checksums right, payload intact. */
    pB = echoFrame(_peerIp, _ourIp, _ourMac, NN_ICMP_ECHO_REQUEST, 0x1234, 7, 32);
    nn_net_input(pB);
    CHECK_EQ(_nTx, 1);
    CHECK(_tx[0] == pB);
    q = ipOf(_tx[0]);
    CHECK(nn_macEqual(_tx[0]->pData, _peerMac));
    CHECK_EQ(nn_cksum(q, 20), 0);
    CHECK(memcmp(q + 12, _ourIp.b, 4) == 0  &&  memcmp(q + 16, _peerIp.b, 4) == 0);
    CHECK_EQ(nn_get16(q + 2), 20 + 8 + 32);
    CHECK_EQ(q[20], NN_ICMP_ECHO_REPLY);
    CHECK_EQ(nn_cksum(q + 20, 40), 0);
    CHECK_EQ(nn_get16(q + 24), 0x1234);
    CHECK_EQ(nn_get16(q + 26), 7);
    CHECK_EQ(q[28 + 5], 15);
    clearTx();

    /* Link padding beyond the IP total length is trimmed before the ICMP checksum. */
    pB = echoFrame(_peerIp, _ourIp, _ourMac, NN_ICMP_ECHO_REQUEST, 1, 1, 0);
    memset(nn_bufPut(pB, 18), 0xEE, 18);
    nn_net_input(pB);
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(_tx[0]->len, NN_ETH_MIN_FRAME);
    CHECK_EQ(nn_get16(ipOf(_tx[0]) + 2), 28);
    clearTx();

    /* Broadcast ping: no answer. Wrong destination: not for us. */
    pB = echoFrame(_peerIp, nn_ip4(10, 0, 77, 255), nn_eth_broadcast, NN_ICMP_ECHO_REQUEST, 1, 2, 0);
    nn_net_input(pB);
    pB = echoFrame(_peerIp, nn_ip4(10, 0, 77, 9), _ourMac, NN_ICMP_ECHO_REQUEST, 1, 3, 0);
    nn_net_input(pB);
    CHECK_EQ(_nTx, 0);
    nn_ipGetStats(&ist);
    CHECK_EQ(ist.rxNotForUs, 1);
    nn_icmpGetStats(&cst);
    CHECK_EQ(cst.rxEchoRequests, 3);
    CHECK_EQ(cst.txEchoReplies, 2);

    /* Bad IP checksum, bad version, short total length, fragment, IHL too small, bad ICMP checksum. */
    pB = echoFrame(_peerIp, _ourIp, _ourMac, NN_ICMP_ECHO_REQUEST, 1, 4, 0);
    pB->pData[NN_ETH_HDR_LEN + 8] = 1;                      /* ttl changed */
    nn_net_input(pB);
    pB = echoFrame(_peerIp, _ourIp, _ourMac, NN_ICMP_ECHO_REQUEST, 1, 4, 0);
    pB->pData[NN_ETH_HDR_LEN] = 0x65;
    nn_net_input(pB);
    pB = echoFrame(_peerIp, _ourIp, _ourMac, NN_ICMP_ECHO_REQUEST, 1, 4, 0);
    nn_bufTrim(pB, NN_ETH_HDR_LEN + 24);
    nn_net_input(pB);
    pB = echoFrame(_peerIp, _ourIp, _ourMac, NN_ICMP_ECHO_REQUEST, 1, 4, 0);
    p = pB->pData + NN_ETH_HDR_LEN;
    nn_put16(p + 6, 0x2000); nn_put16(p + 10, 0); nn_put16(p + 10, nn_cksum(p, 20));
    nn_net_input(pB);
    pB = echoFrame(_peerIp, _ourIp, _ourMac, NN_ICMP_ECHO_REQUEST, 1, 4, 0);
    p = pB->pData + NN_ETH_HDR_LEN;
    p[0] = 0x44; nn_put16(p + 10, 0); nn_put16(p + 10, nn_cksum(p, 20));
    nn_net_input(pB);
    pB = echoFrame(_peerIp, _ourIp, _ourMac, NN_ICMP_ECHO_REQUEST, 1, 4, 8);
    pB->pData[NN_ETH_HDR_LEN + 20 + 9] ^= 0xFF;
    nn_net_input(pB);
    CHECK_EQ(_nTx, 0);
    nn_ipGetStats(&ist);
    CHECK_EQ(ist.rxBadChecksum, 1);
    CHECK_EQ(ist.rxBadHeader, 3);
    CHECK_EQ(ist.rxFragments, 1);
    nn_icmpGetStats(&cst);
    CHECK_EQ(cst.rxBad, 1);

    /* Unknown IP protocol: counted (no ICMP error for now). */
    pB = ethFrame(_ourMac, _peerMac, NN_ETH_TYPE_IP);
    ipHeader(pB, _peerIp, _ourIp, 99, 4);
    memset(nn_bufPut(pB, 4), 0, 4);
    nn_net_input(pB);
    nn_ipGetStats(&ist);
    CHECK_EQ(ist.rxNoProto, 1);

    /* Our echo request and the peer's reply. */
    nn_icmpOnEchoReply(onReply, NULL);
    CHECK_EQ(nn_icmpEchoRequest(_peerIp, 0xBEEF, 1, NULL, 56), NN_OK);
    CHECK_EQ(_nTx, 1);
    q = ipOf(_tx[0]);
    CHECK(nn_macEqual(_tx[0]->pData, _peerMac));           /* resolved in testArp */
    CHECK_EQ(q[9], NN_IP_PROTO_ICMP);
    CHECK_EQ(q[20], NN_ICMP_ECHO_REQUEST);
    CHECK_EQ(nn_cksum(q + 20, 64), 0);
    CHECK_EQ(nn_get16(q + 24), 0xBEEF);
    CHECK_EQ(q[28 + 10], 10);
    clearTx();
    nn_net_input(echoFrame(_peerIp, _ourIp, _ourMac, NN_ICMP_ECHO_REPLY, 0xBEEF, 1, 56));
    CHECK_EQ(_nReplies, 1);
    CHECK_EQ(_lastSeq, 1);
    CHECK_EQ(_lastLen, 56);
    nn_net_input(echoFrame(_peerIp, _ourIp, _ourMac, NN_ICMP_ECHO_REPLY, 0xBEEF, 2, 0));
    CHECK_EQ(_nReplies, 2);
    CHECK_EQ(_lastLen, 0);

    /* Destination unreachable about a UDP packet: quotes IP header + 8 bytes. */
    pB = ethFrame(_ourMac, _peerMac, NN_ETH_TYPE_IP);
    ipHeader(pB, _peerIp, _ourIp, NN_IP_PROTO_UDP, 12);
    p = nn_bufPut(pB, 12);
    memset(p, 0x77, 12);
    nn_bufPull(pB, NN_ETH_HDR_LEN);
    CHECK_EQ(nn_icmp_sendError(pB, NN_ICMP_UNREACHABLE, NN_ICMP_UNREACH_PORT), NN_OK);
    CHECK_EQ(_nTx, 1);
    q = ipOf(_tx[0]);
    CHECK(memcmp(q + 16, _peerIp.b, 4) == 0);
    CHECK_EQ(nn_get16(q + 2), 20 + 8 + 28);
    CHECK(q[20] == NN_ICMP_UNREACHABLE  &&  q[21] == NN_ICMP_UNREACH_PORT);
    CHECK_EQ(nn_cksum(q + 20, 36), 0);
    CHECK(memcmp(q + 28, pB->pData, 28) == 0);
    CHECK_EQ(q[28 + 20], 0x77);
    clearTx();
    /* Not about broadcasts, not about ICMP errors. */
    pB->flags |= NN_BUF_BCAST;
    CHECK_EQ(nn_icmp_sendError(pB, NN_ICMP_UNREACHABLE, 3), NN_ERR_INVAL);
    pB->flags = 0;
    pB->pData[9] = NN_IP_PROTO_ICMP;
    pB->pData[20] = NN_ICMP_UNREACHABLE;
    CHECK_EQ(nn_icmp_sendError(pB, NN_ICMP_UNREACHABLE, 3), NN_ERR_INVAL);
    nn_bufFree(pB);
    CHECK_EQ(_nTx, 0);

    /* Unroutable: no interface for 192.168.x without a gateway... we have one, so take
       the gateway away and check. */
    _if.gw = nn_ip4(0, 0, 0, 0);
    pB = nn_bufAlloc(NN_CFG_TX_HEADROOM);
    nn_bufPut(pB, 4);
    CHECK_EQ(nn_ip_output(pB, nn_ip4(0, 0, 0, 0), _farIp, 200, 64), NN_ERR_NODEV);
    _if.gw = _gwIp;
    /* No headroom for the IP header. */
    pB = nn_bufAlloc(8);
    nn_bufPut(pB, 4);
    CHECK_EQ(nn_ip_output(pB, nn_ip4(0, 0, 0, 0), _peerIp, 200, 64), NN_ERR_NOMEM);
    nn_ipGetStats(&ist);
    CHECK_EQ(ist.txNoRoute, 1);
    CHECK_EQ(ist.txNoHeadroom, 1);
    {
        nn_bufStats_t bs;
        nn_bufGetStats(&bs);
        CHECK_EQ(bs.free, NN_CFG_NUM_BUFS);
    }
}

int main(void)
{
    nn_bufStats_t bs;

    nn_os_testFreeze(true);                             /* timers move only by nn_os_testAdvance */
    nn_os_testAdvance(1000);
    CHECK_EQ(nn_init(), NN_OK);
    memset(&_dev, 0, sizeof(_dev));
    _dev.name = "fake";
    _dev.type = NN_DEV_ETHERNET;
    _dev.flags = NN_DEVF_LINK | NN_DEVF_BROADCAST;
    _dev.hwlen = 6;
    nn_macCopy(_dev.hwaddr, _ourMac);
    _dev.mtu = 1500;
    _dev.pOps = &_ops;
    CHECK_EQ(nn_netdevRegister(&_dev), NN_OK);
    CHECK_EQ(nn_ifaceAdd(&_dev, &_if, _ourIp, _mask, _gwIp), NN_OK);
    CHECK_EQ(nn_ifaceAdd(&_dev, &_if, _ourIp, _mask, _gwIp), NN_ERR_EXIST);

    nn_lock();
    testCksum();
    testAddr();
    testRouting();
    testArp();
    testIpAndIcmp();
    nn_bufGetStats(&bs);
    CHECK_EQ(bs.free, NN_CFG_NUM_BUFS);
    CHECK_EQ(bs.allocFailed, 0);
    nn_unlock();
    test_finish("test_ip");
    return 0;
}
