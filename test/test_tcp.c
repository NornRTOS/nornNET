/**
 * @file test_tcp.c
 * Pure unit test of TCP (POSIX OS layer, synthetic segments in, transmitted segments
 * captured, time advanced by hand): the three way handshake both ways, data in both
 * directions, delayed and immediate ACKs, out of order data, Nagle, retransmission
 * timeout and backoff, fast retransmit, zero window probing, window updates, every
 * close sequence, TIME_WAIT, resets, refused and timed out connects, listener edge
 * cases, bad checksums and the buffer pool after it all.
 */

#include <string.h>

#include "nn_net.h"
#include "nn_eth.h"
#include "nn_ip.h"
#include "nn_tcp.h"
#include "nn_cksum.h"
#include "nn_timer.h"
#include "nn_os.h"
#include "testutil.h"

static const uint8_t _ourMac[6]  = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
static const uint8_t _peerMac[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };
static const nn_ip4_t _ourIp  = NN_IP4_INIT(10, 0, 77, 2);
static const nn_ip4_t _peerIp = NN_IP4_INIT(10, 0, 77, 1);
static const nn_ip4_t _mask   = NN_IP4_INIT(255, 255, 255, 0);

static nn_netdev_t _dev;
static nn_iface_t _if;
static nn_buf_t *_tx[12];
static unsigned _nTx;

static nn_err_t fakeTransmit(nn_netdev_t *pDev, nn_buf_t *pB)
{
    (void)pDev;
    if(_nTx < 12) _tx[_nTx++] = pB; else nn_bufFree(pB);
    return NN_OK;
}
static const nn_netdevOps_t _ops = { NULL, NULL, fakeTransmit };

static void clearTx(void)
{
    unsigned i;
    for(i=0; i<_nTx; ++i) nn_bufFree(_tx[i]);
    _nTx = 0;
}

/* --- Reading captured segments ---------------------------------------------------------- */

static const uint8_t *ipOf(const nn_buf_t *pB) { return pB->pData + NN_ETH_HDR_LEN; }
static const uint8_t *tcpOf(const nn_buf_t *pB) { return ipOf(pB) + (ipOf(pB)[0] & 0x0F) * 4; }
static uint8_t  segFlags(const nn_buf_t *pB) { return tcpOf(pB)[13] & 0x3F; }
static uint32_t segSeq(const nn_buf_t *pB)   { return nn_get32(tcpOf(pB) + 4); }
static uint32_t segAck(const nn_buf_t *pB)   { return nn_get32(tcpOf(pB) + 8); }
static uint16_t segWnd(const nn_buf_t *pB)   { return nn_get16(tcpOf(pB) + 14); }
static uint16_t segHdrLen(const nn_buf_t *pB) { return (uint16_t)((tcpOf(pB)[12] >> 4) * 4); }
static uint16_t segDataLen(const nn_buf_t *pB)
{
    return (uint16_t)(nn_get16(ipOf(pB) + 2) - (ipOf(pB)[0] & 0x0F) * 4 - segHdrLen(pB));
}
static const uint8_t *segData(const nn_buf_t *pB) { return tcpOf(pB) + segHdrLen(pB); }
static uint16_t segMssOption(const nn_buf_t *pB)
{
    const uint8_t *o = tcpOf(pB) + 20, *end = tcpOf(pB) + segHdrLen(pB);
    while(o < end && *o != 0)
    {
        if(*o == 1) { ++o; continue; }
        if(*o == 2 && o[1] == 4) return nn_get16(o + 2);
        o += o[1];
    }
    return 0;
}

/** True when the segment's TCP checksum verifies. */
static bool segChecksumOk(const nn_buf_t *pB)
{
    const uint8_t *ip = ipOf(pB);
    const uint16_t len = (uint16_t)(nn_get16(ip + 2) - (ip[0] & 0x0F) * 4);
    nn_ip4_t s, d;
    memcpy(s.b, ip + 12, 4); memcpy(d.b, ip + 16, 4);
    return nn_cksumFinish(nn_cksumAdd(nn_cksumPseudo(s, d, NN_IP_PROTO_TCP, len), tcpOf(pB), len)) == 0;
}

/* --- Building incoming segments --------------------------------------------------------- */

/** An incoming segment from the peer; \a mss != 0 adds the option. */
static nn_buf_t *segment(uint16_t sport, uint16_t dport, uint32_t seq, uint32_t ack, uint8_t flags,
                         uint16_t wnd, const void *payload, uint16_t n, uint16_t mss)
{
    nn_buf_t *pB = nn_bufAlloc(NN_CFG_RX_OFFSET);
    nn_ethHdr_t *pE = (nn_ethHdr_t *)nn_bufPut(pB, NN_ETH_HDR_LEN);
    const uint16_t hlen = (uint16_t)(20 + (mss != 0 ? 4 : 0));
    uint8_t *pIp, *pT;
    uint32_t sum;

    nn_macCopy(pE->dst, _ourMac);
    nn_macCopy(pE->src, _peerMac);
    nn_put16(pE->type, NN_ETH_TYPE_IP);
    pIp = nn_bufPut(pB, 20);
    memset(pIp, 0, 20);
    pIp[0] = 0x45;
    nn_put16(pIp + 2, (uint16_t)(20 + hlen + n));
    pIp[8] = 64;
    pIp[9] = NN_IP_PROTO_TCP;
    memcpy(pIp + 12, _peerIp.b, 4);
    memcpy(pIp + 16, _ourIp.b, 4);
    nn_put16(pIp + 10, nn_cksum(pIp, 20));
    pT = nn_bufPut(pB, (uint16_t)(hlen + n));
    memset(pT, 0, hlen);
    nn_put16(pT, sport);
    nn_put16(pT + 2, dport);
    nn_put32(pT + 4, seq);
    nn_put32(pT + 8, ack);
    pT[12] = (uint8_t)((hlen / 4) << 4);
    pT[13] = flags;
    nn_put16(pT + 14, wnd);
    if(mss != 0) { pT[20] = 2; pT[21] = 4; nn_put16(pT + 22, mss); }
    if(n != 0) memcpy(pT + hlen, payload, n);
    sum = nn_cksumPseudo(_peerIp, _ourIp, NN_IP_PROTO_TCP, (uint16_t)(hlen + n));
    nn_put16(pT + 16, nn_cksumFinish(nn_cksumAdd(sum, pT, (uint16_t)(hlen + n))));
    pB->pDev = &_dev;
    return pB;
}

/** Teach ARP the peer so nothing parks in its queue. */
static void learn(void)
{
    nn_buf_t *pB = nn_bufAlloc(NN_CFG_RX_OFFSET);
    nn_ethHdr_t *pE = (nn_ethHdr_t *)nn_bufPut(pB, NN_ETH_HDR_LEN);
    uint8_t *a = nn_bufPut(pB, 28);
    nn_macCopy(pE->dst, _ourMac); nn_macCopy(pE->src, _peerMac); nn_put16(pE->type, NN_ETH_TYPE_ARP);
    nn_put16(a, 1); nn_put16(a + 2, 0x0800); a[4] = 6; a[5] = 4; nn_put16(a + 6, 2);
    nn_macCopy(a + 8, _peerMac); memcpy(a + 14, _peerIp.b, 4);
    nn_macCopy(a + 18, _ourMac); memcpy(a + 24, _ourIp.b, 4);
    pB->pDev = &_dev;
    nn_net_input(pB);
}

static void advance(uint32_t ms)
{
    nn_os_testAdvance(ms);
    nn_timer_run();
}

/* --- Events ------------------------------------------------------------------------------- */

static unsigned _events[8];
static void onEvent(nn_tcp_t *pS, uint8_t ev, void *arg) { (void)pS; (void)arg; if(ev < 8) ++_events[ev]; }

/* --- A connection opened actively, used by most tests --------------------------------------- */

#define PEER_PORT   80u
#define PEER_ISS    1000u

static uint8_t _rxRing[2048], _txRing[4096];
static nn_tcp_t _s;

/** Open and connect _s: SYN out, SYN-ACK in with \a peerMss and \a peerWnd, ACK out.
    Leaves the peer at sequence PEER_ISS + 1 and nothing captured. */
static void connectSock(uint16_t peerMss, uint16_t peerWnd)
{
    nn_buf_t *p;
    memset(_events, 0, sizeof(_events));
    CHECK_EQ(nn_tcpOpen(&_s, _rxRing, sizeof(_rxRing), _txRing, sizeof(_txRing)), NN_OK);
    nn_tcpOnEvent(&_s, onEvent, NULL);
    CHECK_EQ(nn_tcpConnect(&_s, _peerIp, PEER_PORT, 0), NN_ERR_PENDING);
    CHECK_EQ(nn_tcpState(&_s), NN_TCP_SYN_SENT);
    CHECK_EQ(_nTx, 1);
    p = _tx[0];
    CHECK_EQ(segFlags(p), NN_TCP_SYN);
    CHECK_EQ(segSeq(p), _s.iss);
    CHECK_EQ(segMssOption(p), 1460);
    CHECK(segChecksumOk(p));
    CHECK(nn_timerIsActive(&_s.timer));
    clearTx();
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS, _s.iss + 1, NN_TCP_SYN | NN_TCP_ACK, peerWnd, NULL, 0, peerMss));
    CHECK_EQ(nn_tcpState(&_s), NN_TCP_ESTABLISHED);
    CHECK_EQ(_events[NN_TCP_EV_CONNECTED], 1);
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segFlags(_tx[0]), NN_TCP_ACK);
    CHECK_EQ(segAck(_tx[0]), PEER_ISS + 1);
    CHECK_EQ(segWnd(_tx[0]), sizeof(_rxRing));
    CHECK(!nn_timerIsActive(&_s.timer));
    clearTx();
}

/** The peer acknowledges everything we sent so far. */
static void peerAcksAll(uint16_t wnd)
{
    nn_net_input(segment(PEER_PORT, _s.localPort, _s.rcvNxt, _s.sndNxt, NN_TCP_ACK, wnd, NULL, 0, 0));
}

static void testHandshakeAndData(void)
{
    uint8_t buf[64];
    nn_tcpStats_t st;

    connectSock(1400, 8192);
    CHECK_EQ(_s.mss, 1400);
    CHECK_EQ(_s.sndWnd, 8192);
    CHECK_EQ(_s.cwnd, 3u * 1400u);

    /* Send: one PSH segment, timer running, ring holds the data until the ACK. */
    CHECK_EQ(nn_tcpSend(&_s, "hello", 5, 0), 5);
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segFlags(_tx[0]), NN_TCP_ACK | NN_TCP_PSH);
    CHECK_EQ(segSeq(_tx[0]), _s.iss + 1);
    CHECK_EQ(segDataLen(_tx[0]), 5);
    CHECK(memcmp(segData(_tx[0]), "hello", 5) == 0);
    CHECK(segChecksumOk(_tx[0]));
    CHECK_EQ(_s.txLen, 5);
    CHECK(nn_timerIsActive(&_s.timer));
    clearTx();
    advance(1);
    peerAcksAll(8192);
    CHECK_EQ(_s.txLen, 0);
    CHECK_EQ(_s.sndUna, _s.iss + 6);
    CHECK(!nn_timerIsActive(&_s.timer));
    CHECK_EQ(_events[NN_TCP_EV_WRITABLE], 1);
    CHECK_EQ(_nTx, 0);
    CHECK_EQ(_s.rto, NN_CFG_TCP_RTO_MIN_MS);         /* 1 ms round trips clamp to the floor */

    /* Receive: the first segment is acknowledged after the delay, the second at once. */
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 1, _s.sndNxt, NN_TCP_ACK | NN_TCP_PSH, 8192, "world", 5, 0));
    CHECK_EQ(_nTx, 0);
    CHECK(_s.flags & NN_TCPF_DELACK);
    CHECK_EQ(_events[NN_TCP_EV_READABLE], 1);
    CHECK_EQ(nn_tcpAvailable(&_s), 5);
    CHECK_EQ(nn_tcpRecv(&_s, buf, sizeof(buf), 0), 5);
    CHECK(memcmp(buf, "world", 5) == 0);
    CHECK_EQ(nn_tcpRecv(&_s, buf, sizeof(buf), 0), NN_ERR_TIMEOUT);
    advance(NN_CFG_TCP_DELACK_MS);
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segFlags(_tx[0]), NN_TCP_ACK);
    CHECK_EQ(segAck(_tx[0]), PEER_ISS + 6);
    CHECK(!(_s.flags & NN_TCPF_DELACK));
    clearTx();
    nn_tcpGetStats(&st);
    CHECK_EQ(st.delAcks, 1);
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 6, _s.sndNxt, NN_TCP_ACK, 8192, "ab", 2, 0));
    CHECK_EQ(_nTx, 0);
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 8, _s.sndNxt, NN_TCP_ACK, 8192, "cd", 2, 0));
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segAck(_tx[0]), PEER_ISS + 10);
    clearTx();
    CHECK_EQ(nn_tcpRecv(&_s, buf, 3, 0), 3);        /* partial read */
    CHECK(memcmp(buf, "abc", 3) == 0);
    CHECK_EQ(nn_tcpRecv(&_s, buf, sizeof(buf), 0), 1);
    CHECK_EQ(buf[0], 'd');

    /* A duplicate of old data is acknowledged at once and not delivered twice. */
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 6, _s.sndNxt, NN_TCP_ACK, 8192, "abcd", 4, 0));
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segAck(_tx[0]), PEER_ISS + 10);
    CHECK_EQ(nn_tcpAvailable(&_s), 0);
    clearTx();
    /* Partly old: "cdEF" starting at +8 delivers only "EF". */
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 8, _s.sndNxt, NN_TCP_ACK, 8192, "cdEF", 4, 0));
    CHECK_EQ(nn_tcpRecv(&_s, buf, sizeof(buf), 0), 2);
    CHECK(memcmp(buf, "EF", 2) == 0);
    advance(NN_CFG_TCP_DELACK_MS);
    clearTx();

    /* Our ACK carries the window: 2048 free again. */
    CHECK_EQ(nn_tcpSend(&_s, "x", 1, 0), 1);
    CHECK_EQ(segWnd(_tx[0]), 2048);
    CHECK_EQ(segAck(_tx[0]), PEER_ISS + 12);
    clearTx();
    peerAcksAll(8192);
    nn_tcpAbort(&_s);
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segFlags(_tx[0]), NN_TCP_RST | NN_TCP_ACK);
    CHECK_EQ(nn_tcpState(&_s), NN_TCP_CLOSED);
    CHECK_EQ(_events[NN_TCP_EV_CLOSED], 1);
    clearTx();
}

static void testOutOfOrder(void)
{
    uint8_t buf[64];
    nn_tcpStats_t st;

    connectSock(1400, 8192);
    /* Segment 2 before segment 1: an immediate duplicate ACK, data kept. */
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 1 + 4, _s.sndNxt, NN_TCP_ACK, 8192, "5678", 4, 0));
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segAck(_tx[0]), PEER_ISS + 1);
    CHECK_EQ(_s.oooLen, 4);
    CHECK_EQ(_s.oooOff, 4);
    CHECK_EQ(nn_tcpAvailable(&_s), 0);
    clearTx();
    /* A third one touching the second extends the range. */
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 1 + 8, _s.sndNxt, NN_TCP_ACK, 8192, "9", 1, 0));
    CHECK_EQ(_s.oooLen, 5);
    clearTx();
    /* The missing one: everything becomes readable, acknowledged at once. */
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 1, _s.sndNxt, NN_TCP_ACK, 8192, "1234", 4, 0));
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segAck(_tx[0]), PEER_ISS + 10);
    CHECK_EQ(_s.oooLen, 0);
    CHECK_EQ(nn_tcpRecv(&_s, buf, sizeof(buf), 0), 9);
    CHECK(memcmp(buf, "123456789", 9) == 0);
    clearTx();
    /* Overlap: the gap filler overlaps the stored range partly. */
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 10 + 3, _s.sndNxt, NN_TCP_ACK, 8192, "DEFG", 4, 0));
    clearTx();
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 10, _s.sndNxt, NN_TCP_ACK, 8192, "ABCDE", 5, 0));
    CHECK_EQ(nn_tcpRecv(&_s, buf, sizeof(buf), 0), 7);
    CHECK(memcmp(buf, "ABCDEFG", 7) == 0);
    clearTx();
    /* A second disjoint range is not kept (one range only), still acknowledged. */
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 17 + 10, _s.sndNxt, NN_TCP_ACK, 8192, "far", 3, 0));
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 17 + 20, _s.sndNxt, NN_TCP_ACK, 8192, "farther", 7, 0));
    CHECK_EQ(_nTx, 2);
    CHECK_EQ(_s.oooLen, 3);
    nn_tcpGetStats(&st);
    CHECK_EQ(st.rxOoo, 5);
    CHECK_EQ(st.rxOooDropped, 1);
    clearTx();
    nn_tcpAbort(&_s);
    clearTx();
}

static void testNagleAndWindow(void)
{
    static uint8_t big[3000];
    unsigned i;

    connectSock(1000, 65535);
    CHECK_EQ(_s.mss, 1000);
    for(i=0; i<sizeof(big); ++i) big[i] = (uint8_t)i;

    /* Nagle: a second small write waits for the ACK of the first. */
    CHECK_EQ(nn_tcpSend(&_s, "a", 1, 0), 1);
    CHECK_EQ(nn_tcpSend(&_s, "b", 1, 0), 1);
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segDataLen(_tx[0]), 1);
    clearTx();
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 1, _s.iss + 2, NN_TCP_ACK, 65535, NULL, 0, 0));
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segDataLen(_tx[0]), 1);
    CHECK_EQ(segData(_tx[0])[0], 'b');
    clearTx();
    peerAcksAll(65535);
    /* Without Nagle both go out. */
    nn_tcpSetNoDelay(&_s, true);
    CHECK_EQ(nn_tcpSend(&_s, "c", 1, 0), 1);
    CHECK_EQ(nn_tcpSend(&_s, "d", 1, 0), 1);
    CHECK_EQ(_nTx, 2);
    clearTx();
    peerAcksAll(65535);
    nn_tcpSetNoDelay(&_s, false);

    /* Congestion window: 3000 bytes with cwnd 3 segments go out as 3 full segments; more
       waits for ACKs (slow start grows cwnd by one segment per ACKed segment). */
    _s.cwnd = 3000;                                     /* the small ACKs above grew it a little */
    CHECK_EQ(nn_tcpSend(&_s, big, 3000, 0), 3000);
    CHECK_EQ(nn_tcpSend(&_s, big, 1000, 0), 1000);
    CHECK_EQ(_nTx, 3);
    CHECK_EQ(segDataLen(_tx[0]), 1000);
    CHECK_EQ(segDataLen(_tx[2]), 1000);
    CHECK(!(segFlags(_tx[0]) & NN_TCP_PSH));
    CHECK(segChecksumOk(_tx[1]));
    CHECK(memcmp(segData(_tx[1]), big + 1000, 1000) == 0);
    CHECK_EQ(nn_tcpSendSpace(&_s), 4096 - 4000);
    clearTx();
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 1, _s.sndUna + 1000, NN_TCP_ACK, 65535, NULL, 0, 0));
    CHECK_EQ(_s.cwnd, 4000);
    CHECK_EQ(_nTx, 1);                                  /* the fourth segment */
    CHECK_EQ(segDataLen(_tx[0]), 1000);
    CHECK(segFlags(_tx[0]) & NN_TCP_PSH);
    clearTx();
    peerAcksAll(65535);
    CHECK_EQ(_s.txLen, 0);

    /* Peer window smaller than cwnd limits us: one full segment, the 500 byte rest waits
       (sender side silly window avoidance); a window update releases the rest. */
    peerAcksAll(1500);
    CHECK_EQ(nn_tcpSend(&_s, big, 3000, 0), 3000);
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segDataLen(_tx[0]), 1000);
    clearTx();
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 1, _s.sndUna, NN_TCP_ACK, 65535, NULL, 0, 0));
    CHECK_EQ(_nTx, 2);
    CHECK_EQ(segDataLen(_tx[0]), 1000);
    CHECK_EQ(segDataLen(_tx[1]), 1000);
    clearTx();
    peerAcksAll(65535);

    /* Send ring full: a non blocking send takes what fits. */
    peerAcksAll(0);
    CHECK_EQ(nn_tcpSend(&_s, big, 3000, 0), 3000);
    CHECK_EQ(nn_tcpSend(&_s, big, 3000, 0), 1096);
    CHECK_EQ(nn_tcpSend(&_s, big, 3000, 0), NN_ERR_TIMEOUT);
    CHECK_EQ(_nTx, 0);
    nn_tcpAbort(&_s);
    clearTx();
}

static void testRetransmission(void)
{
    static uint8_t big[3000];
    nn_tcpStats_t st, st0;
    unsigned i;

    connectSock(1000, 65535);
    for(i=0; i<sizeof(big); ++i) big[i] = (uint8_t)(i * 3);
    nn_tcpGetStats(&st0);

    /* Timeout: resend from the oldest byte with cwnd one segment, RTO doubled. */
    CHECK_EQ(nn_tcpSend(&_s, big, 3000, 0), 3000);
    CHECK_EQ(_nTx, 3);
    clearTx();
    advance(NN_CFG_TCP_RTO_MIN_MS - 1);
    CHECK_EQ(_nTx, 0);
    advance(1);
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segSeq(_tx[0]), _s.iss + 1);
    CHECK_EQ(segDataLen(_tx[0]), 1000);
    CHECK_EQ(_s.cwnd, 1000);
    CHECK_EQ(_s.rto, 2 * NN_CFG_TCP_RTO_MIN_MS);
    CHECK_EQ(_s.rexmits, 1);
    clearTx();
    advance(2 * NN_CFG_TCP_RTO_MIN_MS);
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(_s.rto, 4 * NN_CFG_TCP_RTO_MIN_MS);
    clearTx();
    nn_tcpGetStats(&st);
    CHECK_EQ(st.timeouts - st0.timeouts, 2);
    CHECK_EQ(st.rexmits - st0.rexmits, 2);
    /* The ACK of the first segment lets the next out (slow start again). */
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 1, _s.iss + 1001, NN_TCP_ACK, 65535, NULL, 0, 0));
    CHECK_EQ(_s.rexmits, 0);
    CHECK_EQ(_s.cwnd, 2000);
    CHECK_EQ(_nTx, 2);
    CHECK_EQ(segSeq(_tx[0]), _s.iss + 1001);
    clearTx();
    peerAcksAll(65535);
    CHECK(!nn_timerIsActive(&_s.timer));

    /* After a timeout the peer may acknowledge everything sent before it (only its ACKs
       were lost): valid up to the highest sequence ever sent, not the resend pointer.
       Found by the netem gate: the connection stalled for good on this. */
    _s.cwnd = 5000;
    CHECK_EQ(nn_tcpSend(&_s, big, 3000, 0), 3000);
    CHECK_EQ(_nTx, 3);
    clearTx();
    advance(_s.rto);
    CHECK_EQ(_nTx, 1);                                  /* timeout: first segment again */
    CHECK_EQ(segSeq(_tx[0]), _s.sndUna);
    CHECK_EQ(_s.sndNxt, _s.sndUna + 1000);
    CHECK_EQ(_s.sndMax, _s.sndUna + 3000);
    clearTx();
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 1, _s.sndUna + 3000, NN_TCP_ACK, 65535, NULL, 0, 0));
    CHECK_EQ(_s.txLen, 0);
    CHECK_EQ(_s.sndNxt, _s.sndUna);
    CHECK_EQ(_s.sndUna, _s.sndMax);
    CHECK(!nn_timerIsActive(&_s.timer));
    CHECK_EQ(_nTx, 0);
    /* One beyond anything sent is still answered with an ACK and ignored. */
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 1, _s.sndUna + 1, NN_TCP_ACK, 65535, NULL, 0, 0));
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segFlags(_tx[0]), NN_TCP_ACK);
    CHECK_EQ(_s.sndUna, _s.sndMax);
    clearTx();

    /* Fast retransmit: three duplicate ACKs resend the first segment at once. */
    _s.cwnd = 5000;
    nn_tcpGetStats(&st0);
    CHECK_EQ(nn_tcpSend(&_s, big, 3000, 0), 3000);
    CHECK_EQ(_nTx, 3);
    clearTx();
    for(i=0; i<2; ++i)
        nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 1, _s.sndUna, NN_TCP_ACK, 65535, NULL, 0, 0));
    CHECK_EQ(_nTx, 0);
    CHECK_EQ(_s.dupAcks, 2);
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 1, _s.sndUna, NN_TCP_ACK, 65535, NULL, 0, 0));
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segSeq(_tx[0]), _s.sndUna);
    CHECK_EQ(segDataLen(_tx[0]), 1000);
    CHECK(_s.flags & NN_TCPF_FASTREC);
    CHECK_EQ(_s.ssthresh, 2000);
    CHECK_EQ(_s.cwnd, 2000 + 3000);
    clearTx();
    nn_tcpGetStats(&st);
    CHECK_EQ(st.fastRexmits - st0.fastRexmits, 1);
    CHECK_EQ(st.timeouts - st0.timeouts, 0);
    /* A partial ACK (NewReno) resends the next one; the full ACK ends recovery. */
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 1, _s.sndUna + 1000, NN_TCP_ACK, 65535, NULL, 0, 0));
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segSeq(_tx[0]), _s.sndUna);
    CHECK(_s.flags & NN_TCPF_FASTREC);
    clearTx();
    peerAcksAll(65535);
    CHECK(!(_s.flags & NN_TCPF_FASTREC));
    CHECK_EQ(_s.cwnd, 2000);
    CHECK_EQ(_s.txLen, 0);

    /* Too many timeouts drop the connection. */
    CHECK_EQ(nn_tcpSend(&_s, "x", 1, 0), 1);
    clearTx();
    for(i=0; i<=NN_CFG_TCP_MAX_REXMIT; ++i)
    {
        CHECK_EQ(nn_tcpState(&_s), NN_TCP_ESTABLISHED);
        advance(NN_CFG_TCP_RTO_MAX_MS);
        clearTx();
    }
    CHECK_EQ(nn_tcpState(&_s), NN_TCP_CLOSED);
    CHECK_EQ(_s.err, NN_ERR_TIMEOUT);
    CHECK_EQ(nn_tcpRecv(&_s, big, 10, 0), NN_ERR_TIMEOUT);
    CHECK_EQ(nn_tcpSend(&_s, "x", 1, 0), NN_ERR_TIMEOUT);
    CHECK_EQ(_events[NN_TCP_EV_CLOSED], 1);
}

static void testZeroWindow(void)
{
    static uint8_t big[1000];
    nn_tcpStats_t st;

    connectSock(1000, 0);                               /* the peer opens with window 0 */
    CHECK_EQ(nn_tcpSend(&_s, big, 100, 0), 100);
    CHECK_EQ(_nTx, 0);
    CHECK(_s.flags & NN_TCPF_PERSIST);
    CHECK(nn_timerIsActive(&_s.timer));
    advance(NN_CFG_TCP_RTO_MIN_MS);
    CHECK_EQ(_nTx, 1);                                  /* the probe: one byte */
    CHECK_EQ(segDataLen(_tx[0]), 1);
    CHECK_EQ(segSeq(_tx[0]), _s.iss + 1);
    clearTx();
    /* The peer drops the byte (window still 0): the probe is repeated with backoff. */
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 1, _s.iss + 1, NN_TCP_ACK, 0, NULL, 0, 0));
    CHECK_EQ(_nTx, 0);
    CHECK_EQ(_s.dupAcks, 0);
    advance(2 * NN_CFG_TCP_RTO_MIN_MS);
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segSeq(_tx[0]), _s.iss + 1);
    clearTx();
    /* The peer takes the byte but stays at window 0: probing goes on. */
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 1, _s.iss + 2, NN_TCP_ACK, 0, NULL, 0, 0));
    CHECK_EQ(_s.txLen, 99);
    CHECK(_s.flags & NN_TCPF_PERSIST);
    CHECK(nn_timerIsActive(&_s.timer));
    /* The window opens: the rest goes at once. */
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 1, _s.iss + 2, NN_TCP_ACK, 4000, NULL, 0, 0));
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segDataLen(_tx[0]), 99);
    CHECK(!(_s.flags & NN_TCPF_PERSIST));
    clearTx();
    peerAcksAll(4000);
    nn_tcpGetStats(&st);
    nn_tcpAbort(&_s);
    clearTx();
}

static void testReceiveWindow(void)
{
    static uint8_t big[2048], buf[2048];
    unsigned i;
    uint32_t seq;

    connectSock(1000, 65535);
    for(i=0; i<sizeof(big); ++i) big[i] = (uint8_t)(i ^ 0x5A);
    /* Fill our 2048 byte receive ring: the window closes, the last ACK says 0. */
    seq = PEER_ISS + 1;
    for(i=0; i<2048; i+=512)
    {
        nn_net_input(segment(PEER_PORT, _s.localPort, seq, _s.sndNxt, NN_TCP_ACK, 65535, big + i, 512, 0));
        seq += 512;
    }
    CHECK_EQ(nn_tcpAvailable(&_s), 2048);
    CHECK_EQ(_nTx, 2);
    CHECK_EQ(segWnd(_tx[1]), 0);
    clearTx();
    /* More data than the window: nothing taken, an ACK repeats the state. */
    nn_net_input(segment(PEER_PORT, _s.localPort, seq, _s.sndNxt, NN_TCP_ACK, 65535, big, 100, 0));
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segAck(_tx[0]), seq);
    CHECK_EQ(segWnd(_tx[0]), 0);
    clearTx();
    /* The application reads: a small read does not announce, a large one does. */
    CHECK_EQ(nn_tcpRecv(&_s, buf, 100, 0), 100);
    CHECK_EQ(_nTx, 0);
    CHECK_EQ(nn_tcpRecv(&_s, buf + 100, 1948, 0), 1948);
    CHECK(memcmp(buf, big, 2048) == 0);
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segWnd(_tx[0]), 2048);
    clearTx();
    /* A segment that straddles the window edge is trimmed. */
    nn_net_input(segment(PEER_PORT, _s.localPort, seq + 2000, _s.sndNxt, NN_TCP_ACK, 65535, big, 100, 0));
    CHECK_EQ(_s.oooLen, 48);
    clearTx();
    nn_tcpAbort(&_s);
    clearTx();
}

static void testClose(void)
{
    uint8_t buf[16];
    nn_tcpStats_t st;
    uint32_t seq;

    /* Active close: FIN, ACK, FIN, ACK, then TIME_WAIT in the table. */
    connectSock(1400, 8192);
    CHECK_EQ(nn_tcpClose(&_s), NN_OK);
    CHECK_EQ(nn_tcpState(&_s), NN_TCP_FIN_WAIT_1);
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segFlags(_tx[0]), NN_TCP_FIN | NN_TCP_ACK);
    CHECK_EQ(segSeq(_tx[0]), _s.iss + 1);
    CHECK_EQ(_s.sndNxt, _s.iss + 2);
    clearTx();
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 1, _s.iss + 2, NN_TCP_ACK, 8192, NULL, 0, 0));
    CHECK_EQ(nn_tcpState(&_s), NN_TCP_FIN_WAIT_2);
    CHECK_EQ(_nTx, 0);
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 1, _s.iss + 2, NN_TCP_ACK | NN_TCP_FIN, 8192, NULL, 0, 0));
    CHECK_EQ(nn_tcpState(&_s), NN_TCP_CLOSED);
    CHECK_EQ(_s.err, NN_OK);
    CHECK_EQ(_events[NN_TCP_EV_CLOSED], 1);
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segFlags(_tx[0]), NN_TCP_ACK);
    CHECK_EQ(segAck(_tx[0]), PEER_ISS + 2);
    clearTx();
    nn_tcpGetStats(&st);
    CHECK_EQ(st.timeWaits, 1);
    /* The peer's FIN again (our ACK was lost): answered from the table. */
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 1, _s.iss + 2, NN_TCP_ACK | NN_TCP_FIN, 8192, NULL, 0, 0));
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segFlags(_tx[0]), NN_TCP_ACK);
    CHECK_EQ(segAck(_tx[0]), PEER_ISS + 2);
    CHECK_EQ(segSeq(_tx[0]), _s.iss + 2);
    clearTx();
    /* Anything else to that port gets a reset, the TIME_WAIT entry is left alone. */
    {
        const uint16_t port = _s.localPort;
        nn_net_input(segment(PEER_PORT, (uint16_t)(port + 1), 5, 0, NN_TCP_ACK, 8192, NULL, 0, 0));
        CHECK_EQ(_nTx, 1);
        CHECK_EQ(segFlags(_tx[0]), NN_TCP_RST);
        clearTx();
        /* After 2 MSL the entry is gone and the same segment is answered with RST. */
        advance(2 * NN_CFG_TCP_MSL_MS + 1000);
        nn_net_input(segment(PEER_PORT, port, PEER_ISS + 1, _s.iss + 2, NN_TCP_ACK | NN_TCP_FIN, 8192, NULL, 0, 0));
        CHECK_EQ(_nTx, 1);
        CHECK_EQ(segFlags(_tx[0]), NN_TCP_RST);
        clearTx();
    }

    /* Passive close: FIN in, recv gives 0, close sends our FIN, its ACK ends it. */
    connectSock(1400, 8192);
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 1, _s.sndNxt, NN_TCP_ACK | NN_TCP_PSH, 8192, "bye", 3, 0));
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 4, _s.sndNxt, NN_TCP_ACK | NN_TCP_FIN, 8192, NULL, 0, 0));
    CHECK_EQ(nn_tcpState(&_s), NN_TCP_CLOSE_WAIT);
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segAck(_tx[0]), PEER_ISS + 5);
    clearTx();
    CHECK_EQ(nn_tcpRecv(&_s, buf, sizeof(buf), 0), 3);
    CHECK_EQ(nn_tcpRecv(&_s, buf, sizeof(buf), 0), 0);
    CHECK_EQ(nn_tcpSend(&_s, "ok", 2, 0), 2);         /* still allowed to send */
    CHECK_EQ(_nTx, 1);
    clearTx();
    CHECK_EQ(nn_tcpClose(&_s), NN_OK);
    CHECK_EQ(nn_tcpState(&_s), NN_TCP_LAST_ACK);
    CHECK_EQ(_nTx, 1);                                  /* the FIN goes at once, behind the data */
    CHECK_EQ(segFlags(_tx[0]), NN_TCP_FIN | NN_TCP_ACK);
    seq = segSeq(_tx[0]);
    CHECK_EQ(seq, _s.iss + 3);
    clearTx();
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 5, _s.iss + 3, NN_TCP_ACK, 8192, NULL, 0, 0));
    CHECK_EQ(nn_tcpState(&_s), NN_TCP_LAST_ACK);        /* data acknowledged, FIN not yet */
    CHECK_EQ(_nTx, 0);
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 5, _s.iss + 4, NN_TCP_ACK, 8192, NULL, 0, 0));
    CHECK_EQ(nn_tcpState(&_s), NN_TCP_CLOSED);
    CHECK_EQ(_s.err, NN_OK);
    CHECK_EQ(_nTx, 0);

    /* Simultaneous close: our FIN and theirs cross. */
    connectSock(1400, 8192);
    nn_tcpClose(&_s);
    clearTx();
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 1, _s.iss + 1, NN_TCP_ACK | NN_TCP_FIN, 8192, NULL, 0, 0));
    CHECK_EQ(nn_tcpState(&_s), NN_TCP_CLOSING);
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segAck(_tx[0]), PEER_ISS + 2);
    clearTx();
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 2, _s.iss + 2, NN_TCP_ACK, 8192, NULL, 0, 0));
    CHECK_EQ(nn_tcpState(&_s), NN_TCP_CLOSED);
    nn_tcpGetStats(&st);
    CHECK_EQ(st.timeWaits, 2);
    advance(2 * NN_CFG_TCP_MSL_MS + 1000);

    /* Data and FIN both lost: the timeout resends them in one segment. */
    connectSock(1400, 8192);
    CHECK_EQ(nn_tcpSend(&_s, "last", 4, 0), 4);
    clearTx();
    nn_tcpClose(&_s);
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segFlags(_tx[0]), NN_TCP_FIN | NN_TCP_ACK);
    CHECK_EQ(segSeq(_tx[0]), _s.iss + 5);
    clearTx();
    advance(NN_CFG_TCP_RTO_MIN_MS);
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segFlags(_tx[0]), NN_TCP_FIN | NN_TCP_ACK | NN_TCP_PSH);
    CHECK_EQ(segSeq(_tx[0]), _s.iss + 1);
    CHECK_EQ(segDataLen(_tx[0]), 4);
    clearTx();
    peerAcksAll(8192);
    CHECK_EQ(nn_tcpState(&_s), NN_TCP_FIN_WAIT_2);
    nn_tcpAbort(&_s);
    clearTx();

    /* Close with unread data is a reset. */
    connectSock(1400, 8192);
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 1, _s.sndNxt, NN_TCP_ACK | NN_TCP_PSH, 8192, "unread", 6, 0));
    clearTx();
    nn_tcpClose(&_s);
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segFlags(_tx[0]), NN_TCP_RST | NN_TCP_ACK);
    CHECK_EQ(nn_tcpState(&_s), NN_TCP_CLOSED);
    clearTx();
}

static void testResets(void)
{
    uint8_t buf[8];
    nn_tcpStats_t st;
    unsigned i;

    /* RST on an established connection. */
    connectSock(1400, 8192);
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 1, _s.sndNxt, NN_TCP_RST | NN_TCP_ACK, 8192, NULL, 0, 0));
    CHECK_EQ(nn_tcpState(&_s), NN_TCP_CLOSED);
    CHECK_EQ(_s.err, NN_ERR_RESET);
    CHECK_EQ(nn_tcpRecv(&_s, buf, sizeof(buf), 0), NN_ERR_RESET);
    CHECK_EQ(_nTx, 0);
    /* An RST outside the window is ignored. */
    connectSock(1400, 8192);
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 50000, _s.sndNxt, NN_TCP_RST, 8192, NULL, 0, 0));
    CHECK_EQ(nn_tcpState(&_s), NN_TCP_ESTABLISHED);
    CHECK_EQ(_nTx, 0);
    /* A SYN inside the window resets the connection. */
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 1, _s.sndNxt, NN_TCP_SYN, 8192, NULL, 0, 0));
    CHECK_EQ(nn_tcpState(&_s), NN_TCP_CLOSED);
    CHECK_EQ(_s.err, NN_ERR_RESET);
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segFlags(_tx[0]), NN_TCP_RST);
    clearTx();

    /* Connect refused. */
    CHECK_EQ(nn_tcpOpen(&_s, _rxRing, sizeof(_rxRing), _txRing, sizeof(_txRing)), NN_OK);
    CHECK_EQ(nn_tcpConnect(&_s, _peerIp, PEER_PORT, 0), NN_ERR_PENDING);
    clearTx();
    nn_net_input(segment(PEER_PORT, _s.localPort, 0, _s.iss + 1, NN_TCP_RST | NN_TCP_ACK, 0, NULL, 0, 0));
    CHECK_EQ(nn_tcpState(&_s), NN_TCP_CLOSED);
    CHECK_EQ(_s.err, NN_ERR_REFUSED);
    CHECK_EQ(_nTx, 0);
    /* A SYN-ACK acknowledging the wrong thing is answered with RST and ignored. */
    CHECK_EQ(nn_tcpOpen(&_s, _rxRing, sizeof(_rxRing), _txRing, sizeof(_txRing)), NN_OK);
    CHECK_EQ(nn_tcpConnect(&_s, _peerIp, PEER_PORT, 0), NN_ERR_PENDING);
    clearTx();
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS, _s.iss + 7, NN_TCP_SYN | NN_TCP_ACK, 8192, NULL, 0, 0));
    CHECK_EQ(nn_tcpState(&_s), NN_TCP_SYN_SENT);
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segFlags(_tx[0]), NN_TCP_RST);
    CHECK_EQ(segSeq(_tx[0]), _s.iss + 7);
    clearTx();
    /* SYN retries with backoff, then the connect times out. */
    nn_tcpGetStats(&st);
    for(i=1; i<=NN_CFG_TCP_SYN_RETRIES; ++i)
    {
        advance((uint32_t)NN_CFG_TCP_RTO_INIT_MS << (i - 1));
        CHECK_EQ(_nTx, 1);
        CHECK_EQ(segFlags(_tx[0]), NN_TCP_SYN);
        CHECK_EQ(segMssOption(_tx[0]), 1460);
        clearTx();
        CHECK_EQ(nn_tcpState(&_s), NN_TCP_SYN_SENT);
    }
    advance((uint32_t)NN_CFG_TCP_RTO_INIT_MS << NN_CFG_TCP_SYN_RETRIES);
    CHECK_EQ(nn_tcpState(&_s), NN_TCP_CLOSED);
    CHECK_EQ(_s.err, NN_ERR_TIMEOUT);
    CHECK_EQ(_nTx, 0);

    /* No socket at all: RST+ACK to a SYN, RST to an ACK, nothing to an RST. */
    nn_tcpGetStats(&st);
    nn_net_input(segment(1234, 9, 777, 0, NN_TCP_SYN, 1000, NULL, 0, 1460));
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segFlags(_tx[0]), NN_TCP_RST | NN_TCP_ACK);
    CHECK_EQ(segAck(_tx[0]), 778);
    CHECK_EQ(segSeq(_tx[0]), 0);
    CHECK(segChecksumOk(_tx[0]));
    clearTx();
    nn_net_input(segment(1234, 9, 777, 4242, NN_TCP_ACK, 1000, "x", 1, 0));
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segFlags(_tx[0]), NN_TCP_RST);
    CHECK_EQ(segSeq(_tx[0]), 4242);
    clearTx();
    nn_net_input(segment(1234, 9, 777, 4242, NN_TCP_RST, 1000, NULL, 0, 0));
    CHECK_EQ(_nTx, 0);
    {
        nn_tcpStats_t st2;
        nn_tcpGetStats(&st2);
        CHECK_EQ(st2.rxNoSocket - st.rxNoSocket, 3);
    }

    /* Bad checksum and short header: dropped and counted. */
    {
        nn_buf_t *pB = segment(1234, 9, 777, 0, NN_TCP_SYN, 1000, NULL, 0, 0);
        nn_tcpStats_t st2;
        pB->pData[NN_ETH_HDR_LEN + 20 + 17] ^= 0x55;
        nn_net_input(pB);
        pB = segment(1234, 9, 777, 0, NN_TCP_SYN, 1000, NULL, 0, 0);
        pB->pData[NN_ETH_HDR_LEN + 20 + 12] = 0x20;     /* data offset 8 bytes */
        nn_net_input(pB);
        nn_tcpGetStats(&st2);
        CHECK_EQ(st2.rxBadChecksum - st.rxBadChecksum, 1);
        CHECK_EQ(st2.rxBad - st.rxBad, 1);
        CHECK_EQ(_nTx, 0);
    }
}

static uint8_t _rxRing2[1024], _txRing2[1024];
static nn_tcp_t _listen, _acc;

/* The interface loses its address (DHCP changed or lost it): every connection bound to
   it ends with NN_ERR_DOWN, silently, and the socket is reusable. */
static void testAddrLost(void)
{
    connectSock(1460, 8192);
    clearTx();
    nn_ifaceSetAddr(&_if, nn_ip4(0, 0, 0, 0), nn_ip4(0, 0, 0, 0), nn_ip4(0, 0, 0, 0));
    CHECK_EQ(nn_tcpState(&_s), NN_TCP_CLOSED);
    CHECK_EQ(_s.err, NN_ERR_DOWN);
    CHECK_EQ(_events[NN_TCP_EV_CLOSED], 1);
    CHECK_EQ(_nTx, 0);                                  /* no RST: nothing can be sent */
    CHECK(!nn_timerIsActive(&_s.timer));
    nn_ifaceSetAddr(&_if, _ourIp, _mask, _peerIp);
    connectSock(1460, 8192);                            /* the socket works again */
    clearTx();
    nn_net_input(segment(PEER_PORT, _s.localPort, PEER_ISS + 1, _s.sndNxt, NN_TCP_RST | NN_TCP_ACK, 8192, NULL, 0, 0));
    CHECK_EQ(nn_tcpState(&_s), NN_TCP_CLOSED);
    clearTx();
}

static void testListen(void)
{
    uint8_t buf[16];
    nn_tcpStats_t st;
    const uint16_t cport = 40000;
    const uint32_t ciss = 70000;

    CHECK_EQ(nn_tcpOpen(&_listen, NULL, 0, NULL, 0), NN_OK);
    CHECK_EQ(nn_tcpBind(&_listen, nn_ip4(0, 0, 0, 0), 8080), NN_OK);
    CHECK_EQ(nn_tcpListen(&_listen), NN_OK);
    CHECK_EQ(nn_tcpState(&_listen), NN_TCP_LISTEN);

    /* No socket offered yet: the SYN is dropped silently. */
    nn_tcpGetStats(&st);
    nn_net_input(segment(cport, 8080, ciss, 0, NN_TCP_SYN, 4000, NULL, 0, 1200));
    CHECK_EQ(_nTx, 0);
    {
        nn_tcpStats_t st2;
        nn_tcpGetStats(&st2);
        CHECK_EQ(st2.rxAcceptDropped - st.rxAcceptDropped, 1);
    }
    /* Offer one, retry the SYN: SYN-ACK with our MSS (ring 1024 limits it). */
    CHECK_EQ(nn_tcpOpen(&_acc, _rxRing2, sizeof(_rxRing2), _txRing2, sizeof(_txRing2)), NN_OK);
    memset(_events, 0, sizeof(_events));
    nn_tcpOnEvent(&_acc, onEvent, NULL);
    CHECK_EQ(nn_tcpAccept(&_listen, &_acc, 0), NN_ERR_PENDING);
    CHECK(_listen.pAcceptQ == &_acc);
    nn_net_input(segment(cport, 8080, ciss, 0, NN_TCP_SYN, 4000, NULL, 0, 1200));
    CHECK_EQ(nn_tcpState(&_acc), NN_TCP_SYN_RCVD);
    CHECK(_listen.pAcceptQ == NULL);
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segFlags(_tx[0]), NN_TCP_SYN | NN_TCP_ACK);
    CHECK_EQ(segAck(_tx[0]), ciss + 1);
    CHECK_EQ(segMssOption(_tx[0]), 1024);
    CHECK_EQ(segWnd(_tx[0]), 1024);
    CHECK_EQ(_acc.mss, 1200);
    CHECK_EQ(_acc.remotePort, cport);
    CHECK(nn_ip4Equal(_acc.remoteAddr, _peerIp));
    CHECK(nn_ip4Equal(_acc.localAddr, _ourIp));
    clearTx();
    /* The SYN again (our SYN-ACK lost): SYN-ACK again. */
    nn_net_input(segment(cport, 8080, ciss, 0, NN_TCP_SYN, 4000, NULL, 0, 1200));
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segFlags(_tx[0]), NN_TCP_SYN | NN_TCP_ACK);
    clearTx();
    /* The timer resends it as well. */
    advance(NN_CFG_TCP_RTO_INIT_MS);
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segFlags(_tx[0]), NN_TCP_SYN | NN_TCP_ACK);
    clearTx();
    /* The ACK, with data right behind it. */
    nn_net_input(segment(cport, 8080, ciss + 1, _acc.iss + 1, NN_TCP_ACK | NN_TCP_PSH, 4000, "GET", 3, 0));
    CHECK_EQ(nn_tcpState(&_acc), NN_TCP_ESTABLISHED);
    CHECK_EQ(_events[NN_TCP_EV_CONNECTED], 1);
    CHECK_EQ(_events[NN_TCP_EV_READABLE], 1);
    CHECK(!nn_timerIsActive(&_acc.timer));
    CHECK_EQ(nn_tcpRecv(&_acc, buf, sizeof(buf), 0), 3);
    CHECK(memcmp(buf, "GET", 3) == 0);
    CHECK_EQ(nn_tcpSend(&_acc, "200", 3, 0), 3);
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segAck(_tx[0]), ciss + 4);
    CHECK_EQ(segSeq(_tx[0]), _acc.iss + 1);
    clearTx();
    /* A second connection from the same client port is a different socket; while the
       first exists, the SYN finds the listener only if the tuple differs. */
    nn_net_input(segment((uint16_t)(cport + 1), 8080, 5, 0, NN_TCP_SYN, 4000, NULL, 0, 0));
    CHECK_EQ(_nTx, 0);                                  /* no socket offered: dropped */
    /* An ACK to the listener is answered with a RST. */
    nn_net_input(segment((uint16_t)(cport + 2), 8080, 5, 9, NN_TCP_ACK, 4000, NULL, 0, 0));
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segFlags(_tx[0]), NN_TCP_RST);
    clearTx();
    /* Binding the same port again fails; a withdrawn offer and a closed listener. */
    {
        static nn_tcp_t l2, a2;
        CHECK_EQ(nn_tcpOpen(&l2, NULL, 0, NULL, 0), NN_OK);
        CHECK_EQ(nn_tcpBind(&l2, nn_ip4(0, 0, 0, 0), 8080), NN_ERR_EXIST);
        CHECK_EQ(nn_tcpOpen(&a2, _rxRing, 64, _txRing, 64), NN_OK);
        CHECK_EQ(nn_tcpAccept(&_listen, &a2, 0), NN_ERR_PENDING);
        CHECK_EQ(nn_tcpClose(&a2), NN_OK);
        CHECK(_listen.pAcceptQ == NULL);
        CHECK_EQ(nn_tcpAccept(&_listen, &a2, 0), NN_ERR_PENDING);
        CHECK_EQ(nn_tcpClose(&_listen), NN_OK);
        CHECK_EQ(nn_tcpState(&_listen), NN_TCP_CLOSED);
        CHECK_EQ(a2.err, NN_ERR_CLOSED);
        CHECK(a2.pListener == NULL);
    }
    /* The accepted connection lives on without its listener; the client closes it. */
    nn_net_input(segment(cport, 8080, ciss + 4, _acc.iss + 4, NN_TCP_ACK | NN_TCP_FIN, 4000, NULL, 0, 0));
    CHECK_EQ(nn_tcpState(&_acc), NN_TCP_CLOSE_WAIT);
    clearTx();
    CHECK_EQ(nn_tcpRecv(&_acc, buf, sizeof(buf), 0), 0);
    nn_tcpClose(&_acc);
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(segFlags(_tx[0]), NN_TCP_FIN | NN_TCP_ACK);
    clearTx();
    nn_net_input(segment(cport, 8080, ciss + 5, _acc.iss + 5, NN_TCP_ACK, 4000, NULL, 0, 0));
    CHECK_EQ(nn_tcpState(&_acc), NN_TCP_CLOSED);
    CHECK_EQ(_events[NN_TCP_EV_CLOSED], 1);
    /* RST during the handshake fails the accept with NN_ERR_RESET. */
    CHECK_EQ(nn_tcpOpen(&_listen, NULL, 0, NULL, 0), NN_OK);
    CHECK_EQ(nn_tcpBind(&_listen, _ourIp, 8080), NN_OK);
    CHECK_EQ(nn_tcpListen(&_listen), NN_OK);
    CHECK_EQ(nn_tcpOpen(&_acc, _rxRing2, sizeof(_rxRing2), _txRing2, sizeof(_txRing2)), NN_OK);
    CHECK_EQ(nn_tcpAccept(&_listen, &_acc, 0), NN_ERR_PENDING);
    nn_net_input(segment(cport, 8080, ciss, 0, NN_TCP_SYN, 4000, NULL, 0, 0));
    CHECK_EQ(nn_tcpState(&_acc), NN_TCP_SYN_RCVD);
    CHECK_EQ(_acc.mss, 536);
    clearTx();
    nn_net_input(segment(cport, 8080, ciss + 1, _acc.iss + 1, NN_TCP_RST, 4000, NULL, 0, 0));
    CHECK_EQ(nn_tcpState(&_acc), NN_TCP_CLOSED);
    CHECK_EQ(_acc.err, NN_ERR_RESET);
    CHECK(_acc.pListener == NULL);
    nn_os_testFreeze(false);                            /* a real timeout needs a running clock */
    CHECK_EQ(nn_tcpAccept(&_listen, &_acc, 10), NN_ERR_TIMEOUT);   /* nothing arrives: withdrawn */
    nn_os_testFreeze(true);
    CHECK(_listen.pAcceptQ == NULL);
    nn_tcpClose(&_listen);
    clearTx();
}

int main(void)
{
    nn_bufStats_t bs;

    nn_os_testFreeze(true);                             /* timers move only by nn_os_testAdvance */
    nn_os_testAdvance(1000);
    CHECK_EQ(nn_init(), NN_OK);
    memset(&_dev, 0, sizeof(_dev));
    _dev.name = "fake"; _dev.type = NN_DEV_ETHERNET; _dev.flags = NN_DEVF_LINK | NN_DEVF_BROADCAST;
    _dev.hwlen = 6; nn_macCopy(_dev.hwaddr, _ourMac); _dev.mtu = 1500; _dev.pOps = &_ops;
    CHECK_EQ(nn_netdevRegister(&_dev), NN_OK);
    CHECK_EQ(nn_ifaceAdd(&_dev, &_if, _ourIp, _mask, _peerIp), NN_OK);

    nn_lock();
    learn();
    testHandshakeAndData();
    testOutOfOrder();
    testNagleAndWindow();
    testRetransmission();
    testZeroWindow();
    testReceiveWindow();
    testClose();
    testResets();
    testListen();
    testAddrLost();
    clearTx();
    nn_bufGetStats(&bs);
    CHECK_EQ(bs.free, NN_CFG_NUM_BUFS);
    CHECK_EQ(bs.allocFailed, 0);
    nn_unlock();
    test_finish("test_tcp");
    return 0;
}
