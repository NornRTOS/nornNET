/**
 * @file test_fuzz.c
 * Mutation fuzzer of the whole receive path (POSIX OS layer, ASan and UBSan from the
 * build): valid frames of every protocol are mutated at random (bit flips, byte
 * overwrites, truncation, growth, field swaps) with the checksums repaired often enough
 * that the mutations get past them, and fed to nn_net_input with a live TCP connection,
 * a listener, a UDP socket and a DNS query in place. Timers run between frames. The test
 * passes when nothing crashes, every sanitizer stays quiet, the invariants of the TCP
 * rings hold after every frame and the buffer pool is full at the end.
 *
 *   NN_FUZZ_ITERS   iterations (default 200000)
 *   NN_FUZZ_SEED    seed of the generator (default 1); a failure prints both.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "nn_net.h"
#include "nn_eth.h"
#include "nn_ip.h"
#include "nn_arp.h"
#include "nn_icmp.h"
#include "nn_udp.h"
#include "nn_tcp.h"
#include "nn_dns.h"
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
static unsigned _nTx;

static nn_err_t fakeTransmit(nn_netdev_t *pDev, nn_buf_t *pB)
{
    (void)pDev;
    ++ _nTx;
    nn_bufFree(pB);
    return NN_OK;
}
static const nn_netdevOps_t _ops = { NULL, NULL, fakeTransmit };

/* --- Random numbers (xorshift32, reproducible) ------------------------------------------- */

static uint32_t _rng;
static uint32_t rnd(void)
{
    _rng ^= _rng << 13; _rng ^= _rng >> 17; _rng ^= _rng << 5;
    return _rng;
}
static uint32_t rndBelow(uint32_t n) { return rnd() % n; }

/* --- The corpus: one valid frame of each kind, as byte strings ------------------------------ */

#define MAX_FRAME   1514u
#define CORPUS      14u

static uint8_t _corpus[CORPUS][MAX_FRAME];
static uint16_t _corpusLen[CORPUS];

static uint8_t _rxRing[2048], _txRing[2048], _rxRing2[512], _txRing2[512];
static nn_tcp_t _tcp, _listen, _acc;
static nn_udp_t _udp;
static nn_dnsReq_t *_pDns;
static unsigned _dnsCb;
static void dnsCb(nn_dnsReq_t *pReq, nn_err_t rc, nn_ip4_t addr, void *arg) { (void)pReq; (void)rc; (void)addr; (void)arg; ++_dnsCb; }

static uint8_t *ethHdr(uint8_t *f, const uint8_t *dst, uint16_t type)
{
    nn_macCopy(f, dst); nn_macCopy(f + 6, _peerMac); nn_put16(f + 12, type);
    return f + 14;
}

static uint8_t *ipHdr(uint8_t *p, uint8_t proto, uint16_t payloadLen, nn_ip4_t dst)
{
    memset(p, 0, 20);
    p[0] = 0x45; nn_put16(p + 2, (uint16_t)(20 + payloadLen)); p[8] = 64; p[9] = proto;
    memcpy(p + 12, _peerIp.b, 4); memcpy(p + 16, dst.b, 4);
    nn_put16(p + 10, nn_cksum(p, 20));
    return p + 20;
}

static void tcpSeg(uint8_t *p, uint16_t sport, uint16_t dport, uint32_t seq, uint32_t ack, uint8_t flags,
                   uint16_t wnd, const void *data, uint16_t n, nn_ip4_t dst)
{
    memset(p, 0, 20);
    nn_put16(p, sport); nn_put16(p + 2, dport); nn_put32(p + 4, seq); nn_put32(p + 8, ack);
    p[12] = 0x50; p[13] = flags; nn_put16(p + 14, wnd);
    if(n) memcpy(p + 20, data, n);
    nn_put16(p + 16, nn_cksumFinish(nn_cksumAdd(nn_cksumPseudo(_peerIp, dst, NN_IP_PROTO_TCP, (uint16_t)(20 + n)), p, (uint16_t)(20 + n))));
}

static void udpDgram(uint8_t *p, uint16_t sport, uint16_t dport, const void *data, uint16_t n, nn_ip4_t dst)
{
    nn_put16(p, sport); nn_put16(p + 2, dport); nn_put16(p + 4, (uint16_t)(8 + n)); p[6] = p[7] = 0;
    memcpy(p + 8, data, n);
    nn_put16(p + 6, nn_cksumFinish(nn_cksumAdd(nn_cksumPseudo(_peerIp, dst, NN_IP_PROTO_UDP, (uint16_t)(8 + n)), p, (uint16_t)(8 + n))));
}

static void buildCorpus(void)
{
    uint8_t *f, *p;
    static const uint8_t payload[64] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde";
    unsigned i = 0;

    /* 0: ARP request for us. */
    f = _corpus[i]; p = ethHdr(f, nn_eth_broadcast, NN_ETH_TYPE_ARP);
    nn_put16(p, 1); nn_put16(p + 2, 0x0800); p[4] = 6; p[5] = 4; nn_put16(p + 6, 1);
    nn_macCopy(p + 8, _peerMac); memcpy(p + 14, _peerIp.b, 4); memset(p + 18, 0, 6); memcpy(p + 24, _ourIp.b, 4);
    _corpusLen[i++] = 42;
    /* 1: ARP reply. */
    f = _corpus[i]; p = ethHdr(f, _ourMac, NN_ETH_TYPE_ARP);
    nn_put16(p, 1); nn_put16(p + 2, 0x0800); p[4] = 6; p[5] = 4; nn_put16(p + 6, 2);
    nn_macCopy(p + 8, _peerMac); memcpy(p + 14, _peerIp.b, 4); nn_macCopy(p + 18, _ourMac); memcpy(p + 24, _ourIp.b, 4);
    _corpusLen[i++] = 42;
    /* 2: ICMP echo request. */
    f = _corpus[i]; p = ethHdr(f, _ourMac, NN_ETH_TYPE_IP); p = ipHdr(p, NN_IP_PROTO_ICMP, 8 + 32, _ourIp);
    memset(p, 0, 8); p[0] = 8; nn_put16(p + 4, 0x1234); nn_put16(p + 6, 1); memcpy(p + 8, payload, 32);
    nn_put16(p + 2, nn_cksum(p, 40));
    _corpusLen[i++] = 14 + 20 + 40;
    /* 3: ICMP port unreachable carrying a UDP header of ours. */
    f = _corpus[i]; p = ethHdr(f, _ourMac, NN_ETH_TYPE_IP); p = ipHdr(p, NN_IP_PROTO_ICMP, 8 + 28, _ourIp);
    memset(p, 0, 36); p[0] = 3; p[1] = 3;
    p[8] = 0x45; nn_put16(p + 10, 36); p[16] = 64; p[17] = 17; memcpy(p + 20, _ourIp.b, 4); memcpy(p + 24, _peerIp.b, 4);
    nn_put16(p + 28, 5000); nn_put16(p + 30, 7); nn_put16(p + 32, 16);
    nn_put16(p + 2, nn_cksum(p, 36));
    _corpusLen[i++] = 14 + 20 + 36;
    /* 4: UDP to our socket. */
    f = _corpus[i]; p = ethHdr(f, _ourMac, NN_ETH_TYPE_IP); p = ipHdr(p, NN_IP_PROTO_UDP, 8 + 40, _ourIp);
    udpDgram(p, 7, 5000, payload, 40, _ourIp);
    _corpusLen[i++] = 14 + 20 + 48;
    /* 5: UDP to a closed port. */
    f = _corpus[i]; p = ethHdr(f, _ourMac, NN_ETH_TYPE_IP); p = ipHdr(p, NN_IP_PROTO_UDP, 8 + 4, _ourIp);
    udpDgram(p, 7, 5001, payload, 4, _ourIp);
    _corpusLen[i++] = 14 + 20 + 12;
    /* 6: a DNS answer to port 53 traffic (our query port is unknown here: random). */
    f = _corpus[i]; p = ethHdr(f, _ourMac, NN_ETH_TYPE_IP); p = ipHdr(p, NN_IP_PROTO_UDP, 8 + 45, _ourIp);
    {
        static const uint8_t ans[45] = { 0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
            4, 'f', 'u', 'z', 'z', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1,
            0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1 };
        udpDgram(p, 53, 49152, ans, 45, _ourIp);
    }
    _corpusLen[i++] = 14 + 20 + 53;
    /* 7..11: TCP segments to the connection (ports filled in at run time), with data,
       with FIN, with RST, a bare ACK, a SYN to the listener. */
    f = _corpus[i]; p = ethHdr(f, _ourMac, NN_ETH_TYPE_IP); p = ipHdr(p, NN_IP_PROTO_TCP, 20 + 64, _ourIp);
    tcpSeg(p, 80, 0, 0, 0, NN_TCP_ACK | NN_TCP_PSH, 8192, payload, 64, _ourIp);
    _corpusLen[i++] = 14 + 20 + 84;
    f = _corpus[i]; p = ethHdr(f, _ourMac, NN_ETH_TYPE_IP); p = ipHdr(p, NN_IP_PROTO_TCP, 20, _ourIp);
    tcpSeg(p, 80, 0, 0, 0, NN_TCP_ACK | NN_TCP_FIN, 8192, NULL, 0, _ourIp);
    _corpusLen[i++] = 14 + 20 + 20;
    f = _corpus[i]; p = ethHdr(f, _ourMac, NN_ETH_TYPE_IP); p = ipHdr(p, NN_IP_PROTO_TCP, 20, _ourIp);
    tcpSeg(p, 80, 0, 0, 0, NN_TCP_RST, 8192, NULL, 0, _ourIp);
    _corpusLen[i++] = 14 + 20 + 20;
    f = _corpus[i]; p = ethHdr(f, _ourMac, NN_ETH_TYPE_IP); p = ipHdr(p, NN_IP_PROTO_TCP, 20, _ourIp);
    tcpSeg(p, 80, 0, 0, 0, NN_TCP_ACK, 8192, NULL, 0, _ourIp);
    _corpusLen[i++] = 14 + 20 + 20;
    f = _corpus[i]; p = ethHdr(f, _ourMac, NN_ETH_TYPE_IP); p = ipHdr(p, NN_IP_PROTO_TCP, 24, _ourIp);
    tcpSeg(p, 40000, 8080, 70000, 0, NN_TCP_SYN, 4000, "\x02\x04\x05\xb4", 4, _ourIp);
    p[12] = 0x60;
    nn_put16(p + 16, 0);
    nn_put16(p + 16, nn_cksumFinish(nn_cksumAdd(nn_cksumPseudo(_peerIp, _ourIp, NN_IP_PROTO_TCP, 24), p, 24)));
    _corpusLen[i++] = 14 + 20 + 24;
    /* 12: an IP packet for another host, 13: a broadcast UDP datagram. */
    f = _corpus[i]; p = ethHdr(f, _ourMac, NN_ETH_TYPE_IP); p = ipHdr(p, NN_IP_PROTO_UDP, 8 + 4, nn_ip4(10, 0, 77, 9));
    udpDgram(p, 7, 5000, payload, 4, nn_ip4(10, 0, 77, 9));
    _corpusLen[i++] = 14 + 20 + 12;
    f = _corpus[i]; p = ethHdr(f, nn_eth_broadcast, NN_ETH_TYPE_IP); p = ipHdr(p, NN_IP_PROTO_UDP, 8 + 4, nn_ip4(255, 255, 255, 255));
    udpDgram(p, 68, 5000, payload, 4, nn_ip4(255, 255, 255, 255));
    _corpusLen[i++] = 14 + 20 + 12;
}

/* --- Keeping the connection alive so the TCP paths stay reachable ---------------------------- */

#define PEER_ISS 1000u

static void connectTcp(void)
{
    uint8_t f[MAX_FRAME];
    uint8_t *p;
    nn_buf_t *pB;

    CHECK_EQ(nn_tcpOpen(&_tcp, _rxRing, sizeof(_rxRing), _txRing, sizeof(_txRing)), NN_OK);
    CHECK_EQ(nn_tcpConnect(&_tcp, _peerIp, 80, 0), NN_ERR_PENDING);
    p = ethHdr(f, _ourMac, NN_ETH_TYPE_IP); p = ipHdr(p, NN_IP_PROTO_TCP, 20, _ourIp);
    tcpSeg(p, 80, _tcp.localPort, PEER_ISS, _tcp.iss + 1, NN_TCP_SYN | NN_TCP_ACK, 8192, NULL, 0, _ourIp);
    pB = nn_bufAlloc(NN_CFG_RX_OFFSET);
    memcpy(nn_bufPut(pB, 54), f, 54);
    pB->pDev = &_dev;
    nn_net_input(pB);
    CHECK_EQ(nn_tcpState(&_tcp), NN_TCP_ESTABLISHED);
}

/** Make the TCP corpus entries address the current connection with plausible numbers. */
static void refreshTcpCorpus(void)
{
    unsigned i;
    for(i=7; i<=10; ++i)
    {
        uint8_t *p = _corpus[i] + 34;
        const uint16_t len = (uint16_t)(_corpusLen[i] - 34);
        nn_put16(p + 2, _tcp.localPort);
        nn_put32(p + 4, _tcp.rcvNxt + (rndBelow(4) == 0 ? rndBelow(3000) : 0));
        nn_put32(p + 8, _tcp.sndNxt - (rndBelow(4) == 0 ? rndBelow(200) : 0));
        nn_put16(p + 16, 0);
        nn_put16(p + 16, nn_cksumFinish(nn_cksumAdd(nn_cksumPseudo(_peerIp, _ourIp, NN_IP_PROTO_TCP, len), p, len)));
    }
}

/* --- Mutation ------------------------------------------------------------------------------- */

static void repairChecksums(uint8_t *f, uint16_t len)
{
    uint8_t *ip = f + 14;
    uint16_t ihl, total, l4;
    nn_ip4_t s, d;
    if(len < 34  ||  nn_get16(f + 12) != NN_ETH_TYPE_IP)
        return;
    ihl = (uint16_t)((ip[0] & 0x0F) * 4);
    if(ihl < 20  ||  14 + ihl > len)
        return;
    nn_put16(ip + 10, 0);
    nn_put16(ip + 10, nn_cksum(ip, ihl));
    total = nn_get16(ip + 2);
    if(total < ihl  ||  14 + total > len)
        return;
    l4 = (uint16_t)(total - ihl);
    memcpy(s.b, ip + 12, 4); memcpy(d.b, ip + 16, 4);
    if(ip[9] == NN_IP_PROTO_TCP  &&  l4 >= 20)
    {
        uint8_t *t = ip + ihl;
        nn_put16(t + 16, 0);
        nn_put16(t + 16, nn_cksumFinish(nn_cksumAdd(nn_cksumPseudo(s, d, NN_IP_PROTO_TCP, l4), t, l4)));
    }
    else if(ip[9] == NN_IP_PROTO_UDP  &&  l4 >= 8)
    {
        uint8_t *u = ip + ihl;
        uint16_t ulen = nn_get16(u + 4);
        if(ulen > l4  ||  ulen < 8) ulen = l4;
        nn_put16(u + 6, 0);
        nn_put16(u + 6, nn_cksumFinish(nn_cksumAdd(nn_cksumPseudo(s, d, NN_IP_PROTO_UDP, ulen), u, ulen)));
        if(nn_get16(u + 6) == 0) nn_put16(u + 6, 0xFFFF);
    }
    else if(ip[9] == NN_IP_PROTO_ICMP  &&  l4 >= 4)
    {
        uint8_t *c = ip + ihl;
        nn_put16(c + 2, 0);
        nn_put16(c + 2, nn_cksum(c, l4));
    }
}

static uint16_t mutate(uint8_t *f, uint16_t len)
{
    const unsigned n = 1 + rndBelow(4);
    unsigned i;
    for(i=0; i<n; ++i)
    {
        switch(rndBelow(9))
        {
        case 0: if(len) f[rndBelow(len)] ^= (uint8_t)(1u << rndBelow(8)); break;
        case 1: if(len) f[rndBelow(len)] = (uint8_t)rnd(); break;
        case 2: if(len > 14) len = (uint16_t)(14 + rndBelow(len - 14u)); break;        /* truncate */
        case 3: if(len > 1) len = (uint16_t)rndBelow(len); break;                       /* truncate hard */
        case 4: { uint16_t add = (uint16_t)rndBelow(300); if(len + add > MAX_FRAME) add = (uint16_t)(MAX_FRAME - len);
                  while(add--) f[len++] = (uint8_t)rnd(); } break;                      /* grow */
        case 5: if(len > 1) { uint32_t k = rndBelow(len - 1u); f[k] = (uint8_t)rnd(); f[k + 1] = (uint8_t)rnd(); } break;
        case 6: if(len > 40) { uint32_t k = 14 + rndBelow(len - 40u); memset(f + k, (int)rndBelow(256), 1 + rndBelow(20)); } break;
        case 7: if(len > 2) { uint32_t k = rndBelow(len - 1u); f[k] = 0xFF; f[k + 1] = 0xFF; } break;
        default: if(len > 36) { f[14 + 2 + rndBelow(2)] = (uint8_t)rnd(); } break;      /* IP total length */
        }
    }
    if(rndBelow(3) != 0)
        repairChecksums(f, len);
    return len;
}

static void checkInvariants(void)
{
    CHECK(_tcp.rxLen <= _tcp.rxSize);
    CHECK(_tcp.txLen <= _tcp.txSize);
    CHECK(_tcp.rxHead < _tcp.rxSize);
    CHECK(_tcp.txHead < _tcp.txSize);
    CHECK((uint32_t)_tcp.oooOff + _tcp.oooLen <= (uint32_t)(_tcp.rxSize - _tcp.rxLen)  ||  _tcp.oooLen == 0);
    if(_tcp.state != NN_TCP_CLOSED)                     /* CLOSED keeps stale numbers */
    {
        CHECK((int32_t)(_tcp.sndNxt - _tcp.sndUna) >= 0);
        CHECK(_tcp.sndNxt - _tcp.sndUna <= (uint32_t)_tcp.txLen + 1u);
    }
    CHECK(_acc.rxLen <= _acc.rxSize);
}

int main(void)
{
    const char *envIters = getenv("NN_FUZZ_ITERS"), *envSeed = getenv("NN_FUZZ_SEED");
    const uint32_t iters = envIters ? (uint32_t)strtoul(envIters, NULL, 10) : 200000u;
    const uint32_t seed = envSeed ? (uint32_t)strtoul(envSeed, NULL, 10) : 1u;
    uint32_t it, reconnects = 0, reaccepts = 0;
    nn_bufStats_t bs;
    uint8_t frame[MAX_FRAME];
    uint8_t scratch[256];

    _rng = seed ? seed : 1u;
    nn_os_testFreeze(true);                             /* sequence numbers derive from the clock */
    nn_os_testAdvance(1000);
    CHECK_EQ(nn_init(), NN_OK);
    memset(&_dev, 0, sizeof(_dev));
    _dev.name = "fake"; _dev.type = NN_DEV_ETHERNET; _dev.flags = NN_DEVF_LINK | NN_DEVF_BROADCAST;
    _dev.hwlen = 6; nn_macCopy(_dev.hwaddr, _ourMac); _dev.mtu = 1500; _dev.pOps = &_ops;
    CHECK_EQ(nn_netdevRegister(&_dev), NN_OK);
    CHECK_EQ(nn_ifaceAdd(&_dev, &_if, _ourIp, _mask, _peerIp), NN_OK);
    buildCorpus();

    nn_lock();
    {
        nn_buf_t *pB = nn_bufAlloc(NN_CFG_RX_OFFSET);
        memcpy(nn_bufPut(pB, _corpusLen[1]), _corpus[1], _corpusLen[1]);   /* learn the peer */
        pB->pDev = &_dev;
        nn_net_input(pB);
    }
    CHECK_EQ(nn_udpOpen(&_udp), NN_OK);
    CHECK_EQ(nn_udpBind(&_udp, nn_ip4(0, 0, 0, 0), 5000), NN_OK);
    CHECK_EQ(nn_tcpOpen(&_listen, NULL, 0, NULL, 0), NN_OK);
    CHECK_EQ(nn_tcpBind(&_listen, nn_ip4(0, 0, 0, 0), 8080), NN_OK);
    CHECK_EQ(nn_tcpListen(&_listen), NN_OK);
    CHECK_EQ(nn_tcpOpen(&_acc, _rxRing2, sizeof(_rxRing2), _txRing2, sizeof(_txRing2)), NN_OK);
    CHECK_EQ(nn_tcpAccept(&_listen, &_acc, 0), NN_ERR_PENDING);
    nn_dnsSetServer(_peerIp);
    connectTcp();

    for(it=0; it<iters; ++it)
    {
        const unsigned k = rndBelow(CORPUS);
        uint16_t len = _corpusLen[k];
        nn_buf_t *pB;

        if(k >= 7  &&  k <= 10)
            refreshTcpCorpus();
        memcpy(frame, _corpus[k], len);
        if(rndBelow(8) != 0)
            len = mutate(frame, len);
        pB = nn_bufAlloc(NN_CFG_RX_OFFSET);
        if(pB == NULL)
        {
            nn_timer_run();
            continue;
        }
        memcpy(nn_bufPut(pB, len), frame, len);
        pB->pDev = &_dev;
        nn_net_input(pB);
        checkInvariants();

        /* Keep the application side moving: read, write, close, reopen. */
        if(rndBelow(16) == 0  &&  nn_tcpAvailable(&_tcp))
            (void)nn_tcpRecv(&_tcp, scratch, 1 + rndBelow(sizeof(scratch)), 0);
        if(rndBelow(32) == 0)
            (void)nn_tcpSend(&_tcp, scratch, 1 + rndBelow(sizeof(scratch)), 0);
        if(rndBelow(64) == 0  &&  nn_tcpAvailable(&_acc))
            (void)nn_tcpRecv(&_acc, scratch, sizeof(scratch), 0);
        if(rndBelow(400) == 0  &&  _pDns == NULL)
            (void)nn_dnsQuery(&_pDns, "fuzz.test", 1000, dnsCb, NULL);
        if(rndBelow(4) == 0)
        {
            nn_os_testAdvance(rndBelow(3) == 0 ? 1 + rndBelow(70000) : 1 + rndBelow(50));
            nn_timer_run();
        }
        if(nn_tcpState(&_tcp) == NN_TCP_CLOSED)
        {
            ++ reconnects;
            connectTcp();
        }
        else if(rndBelow(2000) == 0)
            nn_tcpClose(&_tcp);
        if(nn_tcpState(&_acc) == NN_TCP_CLOSED  &&  _acc.pListener == NULL)
        {
            ++ reaccepts;
            CHECK_EQ(nn_tcpOpen(&_acc, _rxRing2, sizeof(_rxRing2), _txRing2, sizeof(_txRing2)), NN_OK);
            CHECK_EQ(nn_tcpAccept(&_listen, &_acc, 0), NN_ERR_PENDING);
        }
        else if(_acc.state >= NN_TCP_ESTABLISHED  &&  rndBelow(500) == 0)
            nn_tcpAbort(&_acc);
        if(test_failures != 0)
        {
            printf("test_fuzz: failure at iteration %lu, seed %lu, corpus %u\n",
                   (unsigned long)it, (unsigned long)seed, k);
            break;
        }
    }
    nn_tcpAbort(&_tcp);
    nn_tcpAbort(&_acc);
    nn_tcpClose(&_acc);
    nn_tcpClose(&_listen);
    nn_udpClose(&_udp);
    for(it=0; it<10; ++it)                              /* ARP gives up on parked replies to
                                                           mutated addresses after 3 s */
    {
        nn_os_testAdvance(1000);
        nn_timer_run();
    }
    nn_os_testAdvance(120000);
    nn_timer_run();
    nn_bufGetStats(&bs);
    CHECK_EQ(bs.free, NN_CFG_NUM_BUFS);
    {
        nn_tcpStats_t ts; nn_udpStats_t us; nn_ipStats_t is; nn_icmpStats_t cs; nn_arpStats_t as;
        nn_tcpGetStats(&ts); nn_udpGetStats(&us); nn_ipGetStats(&is); nn_icmpGetStats(&cs); nn_arpGetStats(&as);
        printf("test_fuzz: %lu frames, seed %lu, tx %u | ip bad=%lu | arp bad=%lu | icmp bad=%lu | udp bad=%lu badCsum=%lu | "
               "tcp bad=%lu badCsum=%lu noSock=%lu resets=%lu ooo=%lu dup=%lu rexmit=%lu | reconnects %lu reaccepts %lu\n",
               (unsigned long)iters, (unsigned long)seed, _nTx,
               (unsigned long)(is.rxBadHeader + is.rxBadChecksum), (unsigned long)as.rxBad, (unsigned long)cs.rxBad,
               (unsigned long)us.rxBad, (unsigned long)us.rxBadChecksum,
               (unsigned long)ts.rxBad, (unsigned long)ts.rxBadChecksum, (unsigned long)ts.rxNoSocket,
               (unsigned long)ts.rxResets, (unsigned long)ts.rxOoo, (unsigned long)ts.rxDup, (unsigned long)ts.rexmits,
               (unsigned long)reconnects, (unsigned long)reaccepts);
    }
    nn_unlock();
    test_finish("test_fuzz");
    return 0;
}
