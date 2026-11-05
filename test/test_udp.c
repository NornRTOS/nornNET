/**
 * @file test_udp.c
 * Pure unit test (POSIX OS layer, synthetic frames in, transmitted frames captured):
 * UDP delivery and filtering, checksums, port unreachable, queue limit, send path, the
 * DHCP client through a full exchange plus renewal and NAK, and the DNS resolver with a
 * compressed answer, a negative answer, retries and the cache.
 */

#include <string.h>

#include "nn_net.h"
#include "nn_eth.h"
#include "nn_ip.h"
#include "nn_udp.h"
#include "nn_dhcp.h"
#include "nn_dns.h"
#include "nn_icmp.h"
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
static nn_buf_t *_tx[8];
static unsigned _nTx;

static nn_err_t fakeTransmit(nn_netdev_t *pDev, nn_buf_t *pB)
{
    (void)pDev;
    if(_nTx < 8) _tx[_nTx++] = pB; else nn_bufFree(pB);
    return NN_OK;
}
static const nn_netdevOps_t _ops = { NULL, NULL, fakeTransmit };

static void clearTx(void)
{
    unsigned i;
    for(i=0; i<_nTx; ++i) nn_bufFree(_tx[i]);
    _nTx = 0;
}

static const uint8_t *ipOf(const nn_buf_t *pB) { return pB->pData + NN_ETH_HDR_LEN; }
static const uint8_t *udpOf(const nn_buf_t *pB) { return ipOf(pB) + 20; }

/** Build an incoming UDP datagram as an Ethernet frame; checksum 0 = none, 1 = correct, 2 = wrong. */
static nn_buf_t *udpFrame(nn_ip4_t src, uint16_t sport, nn_ip4_t dst, uint16_t dport,
                          const uint8_t *payload, uint16_t n, int csumMode, bool bcast)
{
    nn_buf_t *pB = nn_bufAlloc(NN_CFG_RX_OFFSET);
    nn_ethHdr_t *pE = (nn_ethHdr_t *)nn_bufPut(pB, NN_ETH_HDR_LEN);
    uint8_t *pIp, *pU;

    nn_macCopy(pE->dst, bcast ? nn_eth_broadcast : _ourMac);
    nn_macCopy(pE->src, _peerMac);
    nn_put16(pE->type, NN_ETH_TYPE_IP);
    pIp = nn_bufPut(pB, 20);
    memset(pIp, 0, 20);
    pIp[0] = 0x45;
    nn_put16(pIp + 2, (uint16_t)(28 + n));
    pIp[8] = 64;
    pIp[9] = NN_IP_PROTO_UDP;
    memcpy(pIp + 12, src.b, 4);
    memcpy(pIp + 16, dst.b, 4);
    nn_put16(pIp + 10, nn_cksum(pIp, 20));
    pU = nn_bufPut(pB, (uint16_t)(8 + n));
    nn_put16(pU, sport);
    nn_put16(pU + 2, dport);
    nn_put16(pU + 4, (uint16_t)(8 + n));
    pU[6] = pU[7] = 0;
    memcpy(pU + 8, payload, n);
    if(csumMode != 0)
    {
        uint32_t sum = nn_cksumPseudo(src, dst, NN_IP_PROTO_UDP, (uint16_t)(8 + n));
        uint16_t c = nn_cksumFinish(nn_cksumAdd(sum, pU, (uint16_t)(8 + n)));
        if(c == 0) c = 0xFFFF;
        if(csumMode == 2) c ^= 0x0101;
        nn_put16(pU + 6, c);
    }
    pB->pDev = &_dev;
    return pB;
}

static unsigned _readable;
static void onReadable(nn_udp_t *pS, void *arg) { (void)pS; (void)arg; ++_readable; }

/** Teach ARP a neighbour by feeding its reply. */
static void learn(const uint8_t *mac, nn_ip4_t ip)
{
    nn_buf_t *pB = nn_bufAlloc(NN_CFG_RX_OFFSET);
    nn_ethHdr_t *pE = (nn_ethHdr_t *)nn_bufPut(pB, NN_ETH_HDR_LEN);
    uint8_t *a = nn_bufPut(pB, 28);
    nn_macCopy(pE->dst, _ourMac); nn_macCopy(pE->src, mac); nn_put16(pE->type, NN_ETH_TYPE_ARP);
    nn_put16(a, 1); nn_put16(a + 2, 0x0800); a[4] = 6; a[5] = 4; nn_put16(a + 6, 2);
    nn_macCopy(a + 8, mac); memcpy(a + 14, ip.b, 4);
    nn_macCopy(a + 18, _ourMac); memcpy(a + 24, _ourIp.b, 4);
    pB->pDev = &_dev;
    nn_net_input(pB);
}

static void testUdp(void)
{
    nn_udp_t sAny, sSpecific, sConn, sUnbound;
    nn_udpStats_t st;
    nn_bufStats_t bs;
    nn_ip4_t from;
    uint16_t port;
    uint8_t buf[64];
    int32_t n;
    unsigned i;
    static const uint8_t hello[] = "hello";

    learn(_peerMac, _peerIp);
    CHECK_EQ(nn_udpOpen(&sAny), NN_OK);
    CHECK_EQ(nn_udpOpen(&sSpecific), NN_OK);
    CHECK_EQ(nn_udpOpen(&sConn), NN_OK);
    CHECK_EQ(nn_udpOpen(&sUnbound), NN_OK);
    CHECK_EQ(nn_udpBind(&sAny, nn_ip4(0, 0, 0, 0), 5000), NN_OK);
    CHECK_EQ(nn_udpBind(&sSpecific, _ourIp, 5001), NN_OK);
    CHECK_EQ(nn_udpBind(&sUnbound, nn_ip4(0, 0, 0, 0), 5000), NN_ERR_EXIST);
    CHECK_EQ(nn_udpBind(&sUnbound, _ourIp, 5001), NN_ERR_EXIST);
    CHECK_EQ(nn_udpBind(&sConn, nn_ip4(0, 0, 0, 0), 5002), NN_OK);
    CHECK_EQ(nn_udpConnect(&sConn, _peerIp, 7777), NN_OK);
    nn_udpOnReadable(&sAny, onReadable, NULL);

    /* Plain delivery with checksum, and with checksum 0. */
    nn_net_input(udpFrame(_peerIp, 4444, _ourIp, 5000, hello, 5, 1, false));
    CHECK_EQ(nn_udpAvailable(&sAny), 1);
    CHECK_EQ(_readable, 1);
    nn_net_input(udpFrame(_peerIp, 4445, _ourIp, 5000, hello, 5, 0, false));
    CHECK_EQ(nn_udpAvailable(&sAny), 2);
    n = nn_udpRecvFrom(&sAny, buf, sizeof(buf), &from, &port, 0);
    CHECK_EQ(n, 5);
    CHECK(nn_ip4Equal(from, _peerIp)  &&  port == 4444  &&  memcmp(buf, "hello", 5) == 0);
    n = nn_udpRecvFrom(&sAny, buf, 2, &from, &port, 0);        /* truncation */
    CHECK_EQ(n, 5);
    CHECK(port == 4445  &&  buf[0] == 'h'  &&  buf[1] == 'e'  &&  buf[2] == 'l');  /* buf[2] from before */
    CHECK_EQ(nn_udpRecvFrom(&sAny, buf, sizeof(buf), NULL, NULL, 0), NN_ERR_TIMEOUT);

    /* Bad checksum dropped, bad length dropped. */
    nn_net_input(udpFrame(_peerIp, 4444, _ourIp, 5000, hello, 5, 2, false));
    {
        nn_buf_t *pB = udpFrame(_peerIp, 4444, _ourIp, 5000, hello, 5, 0, false);
        nn_put16(pB->pData + NN_ETH_HDR_LEN + 20 + 4, 100);     /* UDP length > IP payload */
        nn_net_input(pB);
    }
    CHECK_EQ(nn_udpAvailable(&sAny), 0);
    nn_udpGetStats(&st);
    CHECK_EQ(st.rxBadChecksum, 1);
    CHECK_EQ(st.rxBad, 1);

    /* Specific address socket: only its address. Broadcast to 5001 goes nowhere (no error). */
    nn_net_input(udpFrame(_peerIp, 1, _ourIp, 5001, hello, 5, 1, false));
    CHECK_EQ(nn_udpAvailable(&sSpecific), 1);
    nn_net_input(udpFrame(_peerIp, 1, nn_ip4(10, 0, 77, 255), 5001, hello, 5, 1, true));
    CHECK_EQ(nn_udpAvailable(&sSpecific), 1);
    CHECK_EQ(_nTx, 0);
    /* Broadcast to the any-socket is delivered. */
    nn_net_input(udpFrame(_peerIp, 1, nn_ip4(255, 255, 255, 255), 5000, hello, 5, 1, true));
    CHECK_EQ(nn_udpAvailable(&sAny), 1);
    nn_bufFree(nn_udpRecvBuf(&sAny, NULL, NULL, 0));
    nn_bufFree(nn_udpRecvBuf(&sSpecific, NULL, NULL, 0));

    /* Connected socket: only its peer. */
    nn_net_input(udpFrame(_peerIp, 7777, _ourIp, 5002, hello, 5, 1, false));
    CHECK_EQ(nn_udpAvailable(&sConn), 1);
    nn_net_input(udpFrame(_peerIp, 7778, _ourIp, 5002, hello, 5, 1, false));
    CHECK_EQ(nn_udpAvailable(&sConn), 1);
    CHECK_EQ(_nTx, 1);                                          /* port unreachable */
    CHECK_EQ(ipOf(_tx[0])[9], NN_IP_PROTO_ICMP);
    CHECK(ipOf(_tx[0])[20] == 3  &&  ipOf(_tx[0])[21] == 3);
    CHECK_EQ(nn_get16(ipOf(_tx[0]) + 28 + 20 + 2), 5002);     /* quoted dst port */
    clearTx();
    nn_bufFree(nn_udpRecvBuf(&sConn, NULL, NULL, 0));

    /* No socket at all: port unreachable, counted. */
    nn_net_input(udpFrame(_peerIp, 1, _ourIp, 9, hello, 5, 1, false));
    CHECK_EQ(_nTx, 1);
    clearTx();
    nn_udpGetStats(&st);
    CHECK_EQ(st.rxNoSocket, 3);                                 /* incl. the broadcast to 5001 */

    /* Queue limit: the oldest NN_CFG_UDP_RXQ stay, newer are dropped. */
    for(i=0; i<NN_CFG_UDP_RXQ + 2; ++i)
    {
        uint8_t b = (uint8_t)i;
        nn_net_input(udpFrame(_peerIp, 1, _ourIp, 5000, &b, 1, 1, false));
    }
    CHECK_EQ(nn_udpAvailable(&sAny), NN_CFG_UDP_RXQ);
    CHECK_EQ(sAny.rxDropped, 2);
    for(i=0; i<NN_CFG_UDP_RXQ; ++i)
    {
        n = nn_udpRecvFrom(&sAny, buf, sizeof(buf), NULL, NULL, 0);
        CHECK(n == 1  &&  buf[0] == i);
    }

    /* Send: header, length, checksum, ephemeral port, connected send. */
    CHECK_EQ(nn_udpSendTo(&sUnbound, hello, 5, _peerIp, 4000), NN_OK);
    CHECK_EQ(_nTx, 1);
    {
        const uint8_t *q = udpOf(_tx[0]);
        uint32_t sum;
        CHECK(nn_macEqual(_tx[0]->pData, _peerMac));
        CHECK_EQ(ipOf(_tx[0])[9], NN_IP_PROTO_UDP);
        CHECK(nn_get16(q) >= NN_CFG_UDP_EPHEMERAL);
        CHECK_EQ(nn_get16(q), sUnbound.localPort);
        CHECK_EQ(nn_get16(q + 2), 4000);
        CHECK_EQ(nn_get16(q + 4), 13);
        sum = nn_cksumPseudo(_ourIp, _peerIp, NN_IP_PROTO_UDP, 13);
        CHECK_EQ(nn_cksumFinish(nn_cksumAdd(sum, q, 13)), 0);
        CHECK(memcmp(q + 8, "hello", 5) == 0);
        clearTx();
    }
    CHECK_EQ(nn_udpSend(&sConn, hello, 2), NN_OK);
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(nn_get16(udpOf(_tx[0])), 5002);
    CHECK_EQ(nn_get16(udpOf(_tx[0]) + 2), 7777);
    clearTx();
    CHECK_EQ(nn_udpSend(&sAny, hello, 2), NN_ERR_INVAL);       /* not connected */
    /* Two ephemeral sockets get different ports. */
    {
        nn_udp_t a, b;
        nn_udpOpen(&a); nn_udpOpen(&b);
        CHECK_EQ(nn_udpBind(&a, nn_ip4(0, 0, 0, 0), 0), NN_OK);
        CHECK_EQ(nn_udpBind(&b, nn_ip4(0, 0, 0, 0), 0), NN_OK);
        CHECK(a.localPort != b.localPort  &&  a.localPort != 0);
        nn_udpClose(&a); nn_udpClose(&b);
    }

    /* Close frees queued datagrams; a datagram for a closed port is unreachable. */
    nn_net_input(udpFrame(_peerIp, 1, _ourIp, 5000, hello, 5, 1, false));
    CHECK_EQ(nn_udpClose(&sAny), NN_OK);
    CHECK_EQ(nn_udpClose(&sAny), NN_ERR_INVAL);
    nn_net_input(udpFrame(_peerIp, 1, _ourIp, 5000, hello, 5, 1, false));
    CHECK_EQ(_nTx, 1);
    clearTx();
    nn_udpClose(&sSpecific); nn_udpClose(&sConn); nn_udpClose(&sUnbound);
    nn_bufGetStats(&bs);
    CHECK_EQ(bs.free, NN_CFG_NUM_BUFS);
}

/* --- DHCP -------------------------------------------------------------------------------- */

static unsigned _bound, _unbound;
static void onDhcp(nn_dhcp_t *pD, bool bound, void *arg)
{
    (void)pD; (void)arg;
    if(bound) ++_bound; else ++_unbound;
}

/** Build a server reply as the frame the server would send (broadcast). */
static nn_buf_t *dhcpReply(uint8_t type, uint32_t xid, nn_ip4_t yi, nn_ip4_t server, uint32_t lease, bool unicast)
{
    uint8_t msg[300];
    uint8_t *o = msg + 240;
    memset(msg, 0, sizeof(msg));
    msg[0] = 2; msg[1] = 1; msg[2] = 6;
    nn_put32(msg + 4, xid);
    memcpy(msg + 16, yi.b, 4);
    memcpy(msg + 28, _ourMac, 6);
    nn_put32(msg + 236, 0x63825363ul);
    *o++ = 53; *o++ = 1; *o++ = type;
    *o++ = 54; *o++ = 4; memcpy(o, server.b, 4); o += 4;
    *o++ = 1;  *o++ = 4; o[0] = 255; o[1] = 255; o[2] = 255; o[3] = 0; o += 4;
    *o++ = 3;  *o++ = 4; memcpy(o, server.b, 4); o += 4;
    *o++ = 6;  *o++ = 4; o[0] = 10; o[1] = 0; o[2] = 77; o[3] = 53; o += 4;
    *o++ = 51; *o++ = 4; nn_put32(o, lease); o += 4;
    *o++ = 0;                                                   /* a pad */
    *o++ = 255;
    return udpFrame(server, 67, unicast ? yi : nn_ip4(255, 255, 255, 255), 68, msg, sizeof(msg), 1, !unicast);
}

static void testDhcp(void)
{
    static nn_dhcp_t d;
    static nn_iface_t ifd;              /* stays linked after this function returns */
    const nn_ip4_t server = NN_IP4_INIT(10, 0, 77, 1);
    const nn_ip4_t offered = NN_IP4_INIT(10, 0, 77, 42);
    const uint8_t *q;
    uint32_t xid;

    /* A second, address-less interface on the same device gets the lease. */
    CHECK_EQ(nn_ifaceAdd(&_dev, &ifd, nn_ip4(0, 0, 0, 0), nn_ip4(0, 0, 0, 0), nn_ip4(0, 0, 0, 0)), NN_OK);
    nn_unlock();
    CHECK_EQ(nn_dhcpStart(&d, &ifd, onDhcp, NULL), NN_OK);
    nn_lock();
    CHECK_EQ(nn_dhcpState(&d), NN_DHCP_SELECTING);
    CHECK_EQ(_nTx, 1);                                          /* DISCOVER, broadcast */
    CHECK(nn_macIsBroadcast(_tx[0]->pData));
    q = ipOf(_tx[0]);
    CHECK(memcmp(q + 12, "\0\0\0\0", 4) == 0  &&  nn_ip4IsLimitedBroadcast(*(const nn_ip4_t *)(const void *)(q + 16)));
    q = udpOf(_tx[0]);
    CHECK(nn_get16(q) == 68  &&  nn_get16(q + 2) == 67);
    CHECK_EQ(q[8], 1);                                          /* BOOTREQUEST */
    CHECK_EQ(nn_get16(q + 8 + 10), 0x8000);                     /* BROADCAST flag */
    CHECK_EQ(q[8 + 240 + 2], 1);                                /* DISCOVER */
    xid = nn_get32(q + 8 + 4);
    CHECK_EQ(nn_get16(q + 4), 8 + 300);                         /* padded to 300 */
    clearTx();

    /* Retransmission after 2 s, then 4 s. */
    nn_os_testAdvance(2000); nn_timer_run();
    CHECK_EQ(_nTx, 1);
    clearTx();
    nn_os_testAdvance(3000); nn_timer_run();
    CHECK_EQ(_nTx, 0);
    nn_os_testAdvance(1000); nn_timer_run();
    CHECK_EQ(_nTx, 1);
    clearTx();

    /* An offer with the wrong xid is ignored; the right one gets a REQUEST. */
    nn_net_input(dhcpReply(2, xid + 1, offered, server, 600, false));
    CHECK_EQ(_nTx, 0);
    nn_net_input(dhcpReply(2, xid, offered, server, 600, false));
    CHECK_EQ(nn_dhcpState(&d), NN_DHCP_REQUESTING);
    CHECK_EQ(_nTx, 1);
    q = udpOf(_tx[0]) + 8 + 240;
    CHECK_EQ(q[2], 3);                                          /* REQUEST */
    {   /* options 50 and 54 present with the offered address and server */
        const uint8_t *o = q; bool has50 = false, has54 = false;
        while(*o != 255) { if(*o == 50 && memcmp(o + 2, offered.b, 4) == 0) has50 = true;
                           if(*o == 54 && memcmp(o + 2, server.b, 4) == 0) has54 = true;
                           o += 2 + o[1]; }
        CHECK(has50 && has54);
    }
    clearTx();

    /* ACK, unicast to the offered address (we have none yet): bound, interface set. */
    nn_net_input(dhcpReply(5, xid, offered, server, 600, true));
    CHECK_EQ(nn_dhcpState(&d), NN_DHCP_BOUND);
    CHECK_EQ(_bound, 1);
    CHECK(nn_ip4Equal(ifd.addr, offered)  &&  nn_ip4Equal(ifd.gw, server)  &&  ifd.mask.b[3] == 0);
    CHECK(nn_ip4Equal(nn_dnsGetServer(), nn_ip4(10, 0, 77, 53)));
    CHECK_EQ(d.leaseS, 600);
    CHECK_EQ(d.t1S, 300);
    CHECK_EQ(d.t2S, 525);

    /* The link came back (nn_dhcpLinkUp, what the net task calls on a driver's link
       change): a broadcast REQUEST with ciaddr confirms the lease at once; the ACK binds
       again without a second bound event. */
    clearTx();
    nn_unlock();
    CHECK_EQ(nn_dhcpLinkUp(&d), NN_OK);
    nn_lock();
    CHECK_EQ(nn_dhcpState(&d), NN_DHCP_REBINDING);
    CHECK_EQ(_nTx, 1);
    CHECK(nn_macIsBroadcast(_tx[0]->pData));
    CHECK(memcmp(udpOf(_tx[0]) + 8 + 12, offered.b, 4) == 0);  /* ciaddr */
    CHECK(nn_ip4Equal(ifd.addr, offered));                      /* address kept meanwhile */
    clearTx();
    nn_net_input(dhcpReply(5, xid, offered, server, 600, true));
    CHECK_EQ(nn_dhcpState(&d), NN_DHCP_BOUND);
    CHECK_EQ(_bound, 1);
    CHECK_EQ(d.verifying, 0);
    /* Unconfirmed after three tries 1.5 s apart: start over, address cleared. */
    nn_unlock();
    CHECK_EQ(nn_dhcpLinkUp(&d), NN_OK);
    nn_lock();
    clearTx();
    nn_os_testAdvance(1500); nn_timer_run();
    CHECK_EQ(nn_dhcpState(&d), NN_DHCP_REBINDING);
    CHECK_EQ(_nTx, 1);
    nn_os_testAdvance(1500); nn_timer_run();
    CHECK_EQ(nn_dhcpState(&d), NN_DHCP_REBINDING);
    CHECK_EQ(_nTx, 2);
    nn_os_testAdvance(1500); nn_timer_run();
    CHECK_EQ(nn_dhcpState(&d), NN_DHCP_SELECTING);
    CHECK_EQ(_unbound, 1);
    CHECK(nn_ip4IsAny(ifd.addr));
    CHECK_EQ(_nTx, 3);
    CHECK_EQ(udpOf(_tx[2])[8 + 240 + 2], 1);                    /* DISCOVER */
    clearTx();
    /* Back on track: offer and ack as before. */
    xid = d.xid;
    nn_net_input(dhcpReply(2, xid, offered, server, 600, false));
    CHECK_EQ(nn_dhcpState(&d), NN_DHCP_REQUESTING);
    clearTx();
    nn_net_input(dhcpReply(5, xid, offered, server, 600, true));
    CHECK_EQ(nn_dhcpState(&d), NN_DHCP_BOUND);
    CHECK_EQ(_bound, 2);
    _bound = 1; _unbound = 0;                                   /* as the checks below expect */

    /* T1: renewing, unicast REQUEST to the server with ciaddr. */
    nn_os_testAdvance(300000); nn_timer_run();
    CHECK_EQ(nn_dhcpState(&d), NN_DHCP_RENEWING);
    CHECK_EQ(_nTx, 1);
    q = ipOf(_tx[0]);
    CHECK(memcmp(q + 16, server.b, 4) == 0  &&  memcmp(q + 12, offered.b, 4) == 0);
    CHECK(memcmp(udpOf(_tx[0]) + 8 + 12, offered.b, 4) == 0);  /* ciaddr */
    CHECK_EQ(nn_get16(udpOf(_tx[0]) + 8 + 10), 0);              /* no BROADCAST flag */
    clearTx();
    nn_net_input(dhcpReply(5, xid, offered, server, 600, true));
    CHECK_EQ(nn_dhcpState(&d), NN_DHCP_BOUND);
    CHECK_EQ(_bound, 1);                                        /* no second bound event */

    /* NAK on renewal: back to discover, address cleared, unbound event. */
    nn_os_testAdvance(300000); nn_timer_run();
    CHECK_EQ(nn_dhcpState(&d), NN_DHCP_RENEWING);
    clearTx();
    xid = d.xid;
    nn_net_input(dhcpReply(6, xid, offered, server, 0, true));
    CHECK_EQ(nn_dhcpState(&d), NN_DHCP_SELECTING);
    CHECK_EQ(_unbound, 1);
    CHECK(nn_ip4IsAny(ifd.addr));
    CHECK_EQ(_nTx, 1);
    CHECK_EQ(udpOf(_tx[0])[8 + 240 + 2], 1);                    /* DISCOVER again */
    clearTx();
    nn_unlock();
    CHECK_EQ(nn_dhcpStop(&d), NN_OK);
    nn_lock();
    CHECK_EQ(nn_dhcpState(&d), NN_DHCP_INIT);
    CHECK_EQ(_nTx, 0);                                          /* no RELEASE: was not bound */
    {
        nn_bufStats_t bs;
        nn_bufGetStats(&bs);
        CHECK_EQ(bs.free, NN_CFG_NUM_BUFS);
    }
}

/* --- DNS --------------------------------------------------------------------------------- */

static nn_err_t _dnsRc = NN_ERR_PENDING;
static nn_ip4_t _dnsAddr;
static void onDns(nn_dnsReq_t *pReq, nn_err_t rc, nn_ip4_t addr, void *arg)
{
    (void)pReq; (void)arg;
    _dnsRc = rc;
    _dnsAddr = addr;
}

/** Response to the query in _tx[0]: answer with a CNAME then an A record, using compression. */
static nn_buf_t *dnsResponse(const nn_buf_t *pQuery, uint8_t rcode, bool withA, uint32_t ttl)
{
    const uint8_t *q = udpOf(pQuery) + 8;
    uint16_t qlen = (uint16_t)(nn_get16(udpOf(pQuery) + 4) - 8);
    uint8_t msg[256];
    uint8_t *p = msg;
    uint16_t sport = nn_get16(udpOf(pQuery));

    memcpy(msg, q, qlen);                                       /* header + question */
    nn_put16(msg + 2, (uint16_t)(0x8180u | rcode));             /* QR RD RA */
    nn_put16(msg + 6, withA ? 2 : 0);
    p = msg + qlen;
    if(withA)
    {
        /* CNAME: name -> pointer to the question name, rdata "alias.example" */
        static const uint8_t alias[] = { 5, 'a', 'l', 'i', 'a', 's', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 };
        uint8_t *pAliasName;
        p[0] = 0xC0; p[1] = 12; p += 2;
        nn_put16(p, 5); nn_put16(p + 2, 1); nn_put32(p + 4, ttl); nn_put16(p + 8, sizeof(alias)); p += 10;
        pAliasName = p;
        memcpy(p, alias, sizeof(alias)); p += sizeof(alias);
        /* A: name -> pointer to the alias in the CNAME rdata */
        p[0] = 0xC0; p[1] = (uint8_t)(pAliasName - msg); p += 2;
        nn_put16(p, 1); nn_put16(p + 2, 1); nn_put32(p + 4, ttl); nn_put16(p + 8, 4); p += 10;
        p[0] = 192; p[1] = 0; p[2] = 2; p[3] = 42; p += 4;
    }
    return udpFrame(nn_ip4(10, 0, 77, 53), 15353, _ourIp, sport, msg, (uint16_t)(p - msg), 1, false);
}

static void testDns(void)
{
    nn_dnsReq_t *pReq;
    nn_ip4_t a;
    nn_dnsStats_t st;
    const uint8_t *q;
    static const uint8_t qname[] = { 6, 'n', 'o', 'r', 'n', 'o', 's', 4, 't', 'e', 's', 't', 0 };

    /* The DNS server (10.0.77.53, set by the DHCP ACK) is on link: teach ARP its MAC so
       the query is not parked. */
    learn(_peerMac, nn_ip4(10, 0, 77, 53));
    nn_dnsSetServerPort(15353);
    CHECK_EQ(nn_dnsQuery(&pReq, "nornos.test", 5000, onDns, NULL), NN_OK);
    CHECK(pReq != NULL);
    CHECK_EQ(_nTx, 1);
    q = udpOf(_tx[0]);
    CHECK_EQ(nn_get16(q + 2), 15353);
    CHECK_EQ(nn_get16(q + 8 + 2), 0x0100);                      /* RD */
    CHECK_EQ(nn_get16(q + 8 + 4), 1);
    CHECK(memcmp(q + 8 + 12, qname, sizeof(qname)) == 0);
    CHECK_EQ(nn_get16(q + 8 + 12 + sizeof(qname)), 1);          /* A */
    CHECK_EQ(nn_get16(q + 8 + 12 + sizeof(qname) + 2), 1);      /* IN */

    /* Retry after 2 s, same id. */
    nn_os_testAdvance(NN_CFG_DNS_RETRY_MS); nn_timer_run();
    CHECK_EQ(_nTx, 2);
    CHECK_EQ(nn_get16(udpOf(_tx[1]) + 8), nn_get16(udpOf(_tx[0]) + 8));
    /* Answer with CNAME + A (compression pointers). */
    nn_net_input(dnsResponse(_tx[0], 0, true, 300));
    CHECK_EQ(_dnsRc, NN_OK);
    CHECK(nn_ip4Equal(_dnsAddr, nn_ip4(192, 0, 2, 42)));
    clearTx();
    nn_dnsGetStats(&st);
    CHECK_EQ(st.queries, 2);
    CHECK_EQ(st.retries, 1);
    CHECK_EQ(st.answers, 1);

    /* Cache hit: no query, immediate callback. */
    _dnsRc = NN_ERR_PENDING;
    CHECK_EQ(nn_dnsQuery(&pReq, "NORNOS.test", 5000, onDns, NULL), NN_OK);
    CHECK(pReq == NULL  &&  _dnsRc == NN_OK  &&  nn_ip4Equal(_dnsAddr, nn_ip4(192, 0, 2, 42)));
    CHECK_EQ(_nTx, 0);
    /* Cache expired after the TTL. */
    nn_os_testAdvance(301000); nn_timer_run();
    _dnsRc = NN_ERR_PENDING;
    CHECK_EQ(nn_dnsQuery(&pReq, "nornos.test", 5000, onDns, NULL), NN_OK);
    CHECK(pReq != NULL  &&  _nTx == 1);
    /* NXDOMAIN. */
    nn_net_input(dnsResponse(_tx[0], 3, false, 0));
    CHECK_EQ(_dnsRc, NN_ERR_NODEV);
    clearTx();
    /* No A record in a positive answer: negative. */
    _dnsRc = NN_ERR_PENDING;
    CHECK_EQ(nn_dnsQuery(&pReq, "nornos.test", 5000, onDns, NULL), NN_OK);
    nn_net_input(dnsResponse(_tx[0], 0, false, 0));
    CHECK_EQ(_dnsRc, NN_ERR_NODEV);
    clearTx();
    /* Timeout: retries until the deadline, then NN_ERR_TIMEOUT. */
    _dnsRc = NN_ERR_PENDING;
    CHECK_EQ(nn_dnsQuery(&pReq, "slow.test", 5000, onDns, NULL), NN_OK);
    nn_os_testAdvance(2000); nn_timer_run();
    nn_os_testAdvance(2000); nn_timer_run();
    CHECK_EQ(_dnsRc, NN_ERR_PENDING);
    nn_os_testAdvance(2000); nn_timer_run();
    CHECK_EQ(_dnsRc, NN_ERR_TIMEOUT);
    CHECK_EQ(_nTx, 3);
    clearTx();
    /* A response for an unknown id is ignored; a stale one too. */
    nn_net_input(dnsResponse(_tx[0] == NULL ? NULL : _tx[0], 0, true, 10));
    nn_dnsGetStats(&st);
    CHECK_EQ(st.timeouts, 1);
    CHECK_EQ(st.negative, 2);
    /* Bad names. */
    CHECK_EQ(nn_dnsQuery(&pReq, "", 1000, onDns, NULL), NN_ERR_INVAL);
    CHECK_EQ(nn_dnsQuery(&pReq, "a..b", 1000, onDns, NULL), NN_ERR_INVAL);
    CHECK_EQ(_nTx, 0);
    /* A literal address resolves without the network. */
    nn_unlock();
    CHECK_EQ(nn_dnsResolve("10.1.2.3", &a, 10), NN_OK);
    CHECK(nn_ip4Equal(a, nn_ip4(10, 1, 2, 3)));
    nn_lock();
    {
        nn_bufStats_t bs;
        nn_bufGetStats(&bs);
        CHECK_EQ(bs.free, NN_CFG_NUM_BUFS);
    }
}

int main(void)
{
    nn_os_testFreeze(true);                             /* timers move only by nn_os_testAdvance */
    nn_os_testAdvance(1000);
    CHECK_EQ(nn_init(), NN_OK);
    memset(&_dev, 0, sizeof(_dev));
    _dev.name = "fake"; _dev.type = NN_DEV_ETHERNET; _dev.flags = NN_DEVF_LINK | NN_DEVF_BROADCAST;
    _dev.hwlen = 6; nn_macCopy(_dev.hwaddr, _ourMac); _dev.mtu = 1500; _dev.pOps = &_ops;
    CHECK_EQ(nn_netdevRegister(&_dev), NN_OK);
    CHECK_EQ(nn_ifaceAdd(&_dev, &_if, _ourIp, _mask, _peerIp), NN_OK);

    nn_lock();
    testUdp();
    testDhcp();
    testDns();
    nn_unlock();
    test_finish("test_udp");
    return 0;
}
