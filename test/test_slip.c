/**
 * @file test_slip.c
 * Unit test of the SLIP driver (POSIX OS layer, bytes in, bytes captured): framing and
 * escaping both ways through a ping, empty frames, a bad escape, an oversize frame, pool
 * exhaustion while a frame arrives, console text between frames, UDP over the link, and
 * the buffer pool after it all.
 */

#include <string.h>

#include "nn_net.h"
#include "nn_ip.h"
#include "nn_icmp.h"
#include "nn_udp.h"
#include "nn_cksum.h"
#include "nn_drv_slip.h"
#include "nn_os.h"
#include "testutil.h"

static const nn_ip4_t _us   = NN_IP4_INIT(10, 0, 78, 2);
static const nn_ip4_t _peer = NN_IP4_INIT(10, 0, 78, 1);

static nn_netdev_t _dev;
static nn_slip_t _slip;
static nn_iface_t _if;

/* Everything the driver writes, raw. */
static uint8_t _line[8192];
static unsigned _lineLen;

static void capture(const uint8_t *p, uint16_t n, void *arg)
{
    (void)arg;
    if(_lineLen + n <= sizeof(_line))
    {
        memcpy(_line + _lineLen, p, n);
        _lineLen += n;
    }
}

/** Decode the first frame in the captured bytes into \a out; returns its length, and
    the text that preceded it (if any) in \a text. */
static unsigned firstFrame(uint8_t *out, char *text)
{
    unsigned i = 0, n = 0, t = 0;
    bool esc = false;
    while(i < _lineLen  &&  _line[i] != 0xC0)
        text[t++] = (char)_line[i++];
    text[t] = 0;
    if(i == _lineLen) return 0;
    ++ i;
    for(; i<_lineLen; ++i)
    {
        const uint8_t c = _line[i];
        if(c == 0xC0) { if(n != 0) break; else continue; }
        if(esc) { esc = false; out[n++] = c == 0xDC ? 0xC0 : c == 0xDD ? 0xDB : c; }
        else if(c == 0xDB) esc = true;
        else out[n++] = c;
    }
    return n;
}

static void clearLine(void) { _lineLen = 0; }

/** Encode \a p as the peer would and feed it to the driver. */
static void feed(const uint8_t *p, unsigned n, bool leadingEnd)
{
    static uint8_t enc[4096];
    unsigned i, k = 0;
    if(leadingEnd) enc[k++] = 0xC0;
    for(i=0; i<n; ++i)
    {
        if(p[i] == 0xC0) { enc[k++] = 0xDB; enc[k++] = 0xDC; }
        else if(p[i] == 0xDB) { enc[k++] = 0xDB; enc[k++] = 0xDD; }
        else enc[k++] = p[i];
    }
    enc[k++] = 0xC0;
    nn_drv_slipInput(&_slip, enc, (uint16_t)k);
}

static unsigned ipPacket(uint8_t *p, uint8_t proto, const uint8_t *payload, unsigned n)
{
    memset(p, 0, 20);
    p[0] = 0x45; nn_put16(p + 2, (uint16_t)(20 + n)); p[8] = 64; p[9] = proto;
    memcpy(p + 12, _peer.b, 4); memcpy(p + 16, _us.b, 4);
    nn_put16(p + 10, nn_cksum(p, 20));
    memcpy(p + 20, payload, n);
    return 20 + n;
}

int main(void)
{
    static uint8_t pkt[2048], out[2048], payload[300];
    static char text[256];
    nn_bufStats_t bs;
    unsigned n, i, k;

    nn_os_testFreeze(true);
    CHECK_EQ(nn_init(), NN_OK);
    CHECK_EQ(nn_drv_slipRegister(&_dev, &_slip, capture, NULL), NN_OK);
    CHECK_EQ(_dev.type, NN_DEV_SLIP);
    CHECK(_dev.flags & NN_DEVF_NOARP);
    CHECK_EQ(nn_ifaceAdd(&_dev, &_if, _us, nn_ip4(255, 255, 255, 0), _peer), NN_OK);
    nn_lock();

    /* A ping with every special byte in its payload: reply escaped on the line. */
    {
        uint8_t icmp[8 + 64];
        memset(icmp, 0, 8);
        icmp[0] = 8; nn_put16(icmp + 4, 0x1234); nn_put16(icmp + 6, 1);
        for(i=0; i<64; ++i) icmp[8 + i] = (uint8_t)i;
        icmp[8 + 10] = 0xC0; icmp[8 + 11] = 0xDB; icmp[8 + 12] = 0xDC; icmp[8 + 13] = 0xC0;
        nn_put16(icmp + 2, nn_cksum(icmp, sizeof(icmp)));
        n = ipPacket(pkt, NN_IP_PROTO_ICMP, icmp, sizeof(icmp));
        feed(pkt, n, true);
        CHECK_EQ(_slip.rxFrames, 1);
        CHECK(_lineLen > n + 2);                        /* escapes make it longer */
        CHECK_EQ(_line[0], 0xC0);
        CHECK_EQ(_line[_lineLen - 1], 0xC0);
        k = firstFrame(out, text);
        CHECK_EQ(k, n);
        CHECK_EQ(out[20], 0);                           /* echo reply */
        CHECK(memcmp(out + 12, _us.b, 4) == 0  &&  memcmp(out + 16, _peer.b, 4) == 0);
        CHECK(memcmp(out + 28, icmp + 8, 64) == 0);
        CHECK_EQ(nn_cksum(out + 20, 8 + 64), 0);
        CHECK_EQ(_slip.txFrames, 1);
        clearLine();
        /* Without the leading END, as some peers send. */
        feed(pkt, n, false);
        CHECK_EQ(_slip.rxFrames, 2);
        CHECK_EQ(firstFrame(out, text), n);
        clearLine();
    }

    /* Empty frames do nothing; a bad escape keeps the byte and is counted. */
    {
        static const uint8_t empties[] = { 0xC0, 0xC0, 0xC0 };
        static const uint8_t bad[] = { 0xC0, 0x45, 0xDB, 0x41, 0xC0 };
        nn_drv_slipInput(&_slip, empties, sizeof(empties));
        CHECK_EQ(_slip.rxFrames, 2);
        nn_drv_slipInput(&_slip, bad, sizeof(bad));
        CHECK_EQ(_slip.rxBadEscape, 1);
        CHECK_EQ(_slip.rxFrames, 3);                    /* a 2 byte frame: IP drops it */
        CHECK_EQ(_lineLen, 0);
    }

    /* Oversize: dropped and counted, the following frame is fine. */
    {
        memset(pkt, 0x11, 1600);
        feed(pkt, 1600, true);
        CHECK_EQ(_slip.rxOversize, 1);
        CHECK_EQ(_slip.rxFrames, 3);
        n = ipPacket(pkt, NN_IP_PROTO_ICMP, payload, 0);
        feed(pkt, n, true);
        CHECK_EQ(_slip.rxFrames, 4);
    }

    /* No buffer while a frame arrives: the frame is skipped to its END, then it works. */
    {
        nn_buf_t *held[NN_CFG_NUM_BUFS];
        unsigned h = 0;
        while(h < NN_CFG_NUM_BUFS  &&  (held[h] = nn_bufAlloc(0)) != NULL) ++h;
        CHECK_EQ(h, NN_CFG_NUM_BUFS);
        feed(pkt, n, true);
        CHECK_EQ(_slip.rxDropped, 1);
        CHECK_EQ(_slip.rxFrames, 4);
        for(i=0; i<h; ++i) nn_bufFree(held[i]);
        feed(pkt, n, true);
        CHECK_EQ(_slip.rxFrames, 5);
        clearLine();
    }

    /* Console text goes out between frames and is readable as such. */
    {
        nn_drv_slipPrint(&_slip, "hello board\n");
        n = ipPacket(pkt, NN_IP_PROTO_ICMP, payload, 0);
        {
            uint8_t *icmp = pkt + 20;
            memset(icmp, 0, 8); icmp[0] = 8; nn_put16(icmp + 2, nn_cksum(icmp, 8));
            nn_put16(pkt + 2, 28); nn_put16(pkt + 10, 0); nn_put16(pkt + 10, nn_cksum(pkt, 20));
        }
        feed(pkt, 28, true);
        k = firstFrame(out, text);
        CHECK(strcmp(text, "hello board\n") == 0);
        CHECK_EQ(k, 28);
        clearLine();
    }

    /* UDP over the link: a datagram in, the reply out, source and destination right. */
    {
        static nn_udp_t sock;
        uint8_t udp[8 + 5] = { 0x1F, 0x90, 0x13, 0x88, 0, 13, 0, 0, 'h', 'e', 'l', 'l', 'o' };
        nn_ip4_t from;
        uint16_t port;
        uint8_t buf[16];
        CHECK_EQ(nn_udpOpen(&sock), NN_OK);
        CHECK_EQ(nn_udpBind(&sock, nn_ip4(0, 0, 0, 0), 5000), NN_OK);
        n = ipPacket(pkt, NN_IP_PROTO_UDP, udp, sizeof(udp));
        feed(pkt, n, true);
        CHECK_EQ(nn_udpRecvFrom(&sock, buf, sizeof(buf), &from, &port, 0), 5);
        CHECK(nn_ip4Equal(from, _peer)  &&  port == 8080);
        CHECK_EQ(nn_udpSendTo(&sock, "world", 5, from, port), NN_OK);
        k = firstFrame(out, text);
        CHECK_EQ(k, 20 + 8 + 5);
        CHECK_EQ(out[9], NN_IP_PROTO_UDP);
        CHECK(memcmp(out + 16, _peer.b, 4) == 0);
        CHECK(memcmp(out + 28, "world", 5) == 0);
        nn_udpClose(&sock);
        clearLine();
    }

    nn_bufGetStats(&bs);
    CHECK_EQ(bs.free, NN_CFG_NUM_BUFS);
    nn_unlock();
    test_finish("test_slip");
    return 0;
}
