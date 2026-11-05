/**
 * @file nn05_slip.c
 * nornNET test 5, on the ESP32 board: the whole stack against the Linux kernel over
 * SLIP on UART0 (tools/slip_bridge.py turns the serial line into a peer on the TAP nn0).
 * Ping, UDP echo and DNS against the host servers, TCP: 50 KB echoed, 200 KB each way
 * through the sink with the throughput printed, an HTTP GET, a passive open accepting
 * tools/tcp_client.py, a refused connect. Console text is written between SLIP frames,
 * which the bridge prints. The link may lose bytes at this rate, so retransmissions are
 * reported, not forbidden; nothing may leak.
 *
 *   RESULT nn05 PASS
 */

#include <string.h>

#include "rtos.h"
#include "uart.h"
#include "nn_net.h"
#include "nn_ip.h"
#include "nn_icmp.h"
#include "nn_udp.h"
#include "nn_dns.h"
#include "nn_tcp.h"
#include "nn_drv_slip.h"

#define TASK_TEST       2u
#define STACK_SIZE      4096u
#define SLIP_BAUD       921600ul
#define PING_ID         0x4E35u

static uint8_t _stackTest[STACK_SIZE];
static nn_netdev_t _dev;
static nn_slip_t _slip;
static nn_iface_t _if;
static nn_udp_t _udp;
static nn_tcp_t _tcp, _tcpL, _tcpA;
static uint8_t _ringR[4096], _ringT[4096], _ringAR[2048], _ringAT[2048];
static uint8_t _tx[1400], _rx[1400];
static const nn_ip4_t _host = NN_IP4_INIT(10, 0, 77, 1);
static const nn_ip4_t _us   = NN_IP4_INIT(10, 0, 77, 3);
static volatile uint32_t _replies, _accepted;
static unsigned _failures;

/* --- Console through the SLIP driver, so text never tears a frame ---------------------- */

static void say(const char *s) { nn_drv_slipPrint(&_slip, s); }

static void sayU32(uint32_t n)
{
    char s[12];
    int i = 11;
    s[i] = 0;
    do { s[--i] = (char)('0' + n % 10u); n /= 10u; } while(n != 0);
    say(s + i);
}

static void expect(const char *what, bool ok)
{
    if(!ok)
    {
        ++ _failures;
        say("CHECK FAILED: ");
        say(what);
        say("\r\n");
    }
}

static void expectRange(const char *what, uint32_t v, uint32_t lo, uint32_t hi)
{
    if(v < lo  ||  v > hi)
    {
        ++ _failures;
        say("CHECK FAILED: ");
        say(what);
        say("=");
        sayU32(v);
        say(" expected ");
        sayU32(lo);
        say("..");
        sayU32(hi);
        say("\r\n");
    }
}

/* --- The serial line ----------------------------------------------------------------------- */

static void slipWrite(const uint8_t *p, uint16_t n, void *arg)
{
    (void)arg;
    while(n--)
        uart_putc((char)*p++);
}

static void uartRx(uint8_t c, void *arg)
{
    (void)arg;
    nn_drv_slipRxByteFromIsr(&_slip, c);
}

/* --- Callbacks ---------------------------------------------------------------------------- */

static void onReply(nn_ip4_t from, uint16_t id, uint16_t seq, const uint8_t *p, uint16_t len, void *arg)
{
    (void)seq; (void)p; (void)arg;
    if(nn_ip4Equal(from, _host)  &&  id == PING_ID  &&  len == 32)
        ++ _replies;
    rtos_notify(TASK_TEST, 1, RTOS_NOTIFY_OR);
}

static void onAccepted(nn_tcp_t *pS, uint8_t ev, void *arg)
{
    (void)pS; (void)arg;
    if(ev == NN_TCP_EV_CONNECTED)
    {
        ++ _accepted;
        rtos_notify(TASK_TEST, 2, RTOS_NOTIFY_OR);
    }
}

static uint8_t pattern(uint32_t i) { return (uint8_t)((i * 7u + 3u) & 255u); }

static void waitClosed(nn_tcp_t *pS, const char *what)
{
    unsigned j;
    for(j=0; j<500 && nn_tcpState(pS) != NN_TCP_CLOSED; ++j)
        rtos_delay(10);
    expect(what, nn_tcpState(pS) == NN_TCP_CLOSED);
}

/* --- The test ------------------------------------------------------------------------------ */

static void testTask(void *arg)
{
    nn_bufStats_t bs;
    nn_tcpStats_t ts;
    nn_ipStats_t is;
    uint32_t t0, dt, freeAtStart, sent, got, ok, k, bad, n;
    int32_t r;
    unsigned i;
    (void)arg;

    rtos_delay(300);                                    /* the bridge resets and attaches */
    nn_lock();
    nn_bufGetStats(&bs);
    nn_unlock();
    freeAtStart = bs.free;
    say("\r\nnn05: slip up, ");
    sayU32(SLIP_BAUD);
    say(" baud\r\n");

    /* Ping Linux. */
    nn_lock();
    nn_icmpOnEchoReply(onReply, NULL);
    nn_unlock();
    for(i=1; i<=5; ++i)
    {
        nn_lock();
        nn_icmpEchoRequest(_host, PING_ID, (uint16_t)i, NULL, 32);
        nn_unlock();
        rtos_notifyTake(1000);
    }
    say("ping ");
    sayU32(_replies);
    say("/5\r\n");
    expectRange("pingReplies", _replies, 4, 5);

    /* UDP echo and DNS. */
    expect("udpOpen", nn_udpOpen(&_udp) == NN_OK);
    expect("udpConnect", nn_udpConnect(&_udp, _host, 17007) == NN_OK);
    ok = 0;
    for(i=0; i<20; ++i)
    {
        const uint16_t len = (uint16_t)(1 + (i * 53u) % 1000u);
        for(k=0; k<len; ++k) _tx[k] = (uint8_t)(k + i);
        if(nn_udpSend(&_udp, _tx, len) != NN_OK) continue;
        r = nn_udpRecvFrom(&_udp, _rx, sizeof(_rx), NULL, NULL, 1000);
        if(r == len  &&  memcmp(_rx, _tx, len) == 0) ++ok;
    }
    say("udp echo ");
    sayU32(ok);
    say("/20\r\n");
    expectRange("udpEcho", ok, 18, 20);
    nn_udpClose(&_udp);
    {
        nn_ip4_t addr;
        nn_lock();
        nn_dnsSetServer(_host);
        nn_dnsSetServerPort(15353);
        nn_unlock();
        expect("dns", nn_dnsResolve("nornos.test", &addr, 3000) == NN_OK  &&  nn_ip4Equal(addr, nn_ip4(192, 0, 2, 42)));
    }

    /* The listener, offered now; the host side client arrives on its own time. */
    expect("listenOpen", nn_tcpOpen(&_tcpL, NULL, 0, NULL, 0) == NN_OK);
    expect("listenBind", nn_tcpBind(&_tcpL, nn_ip4(0, 0, 0, 0), 17009) == NN_OK);
    expect("listen", nn_tcpListen(&_tcpL) == NN_OK);
    expect("acceptOpen", nn_tcpOpen(&_tcpA, _ringAR, sizeof(_ringAR), _ringAT, sizeof(_ringAT)) == NN_OK);
    nn_tcpOnEvent(&_tcpA, onAccepted, NULL);
    expect("acceptOffer", nn_tcpAccept(&_tcpL, &_tcpA, 0) == NN_ERR_PENDING);

    /* TCP echo: 50 KB in 1000 byte writes. */
    expect("echoOpen", nn_tcpOpen(&_tcp, _ringR, sizeof(_ringR), _ringT, sizeof(_ringT)) == NN_OK);
    t0 = rtos_getTick();
    expect("echoConnect", nn_tcpConnect(&_tcp, _host, 17008, 5000) == NN_OK);
    say("tcp connect in ");
    sayU32(rtos_getTick() - t0);
    say(" ms, mss ");
    sayU32(_tcp.mss);
    say("\r\n");
    sent = got = ok = 0;
    n = 50000;
    t0 = rtos_getTick();
    while(got < n)
    {
        if(sent < n  &&  sent - got < 4000)
        {
            const uint32_t n2 = n - sent < 1000 ? n - sent : 1000;
            for(k=0; k<n2; ++k) _tx[k] = pattern(sent + k);
            r = nn_tcpSend(&_tcp, _tx, n2, 5000);
            if(r <= 0) break;
            sent += (uint32_t)r;
        }
        r = nn_tcpRecv(&_tcp, _rx, sizeof(_rx), 5000);
        if(r <= 0) break;
        for(k=0; k<(uint32_t)r; ++k)
            if(_rx[k] == pattern(got + k)) ++ok;
        got += (uint32_t)r;
    }
    dt = rtos_getTick() - t0;
    say("tcp echo ");
    sayU32(ok);
    say("/50000 bytes in ");
    sayU32(dt);
    say(" ms\r\n");
    expectRange("echoOk", ok, n, n);
    nn_tcpClose(&_tcp);
    waitClosed(&_tcp, "echoClosed");

    /* Throughput: 200 KB to the sink and back. */
    expect("sinkOpen", nn_tcpOpen(&_tcp, _ringR, sizeof(_ringR), _ringT, sizeof(_ringT)) == NN_OK);
    expect("sinkConnect", nn_tcpConnect(&_tcp, _host, 17010, 5000) == NN_OK);
    {
        uint8_t hdr[4];
        n = 200000;
        nn_put32(hdr, n);
        expect("sinkHdr", nn_tcpSend(&_tcp, hdr, 4, 1000) == 4);
        t0 = rtos_getTick();
        for(sent=0; sent<n; )
        {
            const uint32_t n2 = n - sent < sizeof(_tx) ? n - sent : (uint32_t)sizeof(_tx);
            for(k=0; k<n2; ++k) _tx[k] = pattern(sent + k);
            r = nn_tcpSend(&_tcp, _tx, n2, 10000);
            if(r <= 0) break;
            sent += (uint32_t)r;
        }
        dt = rtos_getTick() - t0;
        expectRange("sinkSent", sent, n, n);
        say("tcp send 200 KB in ");
        sayU32(dt);
        say(" ms = ");
        sayU32(dt ? n / dt : 0);
        say(" kB/s\r\n");
        r = 0;
        while(r < 4)
        {
            const int32_t m = nn_tcpRecv(&_tcp, hdr + r, 4 - (size_t)r, 10000);
            if(m <= 0) break;
            r += m;
        }
        expect("sinkReply", r == 4  &&  nn_get32(hdr) == 0);
        t0 = rtos_getTick();
        bad = 0;
        for(got=0; got<n; )
        {
            r = nn_tcpRecv(&_tcp, _rx, sizeof(_rx), 10000);
            if(r <= 0) break;
            for(k=0; k<(uint32_t)r; ++k)
                if(_rx[k] != pattern(got + k)) ++bad;
            got += (uint32_t)r;
        }
        dt = rtos_getTick() - t0;
        expectRange("sinkGot", got, n, n);
        expectRange("sinkBad", bad, 0, 0);
        say("tcp receive 200 KB in ");
        sayU32(dt);
        say(" ms = ");
        sayU32(dt ? n / dt : 0);
        say(" kB/s\r\n");
        expect("sinkEof", nn_tcpRecv(&_tcp, _rx, sizeof(_rx), 5000) == 0);
        nn_tcpClose(&_tcp);
        waitClosed(&_tcp, "sinkClosed");
    }

    /* HTTP GET. */
    expect("httpOpen", nn_tcpOpen(&_tcp, _ringR, sizeof(_ringR), _ringT, sizeof(_ringT)) == NN_OK);
    expect("httpConnect", nn_tcpConnect(&_tcp, _host, 18080, 5000) == NN_OK);
    {
        static const char req[] = "GET /tcp_echo.py HTTP/1.0\r\nHost: 10.0.77.1\r\n\r\n";
        uint32_t len = 0;
        expect("httpSend", nn_tcpSend(&_tcp, req, sizeof(req) - 1, 1000) == (int32_t)(sizeof(req) - 1));
        while(len < sizeof(_rx) - 1  &&  (r = nn_tcpRecv(&_tcp, _rx + len, sizeof(_rx) - 1 - len, 5000)) > 0)
            len += (uint32_t)r;
        _rx[len] = 0;
        expect("httpEof", r == 0);
        expect("http200", strncmp((const char *)_rx, "HTTP/1.0 200 OK", 15) == 0);
        expect("httpBody", strstr((const char *)_rx, "TCP echo server for the tests") != NULL);
        say("http GET ");
        sayU32(len);
        say(" bytes\r\n");
        nn_tcpClose(&_tcp);
        waitClosed(&_tcp, "httpClosed");
    }

    /* A closed port. */
    expect("refusedOpen", nn_tcpOpen(&_tcp, _ringR, sizeof(_ringR), _ringT, sizeof(_ringT)) == NN_OK);
    expect("refused", nn_tcpConnect(&_tcp, _host, 17999, 5000) == NN_ERR_REFUSED);

    /* The passive open. */
    t0 = rtos_getTick();
    while(_accepted == 0  &&  rtos_getTick() - t0 < 20000)
        rtos_notifyTake(500);
    expectRange("accepted", _accepted, 1, 1);
    got = 0;
    while((r = nn_tcpRecv(&_tcpA, _rx, sizeof(_rx), 5000)) > 0)
    {
        if(nn_tcpSend(&_tcpA, _rx, (size_t)r, 5000) != r) break;
        got += (uint32_t)r;
    }
    expect("clientEof", r == 0);
    expectRange("clientBytes", got, 20000, 20000);
    say("accepted and echoed ");
    sayU32(got);
    say(" bytes\r\n");
    nn_tcpClose(&_tcpA);
    waitClosed(&_tcpA, "acceptedClosed");
    nn_tcpClose(&_tcpL);

    rtos_delay(300);
    nn_lock();
    nn_bufGetStats(&bs);
    nn_tcpGetStats(&ts);
    nn_ipGetStats(&is);
    nn_unlock();
    say("slip rx ");
    sayU32(_slip.rxFrames);
    say(" tx ");
    sayU32(_slip.txFrames);
    say(" dropped ");
    sayU32(_slip.rxDropped + _slip.rxOversize);
    say(" badEsc ");
    sayU32(_slip.rxBadEscape);
    say(" | ip bad ");
    sayU32(is.rxBadHeader + is.rxBadChecksum);
    say(" | tcp established ");
    sayU32(ts.established);
    say(" rexmits ");
    sayU32(ts.rexmits);
    say(" badCsum ");
    sayU32(ts.rxBadChecksum);
    say(" | bufs free ");
    sayU32(bs.free);
    say("/");
    sayU32(bs.numBufs);
    say(" minFree ");
    sayU32(bs.minFree);
    say("\r\n");
    expectRange("established", ts.established, 4, 4);
    expectRange("freeEnd", bs.free, freeAtStart, freeAtStart);
    expectRange("allocFailed", bs.allocFailed, 0, 0);
    expectRange("stackNet", rtos_getStackFree(NN_CFG_TASK_PRIO), 256, NN_CFG_TASK_STACK);
    expectRange("stackTest", rtos_getStackFree(TASK_TEST), 256, STACK_SIZE);
    say(_failures == 0 ? "RESULT nn05 PASS\r\n" : "RESULT nn05 FAIL\r\n");
    uart_flush();
    rtos_port_halt();
}

int main(void)
{
    uart_init(SLIP_BAUD);
    rtos_init();
    nn_init();
    nn_drv_slipRegister(&_dev, &_slip, slipWrite, NULL);
    nn_ifaceAdd(&_dev, &_if, _us, nn_ip4(255, 255, 255, 0), _host);
    uart_onReceive(uartRx, NULL);
    rtos_createTask(TASK_TEST, testTask, NULL, _stackTest, sizeof(_stackTest));
    rtos_start();
    return 0;
}
