/**
 * @file nn04_tcp.c
 * nornNET test 4, in QEMU: TCP (v0.3) against real peers through slirp. DHCP first, then
 * a listener on port 17009 with a socket offered for accept (the host side client of
 * tools/with_servers.sh connects to it through QEMU's hostfwd after 5 s), and while it
 * is on its way: 100 KB echoed through tools/tcp_echo.py (10.0.2.2:17008), 1 MB sent to
 * and received from tools/tcp_sink.py (17010) with the throughput printed, an HTTP GET
 * from python's http.server (18080), a refused connect to a closed port. Finally the
 * accepted connection echoes the client's 20 000 bytes until it half closes. No buffer
 * may leak, nothing may be retransmitted on this lossless link.
 *
 *   RESULT nn04 PASS
 */

#include <string.h>

#include "rtos.h"
#include "uart.h"
#include "testresult.h"
#include "nn_net.h"
#include "nn_ip.h"
#include "nn_tcp.h"
#include "nn_dhcp.h"
#include "nn_drv_openeth.h"

#define TASK_TEST       2u
#define STACK_SIZE      4096u
#define ECHO_PORT       17008u
#define LISTEN_PORT     17009u
#define SINK_PORT       17010u
#define HTTP_PORT       18080u

static uint8_t _stackTest[STACK_SIZE];
static nn_netdev_t _eth;
static nn_iface_t _ifEth;
static nn_dhcp_t _dhcp;
static nn_tcp_t _tcp, _tcpL, _tcpA;
static uint8_t _ringR[8192], _ringT[8192], _ringAR[2048], _ringAT[2048];
static uint8_t _tx[2048], _rx[2048];
static const uint8_t _mac[6] = { 0x02, 0x4E, 0x4E, 0x00, 0x00, 0x12 };
static volatile uint32_t _accepted;

static uint8_t pattern(uint32_t i) { return (uint8_t)((i * 7u + 3u) & 255u); }

static void onDhcp(nn_dhcp_t *pD, bool bound, void *arg)
{
    (void)pD; (void)arg;
    if(bound)
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

static void waitClosed(nn_tcp_t *pS, const char *what)
{
    unsigned j;
    for(j=0; j<300 && nn_tcpState(pS) != NN_TCP_CLOSED; ++j)
        rtos_delay(10);
    tc_expect(what, nn_tcpState(pS) == NN_TCP_CLOSED);
}

static void testTask(void *arg)
{
    nn_bufStats_t bs;
    nn_tcpStats_t ts;
    const nn_ip4_t host = nn_ip4(10, 0, 2, 2);
    uint32_t t0, freeAtStart, sent, got, ok, k, bad;
    int32_t r;
    char s[16];
    (void)arg;

    nn_lock();
    nn_bufGetStats(&bs);
    nn_unlock();
    freeAtStart = bs.free;

    /* DHCP */
    tc_expect("dhcpStart", nn_dhcpStart(&_dhcp, &_ifEth, onDhcp, NULL) == NN_OK);
    t0 = rtos_getTick();
    while(!nn_dhcpIsBound(&_dhcp)  &&  rtos_getTick() - t0 < 10000)
        rtos_notifyTake(500);
    tc_expect("dhcpBound", nn_dhcpIsBound(&_dhcp));
    uart_puts("nn04: dhcp ");
    uart_puts(nn_ip4ToStr(s, _ifEth.addr));
    uart_puts("\r\n");

    /* The listener and an offered socket; the host side client arrives later. */
    tc_expect("listenOpen", nn_tcpOpen(&_tcpL, NULL, 0, NULL, 0) == NN_OK);
    tc_expect("listenBind", nn_tcpBind(&_tcpL, nn_ip4(0, 0, 0, 0), LISTEN_PORT) == NN_OK);
    tc_expect("listen", nn_tcpListen(&_tcpL) == NN_OK);
    tc_expect("acceptOpen", nn_tcpOpen(&_tcpA, _ringAR, sizeof(_ringAR), _ringAT, sizeof(_ringAT)) == NN_OK);
    nn_tcpOnEvent(&_tcpA, onAccepted, NULL);
    tc_expect("acceptOffer", nn_tcpAccept(&_tcpL, &_tcpA, 0) == NN_ERR_PENDING);

    /* Echo: 100 KB in 1400 byte writes, read back and compared. */
    tc_expect("echoOpen", nn_tcpOpen(&_tcp, _ringR, sizeof(_ringR), _ringT, sizeof(_ringT)) == NN_OK);
    t0 = rtos_getTick();
    tc_expect("echoConnect", nn_tcpConnect(&_tcp, host, ECHO_PORT, 5000) == NN_OK);
    uart_puts("tcp connect in ");
    uart_putU32(rtos_getTick() - t0);
    uart_puts(" ms, mss ");
    uart_putU32(_tcp.mss);
    uart_puts("\r\n");
    sent = got = ok = 0;
    t0 = rtos_getTick();
    while(got < 100000)
    {
        if(sent < 100000  &&  sent - got < 8192)
        {
            const uint32_t n = 100000 - sent < 1400 ? 100000 - sent : 1400;
            for(k=0; k<n; ++k) _tx[k] = pattern(sent + k);
            r = nn_tcpSend(&_tcp, _tx, n, 2000);
            if(r <= 0) break;
            sent += (uint32_t)r;
        }
        r = nn_tcpRecv(&_tcp, _rx, sizeof(_rx), 2000);
        if(r <= 0) break;
        for(k=0; k<(uint32_t)r; ++k)
            if(_rx[k] == pattern(got + k)) ++ok;
        got += (uint32_t)r;
    }
    uart_puts("tcp echo ");
    uart_putU32(ok);
    uart_puts("/100000 bytes in ");
    uart_putU32(rtos_getTick() - t0);
    uart_puts(" ms\r\n");
    tc_expectRange("echoOk", ok, 100000, 100000);
    nn_tcpClose(&_tcp);
    waitClosed(&_tcp, "echoClosed");
    tc_expect("echoOrderly", _tcp.err == NN_OK);

    /* Throughput: 1 MB to the sink and 1 MB back. */
    tc_expect("sinkOpen", nn_tcpOpen(&_tcp, _ringR, sizeof(_ringR), _ringT, sizeof(_ringT)) == NN_OK);
    tc_expect("sinkConnect", nn_tcpConnect(&_tcp, host, SINK_PORT, 5000) == NN_OK);
    {
        uint8_t hdr[4];
        const uint32_t n = 1000000;
        uint32_t dt;
        nn_put32(hdr, n);
        tc_expect("sinkHdr", nn_tcpSend(&_tcp, hdr, 4, 1000) == 4);
        t0 = rtos_getTick();
        for(sent=0; sent<n; )
        {
            const uint32_t n2 = n - sent < sizeof(_tx) ? n - sent : (uint32_t)sizeof(_tx);
            for(k=0; k<n2; ++k) _tx[k] = pattern(sent + k);
            r = nn_tcpSend(&_tcp, _tx, n2, 5000);
            if(r <= 0) break;
            sent += (uint32_t)r;
        }
        dt = rtos_getTick() - t0;
        tc_expectRange("sinkSent", sent, n, n);
        uart_puts("tcp send 1 MB in ");
        uart_putU32(dt);
        uart_puts(" ms = ");
        uart_putU32(dt ? n / dt : 0);
        uart_puts(" kB/s\r\n");
        r = 0;
        while(r < 4)
        {
            const int32_t m = nn_tcpRecv(&_tcp, hdr + r, 4 - (size_t)r, 5000);
            if(m <= 0) break;
            r += m;
        }
        tc_expect("sinkReply", r == 4  &&  nn_get32(hdr) == 0);
        t0 = rtos_getTick();
        bad = 0;
        for(got=0; got<n; )
        {
            r = nn_tcpRecv(&_tcp, _rx, sizeof(_rx), 5000);
            if(r <= 0) break;
            for(k=0; k<(uint32_t)r; ++k)
                if(_rx[k] != pattern(got + k)) ++bad;
            got += (uint32_t)r;
        }
        dt = rtos_getTick() - t0;
        tc_expectRange("sinkGot", got, n, n);
        tc_expectRange("sinkBad", bad, 0, 0);
        uart_puts("tcp receive 1 MB in ");
        uart_putU32(dt);
        uart_puts(" ms = ");
        uart_putU32(dt ? n / dt : 0);
        uart_puts(" kB/s\r\n");
        tc_expect("sinkEof", nn_tcpRecv(&_tcp, _rx, sizeof(_rx), 3000) == 0);
        nn_tcpClose(&_tcp);
        waitClosed(&_tcp, "sinkClosed");
    }

    /* HTTP GET from python's http.server serving the tools directory. */
    tc_expect("httpOpen", nn_tcpOpen(&_tcp, _ringR, sizeof(_ringR), _ringT, sizeof(_ringT)) == NN_OK);
    tc_expect("httpConnect", nn_tcpConnect(&_tcp, host, HTTP_PORT, 5000) == NN_OK);
    {
        static const char req[] = "GET /tcp_echo.py HTTP/1.0\r\nHost: 10.0.2.2\r\n\r\n";
        uint32_t len = 0;
        tc_expect("httpSend", nn_tcpSend(&_tcp, req, sizeof(req) - 1, 1000) == (int32_t)(sizeof(req) - 1));
        while(len < sizeof(_rx) - 1  &&  (r = nn_tcpRecv(&_tcp, _rx + len, sizeof(_rx) - 1 - len, 3000)) > 0)
            len += (uint32_t)r;
        _rx[len] = 0;
        tc_expect("httpEof", r == 0);
        tc_expect("http200", strncmp((const char *)_rx, "HTTP/1.0 200 OK", 15) == 0);
        tc_expect("httpBody", strstr((const char *)_rx, "TCP echo server for the tests") != NULL);
        uart_puts("http GET ");
        uart_putU32(len);
        uart_puts(" bytes\r\n");
        nn_tcpClose(&_tcp);
        waitClosed(&_tcp, "httpClosed");
    }

    /* A closed port: slirp relays the host's RST. */
    tc_expect("refusedOpen", nn_tcpOpen(&_tcp, _ringR, sizeof(_ringR), _ringT, sizeof(_ringT)) == NN_OK);
    tc_expect("refused", nn_tcpConnect(&_tcp, host, 17999, 5000) == NN_ERR_REFUSED);

    /* The passive open: wait for the client, echo until it half closes. */
    t0 = rtos_getTick();
    while(_accepted == 0  &&  rtos_getTick() - t0 < 9000)
        rtos_notifyTake(500);
    tc_expectRange("accepted", _accepted, 1, 1);
    uart_puts("accepted from ");
    uart_puts(nn_ip4ToStr(s, _tcpA.remoteAddr));
    uart_puts("\r\n");
    got = 0;
    while((r = nn_tcpRecv(&_tcpA, _rx, sizeof(_rx), 5000)) > 0)
    {
        if(nn_tcpSend(&_tcpA, _rx, (size_t)r, 5000) != r) break;
        got += (uint32_t)r;
    }
    tc_expect("clientEof", r == 0);
    tc_expectRange("clientBytes", got, 20000, 20000);
    nn_tcpClose(&_tcpA);
    waitClosed(&_tcpA, "acceptedClosed");
    nn_tcpClose(&_tcpL);

    rtos_delay(200);
    nn_lock();
    nn_bufGetStats(&bs);
    nn_tcpGetStats(&ts);
    nn_unlock();
    uart_puts("tcp established ");
    uart_putU32(ts.established);
    uart_puts(" rexmits ");
    uart_putU32(ts.rexmits);
    uart_puts(" ooo ");
    uart_putU32(ts.rxOoo);
    uart_puts(" bad ");
    uart_putU32(ts.rxBad + ts.rxBadChecksum);
    uart_puts("\r\n");
    tc_expectRange("established", ts.established, 4, 4);
    tc_expectRange("tcpBad", ts.rxBad + ts.rxBadChecksum, 0, 0);
    tc_expectRange("timeouts", ts.timeouts, 0, 0);
    tc_expectRange("rxDropped", _eth.stats.rxDropped, 0, 0);
    tc_expectRange("freeEnd", bs.free, freeAtStart, freeAtStart);
    tc_expectRange("allocFailed", bs.allocFailed, 0, 0);
    tc_expectRange("stackNet", rtos_getStackFree(NN_CFG_TASK_PRIO), 256, NN_CFG_TASK_STACK);
    tc_expectRange("stackTest", rtos_getStackFree(TASK_TEST), 256, STACK_SIZE);
    tc_finish("nn04");
}

int main(void)
{
    uart_init(115200);
    rtos_init();
    nn_init();
    if(nn_drv_openethRegister(&_eth, _mac) != NN_OK)
    {
        uart_puts("CHECK FAILED: open_eth init\r\nRESULT nn04 FAIL\r\n");
        rtos_port_halt();
    }
    nn_ifaceAdd(&_eth, &_ifEth, nn_ip4(0, 0, 0, 0), nn_ip4(0, 0, 0, 0), nn_ip4(0, 0, 0, 0));
    rtos_createTask(TASK_TEST, testTask, NULL, _stackTest, sizeof(_stackTest));
    rtos_start();
    return 0;
}
