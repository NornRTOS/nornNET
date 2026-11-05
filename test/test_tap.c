/**
 * @file test_tap.c
 * nornNET on the nornOS host port in real time against the Linux kernel through a TAP
 * interface (tools/tap_setup.sh creates nn0 at 10.0.77.1/24; we are 10.0.77.2).
 *
 *   1. Linux pings us: ARP request answered, echo requests answered; the ping command's
 *      exit status says whether every reply arrived.
 *   2. We ping Linux: ARP resolution, echo replies with the right payload.
 *   3. UDP echo against tools/udp_echo.py on 10.0.77.1 and DNS against tools/dns_stub.py,
 *      both started by the test, plus a datagram to a closed port (ICMP unreachable).
 *   4. TCP against the Linux stack: 200 KB echoed through tools/tcp_echo.py, a passive
 *      open with tools/tcp_client.py connecting to us, 2 MB each way through
 *      tools/tcp_sink.py (throughput printed), an HTTP GET from python's http.server,
 *      and a connect to a closed port (refused).
 *   5. With NN_SOAK_SECONDS set, keep answering for that long and print the counters;
 *      the buffer pool must be full again at the end. tools/soak_tap.sh drives it.
 *
 * Prints SKIP when the interface does not exist.
 */

#define _POSIX_C_SOURCE 200809L
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

#include "rtos.h"
#include "nn_net.h"
#include "nn_eth.h"
#include "nn_ip.h"
#include "nn_arp.h"
#include "nn_icmp.h"
#include "nn_udp.h"
#include "nn_dns.h"
#include "nn_tcp.h"
#include "nn_drv_tap.h"
#include "nn_host.h"
#include "testutil.h"

#define TASK_TEST   2u
#define PING_ID     0x5441u

static nn_netdev_t _tap;
static nn_iface_t _if;
static uint8_t _stackTest[1];
static const uint8_t _mac[6] = { 0x02, 0x4E, 0x4E, 0x00, 0x00, 0x02 };
static const nn_ip4_t _host = NN_IP4_INIT(10, 0, 77, 1);
static const nn_ip4_t _us   = NN_IP4_INIT(10, 0, 77, 2);

static volatile unsigned _replies, _badReplies;
static nn_tcp_t _tcp, _tcpL, _tcpA;
static uint8_t _ringR[8192], _ringT[8192], _ringAR[4096], _ringAT[4096];

static uint8_t pattern(uint32_t i) { return (uint8_t)((i * 7u + 3u) & 255u); }

/** Send  total pattern bytes and read them back through an echo peer, in chunks of
     chunk. Returns the number of bytes echoed correctly. */
static uint32_t echoRun(nn_tcp_t *pS, uint32_t total, uint32_t chunk)
{
    static uint8_t tx[4096], rx[4096];
    uint32_t sent = 0, got = 0, ok = 0;
    while(got < total)
    {
        uint32_t k;
        int32_t n;
        if(sent < total  &&  sent - got < 16384)
        {
            const uint32_t n2 = total - sent < chunk ? total - sent : chunk;
            for(k=0; k<n2; ++k) tx[k] = pattern(sent + k);
            n = nn_tcpSend(pS, tx, n2, 2000);
            if(n <= 0) return ok;
            sent += (uint32_t)n;
        }
        n = nn_tcpRecv(pS, rx, sizeof(rx), 2000);
        if(n <= 0) return ok;
        for(k=0; k<(uint32_t)n; ++k)
            if(rx[k] == pattern(got + k)) ++ok;
        got += (uint32_t)n;
    }
    return ok;
}

static void onReply(nn_ip4_t from, uint16_t id, uint16_t seq, const uint8_t *p, uint16_t len, void *arg)
{
    uint16_t i;
    bool ok = nn_ip4Equal(from, _host)  &&  id == PING_ID  &&  len == 32;
    (void)seq; (void)arg;
    for(i=0; ok && i<len; ++i)
        ok = p[i] == (uint8_t)i;
    if(ok) ++_replies; else ++_badReplies;
    rtos_notify(TASK_TEST, 1, RTOS_NOTIFY_OR);
}

/** Start a command in the background; returns its pid. */
static pid_t spawn(const char *cmd)
{
    const pid_t pid = fork();
    if(pid == 0)
    {
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }
    return pid;
}

/** Wait for the child while the kernel keeps running; returns its exit status or -1. */
static int waitChild(pid_t pid, uint32_t timeoutMs)
{
    const rtos_tick_t t0 = rtos_getTick();
    int status;
    while(rtos_getTick() - t0 < timeoutMs)
    {
        const pid_t r = waitpid(pid, &status, WNOHANG);
        if(r == pid)
            return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        rtos_delay(20);
    }
    return -1;
}

static void printStats(void)
{
    nn_arpStats_t as; nn_icmpStats_t cs; nn_ipStats_t is; nn_bufStats_t bs;
    nn_lock();
    nn_arpGetStats(&as); nn_icmpGetStats(&cs); nn_ipGetStats(&is); nn_bufGetStats(&bs);
    nn_unlock();
    printf("eth rx=%lu tx=%lu drop=%lu txErr=%lu | arp rxReq=%lu txRep=%lu res=%lu | ip rx=%lu bad=%lu notForUs=%lu noProto=%lu | icmp echoReq=%lu echoRep=%lu bad=%lu | bufs free=%u/%u minFree=%u failed=%u\n",
           (unsigned long)_tap.stats.rxFrames, (unsigned long)_tap.stats.txFrames,
           (unsigned long)_tap.stats.rxDropped, (unsigned long)_tap.stats.txErrors,
           (unsigned long)as.rxRequests, (unsigned long)as.txReplies, (unsigned long)as.resolved,
           (unsigned long)is.rx, (unsigned long)(is.rxBadHeader + is.rxBadChecksum),
           (unsigned long)is.rxNotForUs, (unsigned long)is.rxNoProto,
           (unsigned long)cs.rxEchoRequests, (unsigned long)cs.txEchoReplies, (unsigned long)cs.rxBad,
           bs.free, bs.numBufs, bs.minFree, bs.allocFailed);
}

static void testTask(void *arg)
{
    nn_bufStats_t bs;
    nn_icmpStats_t cs;
    const char *soak = getenv("NN_SOAK_SECONDS");
    unsigned i;
    (void)arg;

    /* 1. Linux pings us. */
    {
        const pid_t pid = spawn("ping -c 5 -i 0.2 -W 1 10.0.77.2 > /dev/null 2>&1");
        const int rc = waitChild(pid, 5000);
        CHECK_EQ(rc, 0);
        nn_lock();
        nn_icmpGetStats(&cs);
        nn_unlock();
        CHECK(cs.rxEchoRequests >= 5);
        CHECK(cs.txEchoReplies >= 5);
    }

    /* 2. We ping Linux. */
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
    CHECK_EQ(_replies, 5);
    CHECK_EQ(_badReplies, 0);
    {
        uint8_t mac[6];
        nn_lock();
        CHECK(nn_arpLookup(_host, mac));
        nn_unlock();
    }

    /* 3. UDP echo and DNS against small servers on the Linux side. */
    {
        const pid_t echo = spawn("exec python3 tools/udp_echo.py 10.0.77.1 17007");
        const pid_t dns = spawn("exec python3 tools/dns_stub.py 10.0.77.1 15353");
        static nn_udp_t sock;
        static uint8_t tx[1400], rx[1400];
        nn_ip4_t addr;
        unsigned okCount = 0;
        nn_icmpStats_t before;

        rtos_delay(500);                        /* let the servers bind */
        CHECK_EQ(nn_udpOpen(&sock), NN_OK);
        CHECK_EQ(nn_udpConnect(&sock, _host, 17007), NN_OK);
        for(i=0; i<50; ++i)
        {
            const uint16_t n = (uint16_t)(1 + (i * 97u) % 1400u);
            uint16_t k;
            int32_t r;
            for(k=0; k<n; ++k) tx[k] = (uint8_t)(k ^ i);
            if(nn_udpSend(&sock, tx, n) != NN_OK) continue;
            r = nn_udpRecvFrom(&sock, rx, sizeof(rx), NULL, NULL, 1000);
            if(r == n  &&  memcmp(rx, tx, n) == 0) ++okCount;
        }
        CHECK_EQ(okCount, 50);
        nn_udpClose(&sock);

        nn_lock();
        nn_dnsSetServer(_host);
        nn_dnsSetServerPort(15353);
        nn_icmpGetStats(&before);
        nn_unlock();
        CHECK_EQ(nn_dnsResolve("nornos.test", &addr, 3000), NN_OK);
        CHECK(nn_ip4Equal(addr, nn_ip4(192, 0, 2, 42)));
        CHECK_EQ(nn_dnsResolve("nobody.test", &addr, 3000), NN_ERR_NODEV);

        /* Closed port: Linux answers with ICMP port unreachable. */
        nn_udpOpen(&sock);
        nn_udpSendTo(&sock, tx, 4, _host, 17999);
        rtos_delay(300);
        nn_udpClose(&sock);
        nn_lock();
        nn_icmpGetStats(&cs);
        nn_unlock();
        CHECK(cs.rxErrors >= before.rxErrors + 1);

        kill(echo, SIGTERM);
        kill(dns, SIGTERM);
        waitChild(echo, 1000);
        waitChild(dns, 1000);
    }

    /* 4. TCP against Linux. */
    {
        const pid_t echo = spawn("exec python3 tools/tcp_echo.py 10.0.77.1 17008");
        const pid_t sink = spawn("exec python3 tools/tcp_sink.py 10.0.77.1 17010");
        const pid_t http = spawn("cd tools && exec python3 -m http.server --bind 10.0.77.1 18080 > /dev/null 2>&1");
        nn_tcpStats_t ts0, ts;
        rtos_tick_t t0, dt;
        uint32_t ok, n, k;
        int32_t r;
        static uint8_t rx[4096];
        unsigned j;

        rtos_delay(700);
        nn_lock();
        nn_tcpGetStats(&ts0);
        nn_unlock();

        /* 4a. Echo: 200 KB in 1400 byte writes. */
        CHECK_EQ(nn_tcpOpen(&_tcp, _ringR, sizeof(_ringR), _ringT, sizeof(_ringT)), NN_OK);
        t0 = rtos_getTick();
        CHECK_EQ(nn_tcpConnect(&_tcp, _host, 17008, 3000), NN_OK);
        printf("tcp connect in %lu ms, mss %u, rto %lu ms\n", (unsigned long)(rtos_getTick() - t0), _tcp.mss, (unsigned long)_tcp.rto);
        CHECK_EQ(_tcp.mss, 1460);
        t0 = rtos_getTick();
        ok = echoRun(&_tcp, 200000, 1400);
        dt = rtos_getTick() - t0;
        CHECK_EQ(ok, 200000);
        printf("tcp echo 200000 bytes both ways in %lu ms\n", (unsigned long)dt);
        CHECK_EQ(nn_tcpClose(&_tcp), NN_OK);
        for(j=0; j<300 && nn_tcpState(&_tcp) != NN_TCP_CLOSED; ++j) rtos_delay(10);
        CHECK_EQ(nn_tcpState(&_tcp), NN_TCP_CLOSED);
        CHECK_EQ(_tcp.err, NN_OK);

        /* 4b. Passive open: Linux connects to us and sends 100 KB which we echo. */
        CHECK_EQ(nn_tcpOpen(&_tcpL, NULL, 0, NULL, 0), NN_OK);
        CHECK_EQ(nn_tcpBind(&_tcpL, nn_ip4(0, 0, 0, 0), 17009), NN_OK);
        CHECK_EQ(nn_tcpListen(&_tcpL), NN_OK);
        CHECK_EQ(nn_tcpOpen(&_tcpA, _ringAR, sizeof(_ringAR), _ringAT, sizeof(_ringAT)), NN_OK);
        {
            const pid_t client = spawn("exec python3 tools/tcp_client.py 10.0.77.2 17009 0 100000 > build/tcp_client.log");
            uint32_t echoed = 0;
            CHECK_EQ(nn_tcpAccept(&_tcpL, &_tcpA, 5000), NN_OK);
            while((r = nn_tcpRecv(&_tcpA, rx, sizeof(rx), 3000)) > 0)
            {
                if(nn_tcpSend(&_tcpA, rx, (size_t)r, 3000) != r) break;
                echoed += (uint32_t)r;
            }
            CHECK_EQ(r, 0);                             /* the client half closed */
            CHECK_EQ(echoed, 100000);
            nn_tcpClose(&_tcpA);
            CHECK_EQ(waitChild(client, 10000), 0);
            for(j=0; j<300 && nn_tcpState(&_tcpA) != NN_TCP_CLOSED; ++j) rtos_delay(10);
            CHECK_EQ(nn_tcpState(&_tcpA), NN_TCP_CLOSED);
            nn_tcpClose(&_tcpL);
        }

        /* 4c. Throughput: 2 MB to the sink, 2 MB back. */
        CHECK_EQ(nn_tcpOpen(&_tcp, _ringR, sizeof(_ringR), _ringT, sizeof(_ringT)), NN_OK);
        CHECK_EQ(nn_tcpConnect(&_tcp, _host, 17010, 3000), NN_OK);
        n = 2000000;
        {
            static uint8_t tx[4096];
            uint8_t hdr[4];
            uint32_t sent = 0, got = 0, bad = 0;
            nn_put32(hdr, n);
            CHECK_EQ(nn_tcpSend(&_tcp, hdr, 4, 1000), 4);
            t0 = rtos_getTick();
            while(sent < n)
            {
                const uint32_t n2 = n - sent < sizeof(tx) ? n - sent : (uint32_t)sizeof(tx);
                for(k=0; k<n2; ++k) tx[k] = pattern(sent + k);
                r = nn_tcpSend(&_tcp, tx, n2, 5000);
                if(r <= 0) break;
                sent += (uint32_t)r;
            }
            dt = rtos_getTick() - t0;
            CHECK_EQ(sent, n);
            printf("tcp send 2 MB in %lu ms = %lu kB/s\n", (unsigned long)dt, (unsigned long)(dt ? n / dt : 0));
            r = 0;
            while(r < 4)
            {
                const int32_t m = nn_tcpRecv(&_tcp, hdr + r, 4 - (size_t)r, 5000);
                if(m <= 0) break;
                r += m;
            }
            CHECK_EQ(r, 4);
            CHECK_EQ(nn_get32(hdr), 0);                 /* pattern errors seen by the sink */
            t0 = rtos_getTick();
            while(got < n)
            {
                r = nn_tcpRecv(&_tcp, rx, sizeof(rx), 5000);
                if(r <= 0) break;
                for(k=0; k<(uint32_t)r; ++k)
                    if(rx[k] != pattern(got + k)) ++bad;
                got += (uint32_t)r;
            }
            dt = rtos_getTick() - t0;
            CHECK_EQ(got, n);
            CHECK_EQ(bad, 0);
            printf("tcp receive 2 MB in %lu ms = %lu kB/s\n", (unsigned long)dt, (unsigned long)(dt ? n / dt : 0));
            CHECK_EQ(nn_tcpRecv(&_tcp, rx, sizeof(rx), 3000), 0);    /* the sink closes */
            nn_tcpClose(&_tcp);
            for(j=0; j<300 && nn_tcpState(&_tcp) != NN_TCP_CLOSED; ++j) rtos_delay(10);
            CHECK_EQ(nn_tcpState(&_tcp), NN_TCP_CLOSED);
        }

        /* 4d. HTTP GET of this test's own helper from python's http.server. */
        CHECK_EQ(nn_tcpOpen(&_tcp, _ringR, sizeof(_ringR), _ringT, sizeof(_ringT)), NN_OK);
        CHECK_EQ(nn_tcpConnect(&_tcp, _host, 18080, 3000), NN_OK);
        {
            static const char req[] = "GET /tcp_echo.py HTTP/1.0\r\nHost: 10.0.77.1\r\n\r\n";
            static char page[8192];
            uint32_t len = 0;
            CHECK_EQ(nn_tcpSend(&_tcp, req, sizeof(req) - 1, 1000), (int32_t)(sizeof(req) - 1));
            while(len < sizeof(page) - 1  &&  (r = nn_tcpRecv(&_tcp, page + len, sizeof(page) - 1 - len, 3000)) > 0)
                len += (uint32_t)r;
            page[len] = 0;
            CHECK_EQ(r, 0);
            CHECK(strncmp(page, "HTTP/1.0 200 OK", 15) == 0);
            CHECK(strstr(page, "TCP echo server for the tests") != NULL);
            printf("http GET: %lu bytes, %.15s\n", (unsigned long)len, page);
            nn_tcpClose(&_tcp);
            for(j=0; j<300 && nn_tcpState(&_tcp) != NN_TCP_CLOSED; ++j) rtos_delay(10);
        }

        /* 4e. Closed port: refused at once. */
        CHECK_EQ(nn_tcpOpen(&_tcp, _ringR, sizeof(_ringR), _ringT, sizeof(_ringT)), NN_OK);
        t0 = rtos_getTick();
        CHECK_EQ(nn_tcpConnect(&_tcp, _host, 17999, 3000), NN_ERR_REFUSED);
        CHECK(rtos_getTick() - t0 < 500);

        nn_lock();
        nn_tcpGetStats(&ts);
        nn_unlock();
        printf("tcp: established %lu, rexmits %lu (fast %lu, timeouts %lu), ooo %lu, dup %lu, bad %lu, noSock %lu, resets rx %lu tx %lu\n",
               (unsigned long)(ts.established - ts0.established), (unsigned long)(ts.rexmits - ts0.rexmits),
               (unsigned long)(ts.fastRexmits - ts0.fastRexmits), (unsigned long)(ts.timeouts - ts0.timeouts),
               (unsigned long)(ts.rxOoo - ts0.rxOoo), (unsigned long)(ts.rxDup - ts0.rxDup),
               (unsigned long)(ts.rxBad + ts.rxBadChecksum - ts0.rxBad - ts0.rxBadChecksum),
               (unsigned long)(ts.rxNoSocket - ts0.rxNoSocket),
               (unsigned long)(ts.rxResets - ts0.rxResets), (unsigned long)(ts.txResets - ts0.txResets));
        CHECK_EQ(ts.established - ts0.established, 4);
        CHECK_EQ(ts.rxBad + ts.rxBadChecksum - ts0.rxBad - ts0.rxBadChecksum, 0);
        CHECK_EQ(ts.timeouts - ts0.timeouts, 0);

        kill(echo, SIGTERM);
        kill(sink, SIGTERM);
        kill(http, SIGTERM);
        waitChild(echo, 1000);
        waitChild(sink, 1000);
        waitChild(http, 1000);
    }

    /* 5. Soak. */
    if(soak != NULL)
    {
        const uint32_t secs = (uint32_t)atoi(soak);
        uint32_t t;
        printf("soak for %lu s\n", (unsigned long)secs);
        for(t=0; t<secs; t+=10)
        {
            rtos_delay(10000);
            printStats();
        }
    }
    rtos_delay(100);
    printStats();
    nn_lock();
    nn_bufGetStats(&bs);
    nn_icmpGetStats(&cs);
    nn_unlock();
    CHECK_EQ(bs.free, NN_CFG_NUM_BUFS);
    CHECK_EQ(cs.rxBad, 0);
    CHECK_EQ(_tap.stats.txErrors, 0);
    test_finish("test_tap");
}

int main(void)
{
    const char *ifName = getenv("NN_TAP");

    if(ifName == NULL)
        ifName = "nn0";
    rtos_init();
    CHECK_EQ(nn_init(), NN_OK);
    if(nn_drv_tapRegister(&_tap, ifName, _mac) != NN_OK)
    {
        printf("test_tap: cannot open TAP %s (run sudo tools/tap_setup.sh)\n", ifName);
        printf("RESULT test_tap SKIP\n");
        return 0;
    }
    nn_host_watchFd(nn_drv_tapFd(&_tap), &_tap, nn_drv_tapPollIsr);
    CHECK_EQ(nn_ifaceAdd(&_tap, &_if, _us, nn_ip4(255, 255, 255, 0), _host), NN_OK);
    rtos_createTask(TASK_TEST, testTask, NULL, _stackTest, sizeof(_stackTest));
    rtos_start();
    return 0;
}
