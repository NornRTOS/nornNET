/**
 * @file test_netem.c
 * The loss and reorder part of the stability gate, on the host over the TAP with the
 * Linux side impaired by tc netem (the test does not set it up; it needs root):
 *
 *   sudo tc qdisc add dev nn0 root netem loss 10% delay 20ms 50ms reorder 25% 50%
 *   NN_SOAK_SECONDS=3600 build/test_netem
 *   sudo tc qdisc del dev nn0 root
 *
 * For that long, in cycles of about ten seconds: 20 UDP echoes (each one answered or
 * not, no retry: the loss shows here), a DNS lookup (the resolver retries), 100 KB to
 * tools/tcp_sink.py and back (TCP must get it all through, pattern checked), and the
 * neighbour entry of the Linux side ages out and is resolved again meanwhile. One line
 * per cycle, flushed. Passes when every TCP transfer completed, DNS answered at least
 * 80 % of the lookups, UDP at least 50 % (10 % loss each way leaves 81 %), ARP resolved
 * at all, and the buffer pool is full at the end with no allocation failure.
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

static nn_netdev_t _tap;
static nn_iface_t _if;
static uint8_t _stackTest[1];
static const uint8_t _mac[6] = { 0x02, 0x4E, 0x4E, 0x00, 0x00, 0x02 };
static const nn_ip4_t _host = NN_IP4_INIT(10, 0, 77, 1);
static const nn_ip4_t _us   = NN_IP4_INIT(10, 0, 77, 2);
static nn_tcp_t _tcp;
static uint8_t _ringR[8192], _ringT[8192];

static uint8_t pattern(uint32_t i) { return (uint8_t)((i * 7u + 3u) & 255u); }

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

/** One sink transfer; 0 on success, else the step that failed. */
static unsigned sink(uint32_t nBytes, uint32_t *pMs)
{
    static uint8_t tx[1400], rx[1400];
    uint32_t sent = 0, got = 0, bad = 0, k;
    uint8_t hdr[4];
    int32_t r;
    unsigned fail = 0, j;
    const rtos_tick_t t0 = rtos_getTick();

    if(nn_tcpOpen(&_tcp, _ringR, sizeof(_ringR), _ringT, sizeof(_ringT)) != NN_OK) return 1;
    if(nn_tcpConnect(&_tcp, _host, 17010, 10000) != NN_OK) { nn_tcpAbort(&_tcp); return 1; }
    hdr[0] = (uint8_t)(nBytes >> 24); hdr[1] = (uint8_t)(nBytes >> 16); hdr[2] = (uint8_t)(nBytes >> 8); hdr[3] = (uint8_t)nBytes;
    if(nn_tcpSend(&_tcp, hdr, 4, 5000) != 4) fail = 2;
    while(fail == 0  &&  sent < nBytes)
    {
        const uint32_t n2 = nBytes - sent < sizeof(tx) ? nBytes - sent : (uint32_t)sizeof(tx);
        for(k=0; k<n2; ++k) tx[k] = pattern(sent + k);
        r = nn_tcpSend(&_tcp, tx, n2, 20000);
        if(r <= 0) { fail = 3; break; }
        sent += (uint32_t)r;
    }
    r = 0;
    while(fail == 0  &&  r < 4)
    {
        const int32_t m = nn_tcpRecv(&_tcp, hdr + r, 4 - (size_t)r, 20000);
        if(m <= 0) { fail = 4; break; }
        r += m;
    }
    if(fail == 0  &&  (hdr[0] | hdr[1] | hdr[2] | hdr[3]) != 0) fail = 4;
    while(fail == 0  &&  got < nBytes)
    {
        r = nn_tcpRecv(&_tcp, rx, sizeof(rx), 20000);
        if(r <= 0) { fail = 5; break; }
        for(k=0; k<(uint32_t)r; ++k)
            if(rx[k] != pattern(got + k)) ++bad;
        got += (uint32_t)r;
    }
    if(fail == 0  &&  bad != 0) fail = 6;
    if(fail == 0  &&  nn_tcpRecv(&_tcp, rx, sizeof(rx), 10000) != 0) fail = 7;
    *pMs = (uint32_t)(rtos_getTick() - t0);
    if(fail != 0)
    {
        printf("sink failed at step %u: sent %lu got %lu bad %lu, %s err %d\n", fail,
               (unsigned long)sent, (unsigned long)got, (unsigned long)bad, nn_tcpStateName(nn_tcpState(&_tcp)), (int)_tcp.err);
        nn_tcpAbort(&_tcp);
        return fail;
    }
    nn_tcpClose(&_tcp);
    for(j=0; j<2000 && nn_tcpState(&_tcp) != NN_TCP_CLOSED; ++j) rtos_delay(10);
    if(nn_tcpState(&_tcp) != NN_TCP_CLOSED) { printf("sink: close did not finish, aborted\n"); nn_tcpAbort(&_tcp); }
    return 0;
}

static void testTask(void *arg)
{
    const char *soak = getenv("NN_SOAK_SECONDS");
    const uint32_t secs = soak != NULL ? (uint32_t)atoi(soak) : 600u;
    const pid_t echo = spawn("exec python3 tools/udp_echo.py 10.0.77.1 17007");
    const pid_t dns = spawn("exec python3 tools/dns_stub.py 10.0.77.1 15353");
    const pid_t sinkPid = spawn("exec python3 tools/tcp_sink.py 10.0.77.1 17010");
    static nn_udp_t sock;
    static uint8_t tx[1400], rx[1400];
    uint32_t udpSent = 0, udpOk = 0, dnsN = 0, dnsOk = 0, tcpN = 0, tcpOk = 0, tcpMsMax = 0, tcpMsSum = 0, cycle = 0;
    rtos_tick_t t0;
    nn_bufStats_t bs;
    nn_arpStats_t as;
    nn_tcpStats_t ts;
    unsigned i;
    (void)arg;

    rtos_delay(700);
    nn_lock();
    nn_dnsSetServer(_host);
    nn_dnsSetServerPort(15353);
    nn_unlock();
    printf("netem soak for %lu s\n", (unsigned long)secs);
    fflush(stdout);
    t0 = rtos_getTick();
    while(rtos_getTick() - t0 < secs * 1000ul)
    {
        uint32_t ms = 0, okHere = 0;
        nn_ip4_t addr;
        nn_err_t dr;
        bool tcpGood;
        ++ cycle;
        CHECK_EQ(nn_udpOpen(&sock), NN_OK);
        CHECK_EQ(nn_udpConnect(&sock, _host, 17007), NN_OK);
        for(i=0; i<20; ++i)
        {
            const uint16_t n = (uint16_t)(1 + ((cycle * 20 + i) * 97u) % 1400u);
            uint16_t k;
            int32_t r;
            for(k=0; k<n; ++k) tx[k] = (uint8_t)(k ^ i);
            if(nn_udpSend(&sock, tx, n) != NN_OK) continue;
            ++ udpSent;
            r = nn_udpRecvFrom(&sock, rx, sizeof(rx), NULL, NULL, 1000);
            if(r == n  &&  memcmp(rx, tx, n) == 0) { ++udpOk; ++okHere; }
        }
        nn_udpClose(&sock);
        ++ dnsN;
        dr = nn_dnsResolve(cycle & 1 ? "nornos.test" : "other.test", &addr, 6000);
        if((cycle & 1) ? dr == NN_OK : dr == NN_ERR_NODEV)
            ++ dnsOk;                           /* other.test: the stub's "no such name" is an answer */
        ++ tcpN;
        tcpGood = sink(100000, &ms) == 0;
        if(tcpGood) { ++tcpOk; tcpMsSum += ms; if(ms > tcpMsMax) tcpMsMax = ms; }
        nn_lock();
        nn_bufGetStats(&bs); nn_arpGetStats(&as); nn_tcpGetStats(&ts);
        nn_unlock();
        printf("cycle %lu t %lu s: udp %lu/20, tcp %s in %lu ms | udp %lu/%lu dns %lu/%lu tcp %lu/%lu avg %lu max %lu ms | "
               "arp resolved %lu timeouts %lu | tcp rexmit %lu fast %lu to %lu ooo %lu | bufs free %u/%u min %u failed %u\n",
               (unsigned long)cycle, (unsigned long)((rtos_getTick() - t0) / 1000ul), (unsigned long)okHere, tcpGood ? "ok" : "FAIL", (unsigned long)ms,
               (unsigned long)udpOk, (unsigned long)udpSent, (unsigned long)dnsOk, (unsigned long)dnsN, (unsigned long)tcpOk, (unsigned long)tcpN,
               (unsigned long)(tcpOk ? tcpMsSum / tcpOk : 0), (unsigned long)tcpMsMax,
               (unsigned long)as.resolved, (unsigned long)as.timeouts,
               (unsigned long)ts.rexmits, (unsigned long)ts.fastRexmits, (unsigned long)ts.timeouts, (unsigned long)ts.rxOoo,
               bs.free, bs.numBufs, bs.minFree, bs.allocFailed);
        fflush(stdout);
        rtos_delay(3000);
    }
    nn_lock();
    nn_bufGetStats(&bs); nn_arpGetStats(&as);
    nn_unlock();
    CHECK_EQ(tcpOk, tcpN);
    CHECK(udpSent > 0  &&  udpOk * 2 >= udpSent);
    CHECK(dnsN > 0  &&  dnsOk * 5 >= dnsN * 4);
    CHECK(as.resolved >= 1);                            /* re-resolutions show in the log (entries age out) */
    CHECK_EQ(bs.free, bs.numBufs);
    CHECK_EQ(bs.allocFailed, 0);
    CHECK_EQ(_tap.stats.txErrors, 0);
    kill(echo, SIGTERM); kill(dns, SIGTERM); kill(sinkPid, SIGTERM);
    test_finish("test_netem");
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
        printf("test_netem: cannot open TAP %s (run sudo tools/tap_setup.sh)\n", ifName);
        printf("RESULT test_netem SKIP\n");
        return 0;
    }
    nn_host_watchFd(nn_drv_tapFd(&_tap), &_tap, nn_drv_tapPollIsr);
    CHECK_EQ(nn_ifaceAdd(&_tap, &_if, _us, nn_ip4(255, 255, 255, 0), _host), NN_OK);
    rtos_createTask(TASK_TEST, testTask, NULL, _stackTest, sizeof(_stackTest));
    rtos_start();
    return 0;
}
