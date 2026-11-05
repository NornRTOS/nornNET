/**
 * @file nn03_udp.c
 * nornNET test 3, in QEMU: v0.2 against real peers. DHCP from slirp (expects 10.0.2.15,
 * gateway 10.0.2.2, DNS 10.0.2.3), then 200 UDP echo round trips to tools/udp_echo.py on
 * the host (10.0.2.2:17007) with varying sizes, DNS resolution of nornos.test through
 * tools/dns_stub.py (10.0.2.2:15353) and a negative answer, and a datagram to a closed
 * port for the ICMP error path. No buffer may leak.
 *
 *   RESULT nn03 PASS
 */

#include <string.h>

#include "rtos.h"
#include "uart.h"
#include "testresult.h"
#include "nn_net.h"
#include "nn_ip.h"
#include "nn_udp.h"
#include "nn_dhcp.h"
#include "nn_dns.h"
#include "nn_icmp.h"
#include "nn_drv_openeth.h"

#define TASK_TEST       2u
#define STACK_SIZE      4096u
#define ECHO_PORT       17007u
#define DNS_PORT        15353u
#define NUM_ECHO        200u

static uint8_t _stackTest[STACK_SIZE];
static nn_netdev_t _eth;
static nn_iface_t _ifEth;
static nn_dhcp_t _dhcp;
static nn_udp_t _sock;
static const uint8_t _mac[6] = { 0x02, 0x4E, 0x4E, 0x00, 0x00, 0x11 };
static volatile uint32_t _boundEvents;
static uint8_t _txBuf[1200], _rxBuf[1200];

static void onDhcp(nn_dhcp_t *pD, bool bound, void *arg)
{
    (void)pD; (void)arg;
    if(bound)
    {
        ++ _boundEvents;
        rtos_notify(TASK_TEST, 1, RTOS_NOTIFY_OR);
    }
}

static void testTask(void *arg)
{
    nn_bufStats_t bs;
    nn_udpStats_t us;
    nn_icmpStats_t cs;
    nn_ip4_t host = nn_ip4(10, 0, 2, 2), addr, from;
    char s[16];
    uint32_t i, ok = 0, freeAtStart, t0, rttMax = 0, bytes = 0;
    uint16_t port;
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
    uart_puts("nn03: dhcp ");
    uart_puts(nn_dhcpIsBound(&_dhcp) ? "bound " : "FAILED ");
    uart_puts(nn_ip4ToStr(s, _ifEth.addr));
    uart_puts(" gw ");
    uart_puts(nn_ip4ToStr(s, _ifEth.gw));
    uart_puts(" dns ");
    uart_puts(nn_ip4ToStr(s, nn_dnsGetServer()));
    uart_puts(" lease ");
    uart_putU32(_dhcp.leaseS);
    uart_puts(" s in ");
    uart_putU32(rtos_getTick() - t0);
    uart_puts(" ms\r\n");
    tc_expect("dhcpBound", nn_dhcpIsBound(&_dhcp));
    tc_expectRange("boundEvents", _boundEvents, 1, 1);
    tc_expect("dhcpAddr", nn_ip4Equal(_ifEth.addr, nn_ip4(10, 0, 2, 15)));
    tc_expect("dhcpGw", nn_ip4Equal(_ifEth.gw, host));
    tc_expect("dhcpDns", nn_ip4Equal(nn_dnsGetServer(), nn_ip4(10, 0, 2, 3)));
    tc_expectRange("dhcpDiscovers", _dhcp.discovers, 1, 2);

    /* UDP echo: sizes 1, 2, 4, ... and odd lengths; payload pattern checked. */
    tc_expect("udpOpen", nn_udpOpen(&_sock) == NN_OK);
    tc_expect("udpConnect", nn_udpConnect(&_sock, host, ECHO_PORT) == NN_OK);
    for(i=0; i<NUM_ECHO; ++i)
    {
        const uint16_t n = (uint16_t)(1 + (i * 37u) % 1200u);
        uint16_t k;
        int32_t r;
        uint32_t t;
        for(k=0; k<n; ++k)
            _txBuf[k] = (uint8_t)(k + i);
        t = rtos_getTick();
        if(nn_udpSend(&_sock, _txBuf, n) != NN_OK)
            continue;
        r = nn_udpRecvFrom(&_sock, _rxBuf, sizeof(_rxBuf), &from, &port, 1000);
        t = rtos_getTick() - t;
        if(r == n  &&  memcmp(_rxBuf, _txBuf, n) == 0  &&  port == ECHO_PORT  &&  nn_ip4Equal(from, host))
        {
            ++ ok;
            bytes += n;
            if(t > rttMax) rttMax = t;
        }
    }
    uart_puts("udp echo ");
    uart_putU32(ok);
    uart_puts("/");
    uart_putU32(NUM_ECHO);
    uart_puts(" ok, ");
    uart_putU32(bytes);
    uart_puts(" bytes, rtt max ");
    uart_putU32(rttMax);
    uart_puts(" ms\r\n");
    tc_expectRange("echoOk", ok, NUM_ECHO - 2, NUM_ECHO);   /* the first may wait for ARP */
    tc_expectRange("echoRttMax", rttMax, 0, 300);
    nn_udpClose(&_sock);

    /* DNS via the stub on the host, then a name it does not know. */
    nn_lock();
    nn_dnsSetServer(host);
    nn_dnsSetServerPort(DNS_PORT);
    nn_unlock();
    t0 = rtos_getTick();
    tc_expect("dnsResolve", nn_dnsResolve("nornos.test", &addr, 5000) == NN_OK);
    tc_expect("dnsAddr", nn_ip4Equal(addr, nn_ip4(192, 0, 2, 42)));
    uart_puts("dns nornos.test -> ");
    uart_puts(nn_ip4ToStr(s, addr));
    uart_puts(" in ");
    uart_putU32(rtos_getTick() - t0);
    uart_puts(" ms\r\n");
    tc_expect("dnsCached", nn_dnsResolve("nornos.test", &addr, 5000) == NN_OK);
    tc_expect("dnsNegative", nn_dnsResolve("nobody.test", &addr, 5000) == NN_ERR_NODEV);
    tc_expect("dnsLiteral", nn_dnsResolve("1.2.3.4", &addr, 5000) == NN_OK  &&  addr.b[3] == 4);

    /* A datagram to a closed port on the host: slirp relays the ICMP port unreachable. */
    nn_lock();
    nn_icmpGetStats(&cs);
    nn_unlock();
    {
        const uint32_t errorsBefore = cs.rxErrors;
        nn_udpOpen(&_sock);
        nn_udpSendTo(&_sock, _txBuf, 8, host, 17999);
        rtos_delay(500);
        nn_udpClose(&_sock);
        nn_lock();
        nn_icmpGetStats(&cs);
        nn_unlock();
        uart_puts("icmp errors received ");
        uart_putU32(cs.rxErrors - errorsBefore);
        uart_puts("\r\n");
    }

    rtos_delay(200);
    nn_lock();
    nn_bufGetStats(&bs);
    nn_udpGetStats(&us);
    nn_unlock();
    tc_expectRange("udpBad", us.rxBad + us.rxBadChecksum, 0, 0);
    tc_expectRange("rxDropped", _eth.stats.rxDropped, 0, 0);
    tc_expectRange("freeEnd", bs.free, freeAtStart, freeAtStart);
    tc_expectRange("allocFailed", bs.allocFailed, 0, 0);
    tc_expectRange("stackNet", rtos_getStackFree(NN_CFG_TASK_PRIO), 256, NN_CFG_TASK_STACK);
    tc_expectRange("stackTest", rtos_getStackFree(TASK_TEST), 256, STACK_SIZE);
    tc_finish("nn03");
}

int main(void)
{
    uart_init(115200);
    rtos_init();
    nn_init();
    if(nn_drv_openethRegister(&_eth, _mac) != NN_OK)
    {
        uart_puts("CHECK FAILED: open_eth init\r\nRESULT nn03 FAIL\r\n");
        rtos_port_halt();
    }
    nn_ifaceAdd(&_eth, &_ifEth, nn_ip4(0, 0, 0, 0), nn_ip4(0, 0, 0, 0), nn_ip4(0, 0, 0, 0));
    rtos_createTask(TASK_TEST, testTask, NULL, _stackTest, sizeof(_stackTest));
    rtos_start();
    return 0;
}
