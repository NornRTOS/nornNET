/**
 * @file nn02_ping.c
 * nornNET test 2, in QEMU: the stack talks to a real peer. QEMU's user mode network
 * (slirp) answers ARP and ICMP echo for its gateway 10.0.2.2; we take the static
 * address 10.0.2.15, resolve the gateway, ping it 20 times and check the replies:
 * sequence numbers, payload pattern, round trip time, and that no buffer leaked.
 * Also a ping to a host that does not exist (ARP must give up without leaking) and
 * loopback through 127.0.0.1 and our own address.
 *
 *   RESULT nn02 PASS
 */

#include <string.h>

#include "rtos.h"
#include "uart.h"
#include "testresult.h"
#include "nn_net.h"
#include "nn_ip.h"
#include "nn_arp.h"
#include "nn_icmp.h"
#include "nn_drv_openeth.h"
#include "nn_drv_loop.h"

#define TASK_TEST       2u
#define STACK_SIZE      3072u
/** Build with EXTRA_CFLAGS="-DNN02_PINGS=15000 -DNN02_INTERVAL_MS=20" for a soak run. */
#ifndef NN02_PINGS
# define NN02_PINGS     20u
#endif
#ifndef NN02_INTERVAL_MS
# define NN02_INTERVAL_MS 50u
#endif
#define NUM_PINGS       ((uint32_t)NN02_PINGS)
#define PING_ID         0x4E4Eu
#define PAYLOAD         56u

static uint8_t _stackTest[STACK_SIZE];
static nn_netdev_t _eth, _lo;
static nn_iface_t _ifEth, _ifLo;
static const uint8_t _mac[6] = { 0x02, 0x4E, 0x4E, 0x00, 0x00, 0x10 };

static volatile uint32_t _replies, _badReplies, _loReplies;
static volatile uint32_t _rttSum, _rttMax;
static volatile uint32_t _sentAt;

static void onReply(nn_ip4_t from, uint16_t id, uint16_t seq, const uint8_t *p, uint16_t len, void *arg)
{
    (void)arg; (void)seq;
    if(nn_ip4Equal(from, nn_ip4(10, 0, 2, 2)))
    {
        uint16_t i;
        bool ok = id == PING_ID  &&  len == PAYLOAD;
        for(i=0; ok && i<len; ++i)
            ok = p[i] == (uint8_t)i;
        if(ok)
        {
            const uint32_t rtt = rtos_getTick() - _sentAt;
            ++ _replies;
            _rttSum += rtt;
            if(rtt > _rttMax)
                _rttMax = rtt;
        }
        else
            ++ _badReplies;
    }
    else
        ++ _loReplies;
    rtos_notify(TASK_TEST, 1, RTOS_NOTIFY_OR);
}

static void testTask(void *arg)
{
    nn_bufStats_t bs;
    nn_arpStats_t as;
    nn_icmpStats_t cs;
    nn_ipStats_t is;
    char s[16];
    uint32_t i, freeAtStart;
    uint8_t mac[6];
    (void)arg;

    /* The receive descriptors own a buffer each, so "all free" is the pool minus those. */
    nn_lock();
    nn_bufGetStats(&bs);
    nn_unlock();
    freeAtStart = bs.free;

    uart_puts("nn02: ping ");
    uart_puts(nn_ip4ToStr(s, nn_ip4(10, 0, 2, 2)));
    uart_puts(" from ");
    uart_puts(nn_ip4ToStr(s, _ifEth.addr));
    uart_puts("\r\n");

    nn_lock();
    nn_icmpOnEchoReply(onReply, NULL);
    nn_unlock();

    for(i=1; i<=NUM_PINGS; ++i)
    {
        nn_lock();
        _sentAt = rtos_getTick();
        nn_icmpEchoRequest(nn_ip4(10, 0, 2, 2), PING_ID, (uint16_t)i, NULL, PAYLOAD);
        nn_unlock();
        rtos_notifyTake(1000);
        rtos_delay(NN02_INTERVAL_MS);
    }
    uart_puts("replies ");
    uart_putU32(_replies);
    uart_puts("/");
    uart_putU32(NUM_PINGS);
    uart_puts(" rtt avg ");
    uart_putU32(_replies ? _rttSum / _replies : 0);
    uart_puts(" max ");
    uart_putU32(_rttMax);
    uart_puts(" ms\r\n");
    tc_expectRange("replies", _replies, NUM_PINGS - 1 - NUM_PINGS / 100, NUM_PINGS);  /* the first may lose the ARP race */
    tc_expectRange("badReplies", _badReplies, 0, 0);
    tc_expectRange("rttMax", _rttMax, 0, 500);
    nn_lock();
    tc_expect("gwResolved", nn_arpLookup(nn_ip4(10, 0, 2, 2), mac));
    nn_unlock();

    /* Loopback: 127.0.0.1 and our own address are answered by ourselves. */
    nn_lock();
    nn_icmpEchoRequest(nn_ip4(127, 0, 0, 1), PING_ID, 100, NULL, 8);
    nn_unlock();
    rtos_notifyTake(200);
    nn_lock();
    nn_icmpEchoRequest(_ifEth.addr, PING_ID, 101, NULL, 8);
    nn_unlock();
    rtos_notifyTake(200);
    tc_expectRange("loReplies", _loReplies, 2, 2);

    /* A host that is not there: ARP retries, gives up, frees the parked packet. */
    nn_lock();
    nn_icmpEchoRequest(nn_ip4(10, 0, 2, 99), PING_ID, 200, NULL, 8);
    nn_unlock();
    rtos_delay((NN_CFG_ARP_RETRIES + 2) * NN_CFG_ARP_RETRY_MS);
    nn_lock();
    nn_arpGetStats(&as);
    nn_icmpGetStats(&cs);
    nn_ipGetStats(&is);
    nn_bufGetStats(&bs);
    nn_unlock();
    tc_expectRange("arpTimeouts", as.timeouts, 1, 1);
    tc_expectRange("arpRequests", as.txRequests, 1 + NN_CFG_ARP_RETRIES + 1, 2 + NN_CFG_ARP_RETRIES + 1);
    tc_expectRange("icmpTx", cs.txEchoRequests, NUM_PINGS + 3, NUM_PINGS + 3);
    tc_expectRange("ipBadHeader", is.rxBadHeader + is.rxBadChecksum, 0, 0);
    tc_expectRange("rxDropped", _eth.stats.rxDropped, 0, 0);
    tc_expectRange("txErrors", _eth.stats.txErrors, 0, 0);
    tc_expectRange("freeEnd", bs.free, freeAtStart, freeAtStart);
    tc_expectRange("freeAtStart", freeAtStart, NN_CFG_NUM_BUFS - 8, NN_CFG_NUM_BUFS - 8);
    tc_expectRange("allocFailed", bs.allocFailed, 0, 0);
    uart_puts("eth rx ");
    uart_putU32(_eth.stats.rxFrames);
    uart_puts(" tx ");
    uart_putU32(_eth.stats.txFrames);
    uart_puts(" ip notForUs ");
    uart_putU32(is.rxNotForUs);
    uart_puts(" noProto ");
    uart_putU32(is.rxNoProto);
    uart_puts("\r\n");
    tc_finish("nn02");
}

int main(void)
{
    uart_init(115200);
    rtos_init();
    nn_init();
    nn_drv_loopRegister(&_lo);
    nn_ifaceAdd(&_lo, &_ifLo, nn_ip4(127, 0, 0, 1), nn_ip4(255, 0, 0, 0), nn_ip4(0, 0, 0, 0));
    if(nn_drv_openethRegister(&_eth, _mac) != NN_OK)
    {
        uart_puts("CHECK FAILED: open_eth init\r\nRESULT nn02 FAIL\r\n");
        rtos_port_halt();
    }
    nn_ifaceAdd(&_eth, &_ifEth, nn_ip4(10, 0, 2, 15), nn_ip4(255, 255, 255, 0), nn_ip4(10, 0, 2, 2));
    rtos_createTask(TASK_TEST, testTask, NULL, _stackTest, sizeof(_stackTest));
    rtos_start();
    return 0;
}
