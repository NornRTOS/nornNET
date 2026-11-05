/**
 * @file nn01_loop.c
 * nornNET test 1 on the target: the foundation. The stack runs on nornOS with its net
 * task; a test task sends frames through the loopback device and checks that they come
 * back through the Ethernet layer to a registered protocol without being copied, that a
 * burst beyond the receive queue is dropped and accounted, that timers fire from the net
 * task on time, and that no buffer leaks. Then a throughput figure: loopback round trips
 * per second with 1 KB payload.
 *
 *   RESULT nn01 PASS
 */

#include <string.h>

#include "rtos.h"
#include "uart.h"
#include "testresult.h"
#include "nn_net.h"
#include "nn_eth.h"
#include "nn_timer.h"
#include "nn_drv_loop.h"

#define TASK_TEST       2u
#define TASK_LOW        1u

#define STACK_SIZE      2048u

static uint8_t _stackTest[STACK_SIZE];
static uint8_t _stackLow[STACK_SIZE];
static nn_netdev_t _lo;
static nn_proto_t _proto;

static nn_buf_t *_pLastRx;
static const uint8_t *_pLastPayload;
static uint16_t _lastLen;
static uint32_t _nRx;
static uint8_t _lastByte;
static uint32_t _timerFiredAt;
static uint32_t _periodicCount;
static nn_timer_t _tOnce, _tPeriodic;

static void protoInput(nn_buf_t *pB, nn_netdev_t *pDev)
{
    (void)pDev;
    _pLastRx = pB;
    _pLastPayload = pB->pData;
    _lastLen = pB->len;
    _lastByte = pB->pData[0];
    ++ _nRx;
    nn_bufFree(pB);
}

static void onceCb(nn_timer_t *pT, void *arg)
{
    (void)pT; (void)arg;
    _timerFiredAt = rtos_getTick();
    rtos_notify(TASK_TEST, 1, RTOS_NOTIFY_OR);
}

static void periodicCb(nn_timer_t *pT, void *arg)
{
    (void)pT; (void)arg;
    ++ _periodicCount;
}

static void lowTask(void *arg)
{
    (void)arg;
    for(;;)
        rtos_delay(RTOS_FOREVER);
}

static void testTask(void *arg)
{
    nn_buf_t *pB;
    uint8_t *pPayload;
    nn_bufStats_t st;
    uint32_t i, t0, n;
    (void)arg;

    uart_puts("nn01: nornNET foundation on ");
    uart_puts(_lo.name);
    uart_puts("\r\n");

    /* Round trip, zero copy. */
    pB = nn_bufAlloc(NN_CFG_TX_HEADROOM);
    tc_expect("alloc", pB != NULL);
    pPayload = nn_bufPut(pB, 100);
    memset(pPayload, 0x42, 100);
    tc_expect("output", nn_eth_output(&_lo, pB, nn_eth_broadcast, NN_ETH_TYPE_LOCAL) == NN_OK);
    tc_expectRange("rx1", _nRx, 1, 1);
    tc_expect("sameBuffer", _pLastRx == pB);
    tc_expect("samePayload", _pLastPayload == pPayload);
    tc_expectRange("len", _lastLen, 100, 100);
    tc_expectRange("byte", _lastByte, 0x42, 0x42);

    /* Burst under the lock: the first frame is handed straight to the waiting net task
       (nornOS queue hand-over), NN_CFG_RX_QUEUE more fill the queue, the surplus is
       dropped and freed. */
    nn_lock();
    for(i=0; i<NN_CFG_NUM_BUFS; ++i)
    {
        pB = nn_bufAlloc(NN_CFG_TX_HEADROOM);
        tc_expect("allocBurst", pB != NULL);
        pPayload = nn_bufPut(pB, 1);
        pPayload[0] = (uint8_t)i;
        nn_eth_output(&_lo, pB, nn_eth_broadcast, NN_ETH_TYPE_LOCAL);
    }
    tc_expectRange("rxLocked", _nRx, 1, 1);
    nn_bufGetStats(&st);
    tc_expectRange("freeLocked", st.free, NN_CFG_NUM_BUFS - NN_CFG_RX_QUEUE - 1, NN_CFG_NUM_BUFS - NN_CFG_RX_QUEUE - 1);
    nn_unlock();
    tc_expectRange("rxBurst", _nRx, 2 + NN_CFG_RX_QUEUE, 2 + NN_CFG_RX_QUEUE);
    tc_expectRange("fifo", _lastByte, NN_CFG_RX_QUEUE, NN_CFG_RX_QUEUE);
    tc_expectRange("dropped", _lo.stats.rxDropped, NN_CFG_NUM_BUFS - NN_CFG_RX_QUEUE - 1, NN_CFG_NUM_BUFS - NN_CFG_RX_QUEUE - 1);

    /* Timers: short one started while the net task sleeps forever. */
    nn_lock();
    nn_timerSetup(&_tOnce, onceCb, NULL);
    nn_timerSetup(&_tPeriodic, periodicCb, NULL);
    nn_timerStart(&_tPeriodic, 500, 100);
    nn_timerStart(&_tOnce, 5, 0);
    nn_unlock();
    t0 = rtos_getTick();
    tc_expect("onceNotified", rtos_notifyTake(50));
    tc_expectRange("onceAt", _timerFiredAt - t0, 5, 6);
    rtos_delay(1000);
    tc_expectRange("periodic", _periodicCount, 5, 6);
    nn_lock();
    nn_timerStop(&_tPeriodic);
    nn_unlock();

    /* Throughput: round trips of 1 KB for one second. */
    _nRx = 0;
    t0 = rtos_getTick();
    n = 0;
    while(rtos_getTick() - t0 < 1000)
    {
        pB = nn_bufAlloc(NN_CFG_TX_HEADROOM);
        if(pB == NULL)
            break;
        nn_bufPut(pB, 1024);
        nn_eth_output(&_lo, pB, nn_eth_broadcast, NN_ETH_TYPE_LOCAL);
        ++ n;
    }
    tc_expect("throughputNoAllocFail", pB != NULL);
    tc_expectRange("throughputRx", _nRx, n, n);
    uart_puts("loopback round trips/s (1 KB): ");
    uart_putU32(n);
    uart_puts("\r\n");

    nn_bufGetStats(&st);
    tc_expectRange("freeEnd", st.free, NN_CFG_NUM_BUFS, NN_CFG_NUM_BUFS);
    tc_expectRange("allocFailed", st.allocFailed, 0, 0);
    tc_expectRange("stackNet", rtos_getStackFree(NN_CFG_TASK_PRIO), 256, NN_CFG_TASK_STACK);
    tc_expectRange("stackTest", rtos_getStackFree(TASK_TEST), 256, STACK_SIZE);
    tc_finish("nn01");
}

int main(void)
{
    uart_init(115200);
    rtos_init();
    nn_init();
    nn_drv_loopRegister(&_lo);
    memset(&_proto, 0, sizeof(_proto));
    _proto.type = NN_ETH_TYPE_LOCAL;
    _proto.name = "test";
    _proto.input = protoInput;
    nn_protoRegister(&_proto);
    rtos_createTask(TASK_LOW, lowTask, NULL, _stackLow, sizeof(_stackLow));
    rtos_createTask(TASK_TEST, testTask, NULL, _stackTest, sizeof(_stackTest));
    rtos_start();
    return 0;
}
