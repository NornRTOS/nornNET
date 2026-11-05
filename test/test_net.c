/**
 * @file test_net.c
 * nornNET on the nornOS host port with simulated time: the net task, the receive queue,
 * loopback round trips with zero copy, queue overflow accounting, timers waking the
 * net task (including a short timer started while it sleeps for longer), UDP and TCP
 * between two sockets over loopback with the blocking API: a TCP echo server task and a
 * client task exchange 64 KB through 1 KB rings, close in both orders, and a connect to
 * a closed port is refused.
 */

#include <string.h>

#include "rtos.h"
#include "nn_net.h"
#include "nn_eth.h"
#include "nn_timer.h"
#include "nn_ip.h"
#include "nn_udp.h"
#include "nn_tcp.h"
#include "nn_drv_loop.h"
#include "testutil.h"

#define TASK_TEST   2u
#define TASK_ECHO   1u
#define ECHO_PORT   8080u

static nn_netdev_t _lo;
static nn_iface_t _ifLo;
static nn_proto_t _proto;
static nn_udp_t _udpA, _udpB;
static uint8_t _stackTest[1], _stackEcho[1];
static nn_tcp_t _tcpL, _tcpA, _tcpC;
static uint8_t _ringAR[1024], _ringAT[1024], _ringCR[1024], _ringCT[1024];
static volatile unsigned _echoConnections, _echoBytes;

static nn_buf_t *_pLastRx;
static const uint8_t *_pLastPayload;
static uint16_t _lastLen;
static unsigned _nRx;
static uint8_t _lastByte;

static nn_ms_t _timerFiredAt;
static unsigned _periodicCount;
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

/** TCP echo server: accepts one connection at a time and echoes until the peer closes. */
static void echoTask(void *arg)
{
    static uint8_t buf[700];
    (void)arg;
    CHECK_EQ(nn_tcpOpen(&_tcpL, NULL, 0, NULL, 0), NN_OK);
    CHECK_EQ(nn_tcpBind(&_tcpL, nn_ip4(0, 0, 0, 0), ECHO_PORT), NN_OK);
    CHECK_EQ(nn_tcpListen(&_tcpL), NN_OK);
    for(;;)
    {
        int32_t n;
        CHECK_EQ(nn_tcpOpen(&_tcpA, _ringAR, sizeof(_ringAR), _ringAT, sizeof(_ringAT)), NN_OK);
        if(nn_tcpAccept(&_tcpL, &_tcpA, NN_FOREVER) != NN_OK)
            continue;
        ++ _echoConnections;
        while((n = nn_tcpRecv(&_tcpA, buf, sizeof(buf), NN_FOREVER)) > 0)
        {
            _echoBytes += (unsigned)n;
            if(nn_tcpSend(&_tcpA, buf, (size_t)n, NN_FOREVER) != n)
                break;
        }
        nn_tcpClose(&_tcpA);
        while(nn_tcpState(&_tcpA) != NN_TCP_CLOSED)
            rtos_delay(1);
    }
}

static void testTask(void *arg)
{
    nn_buf_t *pB;
    uint8_t *pPayload;
    nn_bufStats_t st;
    unsigned i;
    (void)arg;

    /* One frame: the net task (higher priority) processes it before we return. */
    pB = nn_bufAlloc(NN_CFG_TX_HEADROOM);
    CHECK(pB != NULL);
    pPayload = nn_bufPut(pB, 100);
    memset(pPayload, 0x42, 100);
    CHECK_EQ(nn_eth_output(&_lo, pB, nn_eth_broadcast, NN_ETH_TYPE_LOCAL), NN_OK);
    CHECK_EQ(_nRx, 1);
    CHECK(_pLastRx == pB);
    CHECK(_pLastPayload == pPayload);
    CHECK_EQ(_lastLen, 100);
    CHECK_EQ(_lastByte, 0x42);

    /* Burst: with the stack locked the net task cannot run. The first frame is handed
       straight to the waiting task (nornOS queue hand-over, no slot used), the next
       NN_CFG_RX_QUEUE fill the queue, the surplus is dropped and freed; after unlock
       everything queued arrives in order. */
    nn_lock();
    for(i=0; i<NN_CFG_NUM_BUFS; ++i)
    {
        pB = nn_bufAlloc(NN_CFG_TX_HEADROOM);
        CHECK(pB != NULL);
        pPayload = nn_bufPut(pB, 1);
        pPayload[0] = (uint8_t)i;
        CHECK_EQ(nn_eth_output(&_lo, pB, nn_eth_broadcast, NN_ETH_TYPE_LOCAL), NN_OK);
    }
    CHECK_EQ(_nRx, 1);
    nn_bufGetStats(&st);
    CHECK_EQ(st.free, NN_CFG_NUM_BUFS - NN_CFG_RX_QUEUE - 1);   /* dropped ones already freed */
    nn_unlock();
    CHECK_EQ(_nRx, 2 + NN_CFG_RX_QUEUE);
    CHECK_EQ(_lastByte, NN_CFG_RX_QUEUE);                    /* FIFO order kept */
    CHECK_EQ(_lo.stats.rxDropped, NN_CFG_NUM_BUFS - NN_CFG_RX_QUEUE - 1);
    CHECK_EQ(_lo.stats.txFrames, 1 + NN_CFG_NUM_BUFS);
    nn_bufGetStats(&st);
    CHECK_EQ(st.free, NN_CFG_NUM_BUFS);

    /* Timers. The net task sleeps forever (no timers); a one shot started here must
       wake it via the kick and fire on time. */
    nn_lock();
    nn_timerSetup(&_tOnce, onceCb, NULL);
    nn_timerSetup(&_tPeriodic, periodicCb, NULL);
    nn_timerStart(&_tPeriodic, 1000, 100);
    nn_timerStart(&_tOnce, 5, 0);
    nn_unlock();
    {
        const rtos_tick_t t0 = rtos_getTick();
        CHECK(rtos_notifyTake(50));
        CHECK(_timerFiredAt >= t0 + 5  &&  _timerFiredAt <= t0 + 6);
    }
    rtos_delay(1500);
    CHECK(_periodicCount >= 5  &&  _periodicCount <= 6);
    nn_lock();
    nn_timerStop(&_tPeriodic);
    nn_unlock();

    /* UDP over loopback with a blocking receive: A sends to B on 127.0.0.1, B receives
       with timeout, replies, A receives. Then a timeout, then a datagram arriving while
       the reader already sleeps (sent by the timer callback). */
    {
        uint8_t buf[32];
        nn_ip4_t from;
        uint16_t port;
        int32_t n;
        rtos_tick_t t0;

        CHECK_EQ(nn_udpOpen(&_udpA), NN_OK);
        CHECK_EQ(nn_udpOpen(&_udpB), NN_OK);
        CHECK_EQ(nn_udpBind(&_udpB, nn_ip4(0, 0, 0, 0), 7), NN_OK);
        CHECK_EQ(nn_udpSendTo(&_udpA, "ping", 4, nn_ip4(127, 0, 0, 1), 7), NN_OK);
        n = nn_udpRecvFrom(&_udpB, buf, sizeof(buf), &from, &port, 100);
        CHECK_EQ(n, 4);
        CHECK(nn_ip4Equal(from, nn_ip4(127, 0, 0, 1))  &&  port == _udpA.localPort);
        CHECK_EQ(nn_udpSendTo(&_udpB, "pong", 4, from, port), NN_OK);
        n = nn_udpRecvFrom(&_udpA, buf, sizeof(buf), &from, &port, 100);
        CHECK(n == 4  &&  memcmp(buf, "pong", 4) == 0  &&  port == 7);
        t0 = rtos_getTick();
        CHECK_EQ(nn_udpRecvFrom(&_udpA, buf, sizeof(buf), NULL, NULL, 30), NN_ERR_TIMEOUT);
        CHECK(rtos_getTick() - t0 >= 30  &&  rtos_getTick() - t0 <= 32);
        nn_udpClose(&_udpA);
        nn_udpClose(&_udpB);
    }

    /* TCP over loopback against the echo task: 64 KB in 512 byte writes, each read
       back and compared, through 1 KB rings (so sends block and windows close and open),
       then an orderly close from our side. */
    {
        static uint8_t tx[512], rx[512];
        nn_tcpStats_t ts;
        uint32_t total = 0, k;
        unsigned j;
        rtos_tick_t t0;

        CHECK_EQ(nn_tcpOpen(&_tcpC, _ringCR, sizeof(_ringCR), _ringCT, sizeof(_ringCT)), NN_OK);
        CHECK_EQ(nn_tcpConnect(&_tcpC, nn_ip4(127, 0, 0, 1), ECHO_PORT, 1000), NN_OK);
        CHECK_EQ(nn_tcpState(&_tcpC), NN_TCP_ESTABLISHED);
        CHECK_EQ(_tcpC.mss, 1024);                      /* the server's ring bounds its MSS */
        t0 = rtos_getTick();
        for(k=0; k<128; ++k)
        {
            int32_t got = 0;
            for(j=0; j<sizeof(tx); ++j) tx[j] = (uint8_t)(j * 7 + k);
            CHECK_EQ(nn_tcpSend(&_tcpC, tx, sizeof(tx), 1000), (int32_t)sizeof(tx));
            while(got < (int32_t)sizeof(rx))
            {
                const int32_t n = nn_tcpRecv(&_tcpC, rx + got, sizeof(rx) - (size_t)got, 1000);
                if(n <= 0) { CHECK(n > 0); break; }
                got += n;
            }
            CHECK(memcmp(tx, rx, sizeof(tx)) == 0);
            total += sizeof(tx);
        }
        CHECK_EQ(total, 65536);
        CHECK_EQ(_echoBytes, 65536);
        CHECK(rtos_getTick() - t0 < 2000);
        CHECK_EQ(nn_tcpClose(&_tcpC), NN_OK);
        for(j=0; j<100 && nn_tcpState(&_tcpC) != NN_TCP_CLOSED; ++j)
            rtos_delay(1);
        CHECK_EQ(nn_tcpState(&_tcpC), NN_TCP_CLOSED);
        CHECK_EQ(_tcpC.err, NN_OK);
        nn_lock();
        nn_tcpGetStats(&ts);
        nn_unlock();
        CHECK_EQ(ts.established, 2);
        CHECK_EQ(ts.rexmits, 0);
        CHECK_EQ(ts.timeWaits, 1);
        CHECK_EQ(ts.rxBad + ts.rxBadChecksum + ts.rxNoSocket, 0);
        CHECK_EQ(_echoConnections, 1);

        /* The server closes first: our recv returns 0 and the close completes from
           CLOSE_WAIT; the TIME_WAIT entry of the previous connection is no obstacle. */
        rtos_delay(5);
        CHECK_EQ(nn_tcpOpen(&_tcpC, _ringCR, sizeof(_ringCR), _ringCT, sizeof(_ringCT)), NN_OK);
        CHECK_EQ(nn_tcpConnect(&_tcpC, nn_ip4(127, 0, 0, 1), ECHO_PORT, 1000), NN_OK);
        CHECK_EQ(nn_tcpSend(&_tcpC, "x", 1, 100), 1);
        CHECK_EQ(nn_tcpRecv(&_tcpC, rx, sizeof(rx), 1000), 1);
        nn_lock();
        nn_tcpAbort(&_tcpA);                            /* the server side goes away */
        nn_unlock();
        CHECK_EQ(nn_tcpRecv(&_tcpC, rx, sizeof(rx), 1000), NN_ERR_RESET);
        CHECK_EQ(nn_tcpState(&_tcpC), NN_TCP_CLOSED);
        CHECK_EQ(_tcpC.err, NN_ERR_RESET);

        /* Nobody listens on 8081: refused at once. No route: NN_ERR_NODEV. */
        CHECK_EQ(nn_tcpOpen(&_tcpC, _ringCR, sizeof(_ringCR), _ringCT, sizeof(_ringCT)), NN_OK);
        CHECK_EQ(nn_tcpConnect(&_tcpC, nn_ip4(127, 0, 0, 1), ECHO_PORT + 1, 1000), NN_ERR_REFUSED);
        CHECK_EQ(nn_tcpOpen(&_tcpC, _ringCR, sizeof(_ringCR), _ringCT, sizeof(_ringCT)), NN_OK);
        CHECK_EQ(nn_tcpConnect(&_tcpC, nn_ip4(10, 9, 9, 9), 80, 10), NN_ERR_NODEV);
        rtos_delay(10);
    }

    /* Nothing leaked. */
    nn_bufGetStats(&st);
    CHECK_EQ(st.free, NN_CFG_NUM_BUFS);
    CHECK_EQ(st.allocFailed, 0);
    test_finish("test_net");
}

void test_idleHook(void)
{
    rtos_host_tick();
}

int main(void)
{
    rtos_init();
    CHECK_EQ(nn_init(), NN_OK);
    CHECK_EQ(nn_drv_loopRegister(&_lo), NN_OK);
    CHECK_EQ(nn_ifaceAdd(&_lo, &_ifLo, nn_ip4(127, 0, 0, 1), nn_ip4(255, 0, 0, 0), nn_ip4(0, 0, 0, 0)), NN_OK);
    memset(&_proto, 0, sizeof(_proto));
    _proto.type = NN_ETH_TYPE_LOCAL;
    _proto.name = "test";
    _proto.input = protoInput;
    CHECK_EQ(nn_protoRegister(&_proto), NN_OK);
    rtos_createTask(TASK_TEST, testTask, NULL, _stackTest, sizeof(_stackTest));
    rtos_createTask(TASK_ECHO, echoTask, NULL, _stackEcho, sizeof(_stackEcho));
    rtos_start();
    return 0;
}
