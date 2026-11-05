/**
 * @file test_buf.c
 * Pure unit test (POSIX OS layer, no net task): packet buffer arithmetic, pool
 * exhaustion and statistics, Ethernet input filtering and dispatch through
 * nn_net_input, and the timer list order.
 */

#include <string.h>

#include "nn_net.h"
#include "nn_eth.h"
#include "nn_timer.h"
#include "nn_os.h"
#include "testutil.h"

static nn_buf_t *_pGot;
static nn_netdev_t *_pGotDev;
static unsigned _nGot;

static void protoInput(nn_buf_t *pB, nn_netdev_t *pDev)
{
    _pGot = pB;
    _pGotDev = pDev;
    ++ _nGot;
    nn_bufFree(pB);
}

static nn_buf_t *_pTx;

static nn_err_t fakeTransmit(nn_netdev_t *pDev, nn_buf_t *pB)
{
    (void)pDev;
    _pTx = pB;     /* keep it: the test frees it */
    return NN_OK;
}

static nn_err_t failTransmit(nn_netdev_t *pDev, nn_buf_t *pB)
{
    (void)pDev; (void)pB;
    return NN_ERR_IO;
}

static const nn_netdevOps_t _fakeOps = { NULL, NULL, fakeTransmit };
static const nn_netdevOps_t _failOps = { NULL, NULL, failTransmit };
static const uint8_t _mac[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
static const uint8_t _other[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x66 };

static void testBufArithmetic(void)
{
    nn_buf_t *pB = nn_bufAlloc(NN_CFG_TX_HEADROOM);
    uint8_t *p;

    CHECK(pB != NULL);
    CHECK_EQ(nn_bufHeadroom(pB), NN_CFG_TX_HEADROOM);
    CHECK_EQ(pB->len, 0);
    CHECK_EQ(nn_bufTailroom(pB), NN_CFG_BUF_DATA - NN_CFG_TX_HEADROOM);
    CHECK(((uintptr_t)pB->pData & 3u) == 0);          /* payload 4-aligned */

    p = nn_bufPut(pB, 100);
    CHECK(p == pB->pData);
    CHECK_EQ(pB->len, 100);
    CHECK(nn_bufPut(pB, NN_CFG_BUF_DATA) == NULL);    /* too big */
    CHECK_EQ(pB->len, 100);

    p = nn_bufPush(pB, 8);
    CHECK(p == pB->pData  &&  p + 8 == pB->data + NN_CFG_TX_HEADROOM);
    CHECK_EQ(pB->len, 108);
    CHECK(nn_bufPush(pB, NN_CFG_TX_HEADROOM) == NULL);  /* headroom short */
    CHECK_EQ(nn_bufHeadroom(pB), NN_CFG_TX_HEADROOM - 8);

    CHECK(nn_bufPull(pB, 200) == NULL);
    p = nn_bufPull(pB, 8);
    CHECK(p == pB->data + NN_CFG_TX_HEADROOM);
    CHECK_EQ(pB->len, 100);
    nn_bufTrim(pB, 40);
    CHECK_EQ(pB->len, 40);
    nn_bufTrim(pB, 50);
    CHECK_EQ(pB->len, 40);
    nn_bufFree(pB);
}

static void testPool(void)
{
    nn_buf_t *bufs[NN_CFG_NUM_BUFS];
    nn_bufStats_t st;
    unsigned i;

    nn_bufGetStats(&st);
    CHECK_EQ(st.free, NN_CFG_NUM_BUFS);
    for(i=0; i<NN_CFG_NUM_BUFS; ++i)
    {
        bufs[i] = nn_bufAlloc(0);
        CHECK(bufs[i] != NULL);
    }
    CHECK(nn_bufAlloc(0) == NULL);
    CHECK(nn_bufAllocFromIsr(0) == NULL);
    nn_bufGetStats(&st);
    CHECK_EQ(st.free, 0);
    CHECK_EQ(st.minFree, 0);
    CHECK_EQ(st.allocFailed, 2);
    for(i=0; i<NN_CFG_NUM_BUFS; ++i)
        nn_bufFree(bufs[i]);
    nn_bufGetStats(&st);
    CHECK_EQ(st.free, NN_CFG_NUM_BUFS);
}

static nn_buf_t *makeFrame(const uint8_t *dst, uint16_t type, uint16_t payloadLen)
{
    nn_buf_t *pB = nn_bufAlloc(NN_CFG_RX_OFFSET);
    nn_ethHdr_t *pH = (nn_ethHdr_t *)nn_bufPut(pB, (uint16_t)(NN_ETH_HDR_LEN + payloadLen));
    nn_macCopy(pH->dst, dst);
    nn_macCopy(pH->src, _other);
    nn_put16(pH->type, type);
    memset((uint8_t *)pH + NN_ETH_HDR_LEN, 0xA5, payloadLen);
    return pB;
}

static void testEthInput(nn_netdev_t *pDev)
{
    nn_proto_t proto;
    nn_buf_t *pB;
    nn_bufStats_t st;
    uint8_t *pPayload;

    memset(&proto, 0, sizeof(proto));
    proto.type = NN_ETH_TYPE_LOCAL;
    proto.name = "test";
    proto.input = protoInput;
    CHECK_EQ(nn_protoRegister(&proto), NN_OK);
    CHECK_EQ(nn_protoRegister(&proto), NN_ERR_EXIST);
    CHECK(nn_protoFind(NN_ETH_TYPE_LOCAL) == &proto);
    CHECK(nn_protoFind(NN_ETH_TYPE_IP) != NULL);            /* registered by nn_init */
    CHECK(nn_protoFind(0x1234) == NULL);

    /* Unicast to us: delivered, header stripped, zero copy. */
    pB = makeFrame(_mac, NN_ETH_TYPE_LOCAL, 50);
    pPayload = pB->pData + NN_ETH_HDR_LEN;
    pB->pDev = pDev;
    nn_net_input(pB);
    CHECK_EQ(_nGot, 1);
    CHECK(_pGot == pB  &&  _pGotDev == pDev);
    CHECK(_pGot->pData == pPayload);
    CHECK_EQ(_pGot->len, 50);
    CHECK_EQ(_pGot->flags, 0);

    /* Broadcast and multicast: delivered with flags. */
    pB = makeFrame(nn_eth_broadcast, NN_ETH_TYPE_LOCAL, 10);
    pB->pDev = pDev;
    nn_net_input(pB);
    CHECK_EQ(_nGot, 2);
    CHECK_EQ(_pGot->flags, NN_BUF_BCAST);
    {
        static const uint8_t mcast[6] = { 0x01, 0x00, 0x5E, 0x00, 0x00, 0x01 };
        pB = makeFrame(mcast, NN_ETH_TYPE_LOCAL, 10);
        pB->pDev = pDev;
        nn_net_input(pB);
        CHECK_EQ(_nGot, 3);
        CHECK_EQ(_pGot->flags, NN_BUF_MCAST);
    }

    /* For another station: dropped. Promiscuous: delivered. */
    pB = makeFrame(_other, NN_ETH_TYPE_LOCAL, 10);
    pB->pDev = pDev;
    nn_net_input(pB);
    CHECK_EQ(_nGot, 3);
    pDev->flags |= NN_DEVF_PROMISC;
    pB = makeFrame(_other, NN_ETH_TYPE_LOCAL, 10);
    pB->pDev = pDev;
    nn_net_input(pB);
    CHECK_EQ(_nGot, 4);
    pDev->flags &= (uint8_t)~NN_DEVF_PROMISC;

    /* Unknown type and a runt: dropped, no leak. */
    pB = makeFrame(_mac, 0x1234, 10);
    pB->pDev = pDev;
    nn_net_input(pB);
    pB = makeFrame(_mac, NN_ETH_TYPE_LOCAL, 0);
    nn_bufTrim(pB, 7);
    pB->pDev = pDev;
    nn_net_input(pB);
    CHECK_EQ(_nGot, 4);
    nn_bufGetStats(&st);
    CHECK_EQ(st.free, NN_CFG_NUM_BUFS);
    CHECK_EQ(nn_net_rxCount(), 7);
    CHECK_EQ(pDev->stats.rxFrames, 7);
    CHECK_EQ(proto.rxFrames, 4);
}

static void testEthOutput(nn_netdev_t *pDev)
{
    nn_buf_t *pB = nn_bufAlloc(NN_CFG_TX_HEADROOM);
    uint8_t *pPayload = nn_bufPut(pB, 3);
    const nn_ethHdr_t *pH;
    nn_netdev_t down, failing;

    pPayload[0] = 1; pPayload[1] = 2; pPayload[2] = 3;
    _pTx = NULL;
    CHECK_EQ(nn_eth_output(pDev, pB, _other, NN_ETH_TYPE_LOCAL), NN_OK);
    CHECK(_pTx == pB);
    CHECK_EQ(pB->len, NN_ETH_MIN_FRAME);                  /* padded */
    pH = (const nn_ethHdr_t *)pB->pData;
    CHECK(nn_macEqual(pH->dst, _other)  &&  nn_macEqual(pH->src, _mac));
    CHECK_EQ(nn_get16(pH->type), NN_ETH_TYPE_LOCAL);
    CHECK(pB->pData + NN_ETH_HDR_LEN == pPayload);        /* payload did not move */
    CHECK(pPayload[3] == 0  &&  pPayload[45] == 0);       /* padding zeroed */
    CHECK_EQ(pDev->stats.txFrames, 1);
    nn_bufFree(pB);

    /* Device down and transmit failure both free the buffer. */
    down = *pDev;
    down.flags = 0;
    pB = nn_bufAlloc(NN_CFG_TX_HEADROOM);
    CHECK_EQ(nn_eth_output(&down, pB, _other, NN_ETH_TYPE_LOCAL), NN_ERR_DOWN);
    failing = *pDev;
    failing.pOps = &_failOps;
    pB = nn_bufAlloc(NN_CFG_TX_HEADROOM);
    CHECK_EQ(nn_eth_output(&failing, pB, _other, NN_ETH_TYPE_LOCAL), NN_ERR_IO);
    CHECK_EQ(failing.stats.txErrors, 1);
    /* No headroom for the header. */
    pB = nn_bufAlloc(4);
    CHECK_EQ(nn_eth_output(pDev, pB, _other, NN_ETH_TYPE_LOCAL), NN_ERR_NOMEM);
    {
        nn_bufStats_t st;
        nn_bufGetStats(&st);
        CHECK_EQ(st.free, NN_CFG_NUM_BUFS);
    }
}

static unsigned _fired[3];
static void timerCb(nn_timer_t *pT, void *arg)
{
    (void)pT;
    ++ _fired[*(int *)arg];
}

static void testTimers(void)
{
    nn_timer_t t0, t1, t2;
    int i0 = 0, i1 = 1, i2 = 2;
    nn_ms_t next;

    nn_timerSetup(&t0, timerCb, &i0);
    nn_timerSetup(&t1, timerCb, &i1);
    nn_timerSetup(&t2, timerCb, &i2);
    CHECK(nn_timer_nextMs() <= 1000);                          /* ARP's timer */
    nn_timerStart(&t0, 300, 0);
    nn_timerStart(&t1, 100, 0);
    nn_timerStart(&t2, 200, 50);
    CHECK(nn_timerIsActive(&t1));
    next = nn_timer_nextMs();
    CHECK(next > 80  &&  next <= 100);
    nn_timerStop(&t1);
    CHECK(!nn_timerIsActive(&t1));
    next = nn_timer_nextMs();
    CHECK(next > 180  &&  next <= 200);
    nn_timer_run();
    CHECK(_fired[0] == 0  &&  _fired[2] == 0);
    /* Pretend time passed instead of sleeping. */
    nn_os_testAdvance(200);
    nn_timer_run();
    CHECK_EQ(_fired[2], 1);
    CHECK_EQ(_fired[0], 0);
    CHECK(nn_timerIsActive(&t2));              /* periodic re-armed */
    nn_os_testAdvance(100);
    nn_timer_run();
    CHECK_EQ(_fired[2], 3);
    CHECK_EQ(_fired[0], 1);
    CHECK(!nn_timerIsActive(&t0));
    nn_timerStop(&t2);
    CHECK(nn_timer_nextMs() <= 1000  &&  nn_timer_nextMs() > 200);  /* only ARP's left */
}

int main(void)
{
    nn_netdev_t dev;

    CHECK_EQ(nn_init(), NN_OK);
    memset(&dev, 0, sizeof(dev));
    dev.name = "fake";
    dev.type = NN_DEV_ETHERNET;
    dev.flags = NN_DEVF_LINK | NN_DEVF_BROADCAST;
    dev.hwlen = 6;
    nn_macCopy(dev.hwaddr, _mac);
    dev.mtu = 1500;
    dev.pOps = &_fakeOps;
    CHECK_EQ(nn_netdevRegister(&dev), NN_OK);
    CHECK_EQ(nn_netdevRegister(&dev), NN_ERR_EXIST);
    CHECK(nn_netdevFind("fake") == &dev);
    CHECK(nn_netdevFind("none") == NULL);

    nn_lock();
    testBufArithmetic();
    testPool();
    testEthInput(&dev);
    testEthOutput(&dev);
    testTimers();
    nn_unlock();
    test_finish("test_buf");
    return 0;
}
