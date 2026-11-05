/**
 * @file nn_drv_openeth.c
 * OpenCores 10/100 MAC (ethoc) driver for QEMU. Descriptors live in the device at
 * base + 0x400: 128 of them, the first TX_BD_NUM for transmit, the rest for receive.
 * Receive descriptors own a packet buffer each; the interrupt hands a filled buffer to
 * the stack and gives the descriptor a fresh one. Transmit descriptors hold the stack's
 * buffer until the completion interrupt frees it: zero copy both ways.
 *
 * QEMU details that matter (hw/net/opencores_eth.c): the received length includes a
 * zero filled 4 byte FCS; a frame is accepted when the destination matches MAC_ADDR,
 * is broadcast (unless BRO), or PRO is set; writing a descriptor with RD set transmits
 * at once and raises TXB if IRQ was set; RXEN resets the receive index to TX_BD_NUM.
 */

#include <string.h>

#include "nn_drv_openeth.h"
#include "nn_net.h"
#include "nn_eth.h"
#include "nn_os.h"
#include "rtos.h"

#define OE_BASE             0x3FF69000ul
#define OE_REG(off)         PORT_REG(OE_BASE + (off))
#define OE_MODER            OE_REG(0x00)
#define OE_INT_SOURCE       OE_REG(0x04)
#define OE_INT_MASK         OE_REG(0x08)
#define OE_PACKETLEN        OE_REG(0x18)
#define OE_TX_BD_NUM        OE_REG(0x20)
#define OE_MAC_ADDR0        OE_REG(0x40)
#define OE_MAC_ADDR1        OE_REG(0x44)
#define OE_DESC_FLAGS(i)    PORT_REG(OE_BASE + 0x400ul + 8ul * (i))
#define OE_DESC_PTR(i)      PORT_REG(OE_BASE + 0x404ul + 8ul * (i))

#define MODER_RXEN          0x0001ul
#define MODER_TXEN          0x0002ul
#define MODER_BRO           0x0008ul    /* reject broadcast */
#define MODER_PRO           0x0020ul
#define MODER_FULLD         0x0400ul
#define MODER_RST           0x0800ul
#define MODER_CRCEN         0x2000ul
#define MODER_PAD           0x8000ul

#define INT_TXB             0x01ul
#define INT_TXE             0x02ul
#define INT_RXB             0x04ul
#define INT_RXE             0x08ul
#define INT_BUSY            0x10ul

#define TXD_RD              0x8000ul
#define TXD_IRQ             0x4000ul
#define TXD_WR              0x2000ul
#define TXD_PAD             0x1000ul
#define TXD_CRC             0x0800ul
#define RXD_E               0x8000ul
#define RXD_IRQ             0x4000ul
#define RXD_WR              0x2000ul
#define RXD_ERRORS          0x01FFul    /* CF M OR IS DN TL SF CRC LC */

#define NUM_TX              4u
#define NUM_RX              8u
#define RX_FIRST            NUM_TX
#define MAX_FRAME           1536u

#define SRC_ETH_MAC         38u         /* ETS_ETH_MAC_INTR_SOURCE */
#define CPU_INT_ETH         9u          /* a free level 1 external interrupt */

static nn_netdev_t *_pDev;
static nn_buf_t *_rxBufs[NUM_RX];
static nn_buf_t *_txBufs[NUM_TX];
static uint8_t _rxHead, _txHead, _txTail;
static uint32_t _rxNoBuf, _rxErrors;

static void armRx(unsigned i, nn_buf_t *pB)
{
    _rxBufs[i] = pB;
    OE_DESC_PTR(RX_FIRST + i) = (uint32_t)(uintptr_t)pB->pData;
    OE_DESC_FLAGS(RX_FIRST + i) = RXD_E | RXD_IRQ | (i == NUM_RX - 1u ? RXD_WR : 0ul);
}

static void isr(void)
{
    const uint32_t src = OE_INT_SOURCE;
    OE_INT_SOURCE = src;

    if(src & (INT_RXB | INT_RXE | INT_BUSY))
    {
        unsigned n;
        for(n=0; n<NUM_RX; ++n)
        {
            const uint32_t flags = OE_DESC_FLAGS(RX_FIRST + _rxHead);
            nn_buf_t *pB, *pNew;
            uint32_t len;

            if(flags & RXD_E)
                break;
            pB = _rxBufs[_rxHead];
            len = flags >> 16;
            if(len >= 4u)
                len -= 4u;                          /* QEMU's zero filled FCS */
            pNew = nn_bufAllocFromIsr(NN_CFG_RX_OFFSET);
            if((flags & RXD_ERRORS)  ||  len > nn_bufTailroom(pB)  ||  len < NN_ETH_HDR_LEN)
            {
                ++ _rxErrors;
                if(pNew != NULL)
                    nn_bufFreeFromIsr(pNew);
                nn_bufReset(pB, NN_CFG_RX_OFFSET);
                armRx(_rxHead, pB);
            }
            else if(pNew == NULL)
            {
                ++ _rxNoBuf;                        /* keep the old buffer, drop the frame */
#if NN_CFG_STATS
                ++ _pDev->stats.rxDropped;
#endif
                nn_bufReset(pB, NN_CFG_RX_OFFSET);
                armRx(_rxHead, pB);
            }
            else
            {
                nn_bufPut(pB, (uint16_t)len);
                armRx(_rxHead, pNew);
                nn_net_rxFromIsr(_pDev, pB);
            }
            _rxHead = (uint8_t)((_rxHead + 1u) % NUM_RX);
        }
    }
    if(src & (INT_TXB | INT_TXE))
    {
        while(_txBufs[_txTail] != NULL  &&  !(OE_DESC_FLAGS(_txTail) & TXD_RD))
        {
            nn_bufFreeFromIsr(_txBufs[_txTail]);
            _txBufs[_txTail] = NULL;
            _txTail = (uint8_t)((_txTail + 1u) % NUM_TX);
        }
    }
}

static nn_err_t transmit(nn_netdev_t *pDev, nn_buf_t *pB)
{
    nn_os_cs_t s;
    unsigned i;
    (void)pDev;

    if(pB->len > MAX_FRAME)
        return NN_ERR_INVAL;
    s = nn_os_enterCritical();
    i = _txHead;
    if(_txBufs[i] != NULL)
    {
        nn_os_exitCritical(s);
        return NN_ERR_FULL;
    }
    _txBufs[i] = pB;
    _txHead = (uint8_t)((_txHead + 1u) % NUM_TX);
    OE_DESC_PTR(i) = (uint32_t)(uintptr_t)pB->pData;
    OE_DESC_FLAGS(i) = ((uint32_t)pB->len << 16) | TXD_RD | TXD_IRQ | TXD_PAD | TXD_CRC
                       | (i == NUM_TX - 1u ? TXD_WR : 0ul);
    nn_os_exitCritical(s);
    return NN_OK;
}

static nn_err_t open(nn_netdev_t *pDev)
{
    unsigned i;

    OE_MODER = 0;
    OE_INT_MASK = 0;
    OE_INT_SOURCE = 0xFFul;
    OE_TX_BD_NUM = NUM_TX;
    OE_PACKETLEN = (0x0040ul << 16) | MAX_FRAME;     /* MINFL 64 incl. FCS, MAXFL */
    OE_MAC_ADDR1 = ((uint32_t)pDev->hwaddr[0] << 8) | pDev->hwaddr[1];
    OE_MAC_ADDR0 = ((uint32_t)pDev->hwaddr[2] << 24) | ((uint32_t)pDev->hwaddr[3] << 16)
                   | ((uint32_t)pDev->hwaddr[4] << 8) | pDev->hwaddr[5];
    for(i=0; i<NUM_TX; ++i)
    {
        _txBufs[i] = NULL;
        OE_DESC_FLAGS(i) = 0;
    }
    for(i=0; i<NUM_RX; ++i)
    {
        nn_buf_t * const pB = nn_bufAlloc(NN_CFG_RX_OFFSET);
        if(pB == NULL)
            return NN_ERR_NOMEM;
        armRx(i, pB);
    }
    _rxHead = _txHead = _txTail = 0;
    rtos_port_attachInterrupt(CPU_INT_ETH, SRC_ETH_MAC, isr);
    OE_INT_MASK = INT_RXB | INT_RXE | INT_BUSY | INT_TXB | INT_TXE;
    OE_MODER = MODER_RXEN | MODER_TXEN | MODER_FULLD | MODER_CRCEN | MODER_PAD;
    pDev->flags |= NN_DEVF_LINK;
    return NN_OK;
}

static nn_err_t closeDev(nn_netdev_t *pDev)
{
    (void)pDev;
    OE_MODER = 0;
    OE_INT_MASK = 0;
    return NN_OK;
}

static const nn_netdevOps_t _ops = { open, closeDev, transmit };

nn_err_t nn_drv_openethRegister(nn_netdev_t *pDev, const uint8_t hwaddr[6])
{
    memset(pDev, 0, sizeof(*pDev));
    pDev->name = "eth0";
    pDev->type = NN_DEV_ETHERNET;
    pDev->flags = NN_DEVF_BROADCAST;
    pDev->hwlen = NN_ETH_ALEN;
    nn_macCopy(pDev->hwaddr, hwaddr);
    pDev->mtu = NN_ETH_MTU;
    pDev->pOps = &_ops;
    _pDev = pDev;
    return nn_netdevRegister(pDev);
}
