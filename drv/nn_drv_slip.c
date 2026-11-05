/**
 * @file nn_drv_slip.c
 * SLIP framing over any byte stream. See nn_drv_slip.h.
 */

#include <string.h>

#include "nn_drv_slip.h"
#include "nn_net.h"
#include "nn_eth.h"

#define END         0xC0u
#define ESC         0xDBu
#define ESC_END     0xDCu
#define ESC_ESC     0xDDu

/** Headroom of a received packet: as if an Ethernet header preceded it, so the IP
    header lands on the same 4 byte boundary as on Ethernet devices. */
#define RX_HEADROOM (NN_CFG_RX_OFFSET + NN_ETH_HDR_LEN)

static nn_err_t transmit(nn_netdev_t *pDev, nn_buf_t *pB)
{
    nn_slip_t * const pS = pDev->pPriv;
    const uint8_t *p = pB->pData;
    uint8_t out[128];
    uint16_t n = 0, i;

    out[n++] = END;
    for(i=0; i<pB->len; ++i)
    {
        const uint8_t c = p[i];
        if(c == END)
        {
            out[n++] = ESC;
            out[n++] = ESC_END;
        }
        else if(c == ESC)
        {
            out[n++] = ESC;
            out[n++] = ESC_ESC;
        }
        else
            out[n++] = c;
        if(n >= sizeof(out) - 2u)
        {
            pS->write(out, n, pS->arg);
            n = 0;
        }
    }
    out[n++] = END;
    pS->write(out, n, pS->arg);
    ++ pS->txFrames;
    nn_bufFree(pB);
    return NN_OK;
}

static const nn_netdevOps_t _ops = { NULL, NULL, transmit };

nn_err_t nn_drv_slipRegister(nn_netdev_t *pDev, nn_slip_t *pS, nn_slipWriteFunc_t write, void *arg)
{
    if(pDev == NULL  ||  pS == NULL  ||  write == NULL)
        return NN_ERR_INVAL;
    memset(pS, 0, sizeof(*pS));
    pS->pDev = pDev;
    pS->write = write;
    pS->arg = arg;
    memset(pDev, 0, sizeof(*pDev));
    pDev->name = "sl0";
    pDev->type = NN_DEV_SLIP;
    pDev->flags = NN_DEVF_LINK | NN_DEVF_NOARP;
    pDev->hwlen = 0;
    pDev->mtu = 1500;
    pDev->pOps = &_ops;
    pDev->pPriv = pS;
    return nn_netdevRegister(pDev);
}

/** The decoder. \a ctx: 0 task with the lock (synchronous input), 1 interrupt. */
static void rxByte(nn_slip_t *pS, uint8_t c, int ctx)
{
    uint8_t *pOut;

    if(c == END)
    {
        if(pS->pRx != NULL)
        {
            nn_buf_t * const pB = pS->pRx;
            pS->pRx = NULL;
            if(pB->len == 0)
                (ctx ? nn_bufFreeFromIsr : nn_bufFree)(pB);
            else
            {
                ++ pS->rxFrames;
                if(ctx)
                    nn_net_rxFromIsr(pS->pDev, pB);
                else
                {
                    pB->pDev = pS->pDev;
                    nn_net_input(pB);
                }
            }
        }
        pS->esc = false;
        pS->dropping = false;
        return;
    }
    if(pS->dropping)
        return;
    if(pS->esc)
    {
        pS->esc = false;
        if(c == ESC_END)
            c = END;
        else if(c == ESC_ESC)
            c = ESC;
        else
            ++ pS->rxBadEscape;                         /* RFC 1055: keep the byte */
    }
    else if(c == ESC)
    {
        pS->esc = true;
        return;
    }
    if(pS->pRx == NULL)
    {
        pS->pRx = ctx ? nn_bufAllocFromIsr(RX_HEADROOM) : nn_bufAlloc(RX_HEADROOM);
        if(pS->pRx == NULL)
        {
            ++ pS->rxDropped;
            pS->dropping = true;
            return;
        }
    }
    pOut = nn_bufPut(pS->pRx, 1);
    if(pOut == NULL)
    {
        ++ pS->rxOversize;
        (ctx ? nn_bufFreeFromIsr : nn_bufFree)(pS->pRx);
        pS->pRx = NULL;
        pS->dropping = true;
        return;
    }
    *pOut = c;
}

void nn_drv_slipRxByteFromIsr(nn_slip_t *pS, uint8_t c)
{
    rxByte(pS, c, 1);
}

void nn_drv_slipInput(nn_slip_t *pS, const uint8_t *p, uint16_t n)
{
    uint16_t i;
    for(i=0; i<n; ++i)
        rxByte(pS, p[i], 0);
}

void nn_drv_slipPrint(nn_slip_t *pS, const char *s)
{
    nn_lock();
    pS->write((const uint8_t *)s, (uint16_t)strlen(s), pS->arg);
    nn_unlock();
}
