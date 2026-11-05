/**
 * @file nn_drv_loop.c
 * Loopback: the frame changes direction, nothing else. Also the first exercise of the
 * whole path, which is why the net core treats it like Ethernet.
 */

#include <string.h>

#include "nn_drv_loop.h"
#include "nn_net.h"

static nn_err_t transmit(nn_netdev_t *pDev, nn_buf_t *pB)
{
    nn_net_rx(pDev, pB);
    return NN_OK;
}

static const nn_netdevOps_t _ops = { NULL, NULL, transmit };

nn_err_t nn_drv_loopRegister(nn_netdev_t *pDev)
{
    memset(pDev, 0, sizeof(*pDev));
    pDev->name = "lo";
    pDev->type = NN_DEV_LOOPBACK;
    pDev->flags = NN_DEVF_LINK | NN_DEVF_NOARP;
    pDev->hwlen = 0;
    pDev->mtu = 1500u;
    pDev->pOps = &_ops;
    return nn_netdevRegister(pDev);
}
