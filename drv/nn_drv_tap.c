/**
 * @file nn_drv_tap.c
 * Linux TAP driver. Transmit writes the frame to the descriptor and frees the buffer at
 * once. Receive is pull based: the host glue polls the descriptor and calls
 * nn_drv_tapPollIsr, which plays the part of a receive interrupt.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>

#include "nn_drv_tap.h"
#include "nn_net.h"
#include "nn_eth.h"

typedef struct tap { int fd; } tap_t;

static tap_t _tap = { -1 };

static nn_err_t transmit(nn_netdev_t *pDev, nn_buf_t *pB)
{
    tap_t * const pT = pDev->pPriv;
    const ssize_t n = write(pT->fd, pB->pData, pB->len);
    const nn_err_t rc = (n == (ssize_t)pB->len) ? NN_OK : NN_ERR_IO;
    if(rc == NN_OK)
        nn_bufFree(pB);
    return rc;
}

static nn_err_t closeDev(nn_netdev_t *pDev)
{
    tap_t * const pT = pDev->pPriv;
    if(pT->fd >= 0)
        close(pT->fd);
    pT->fd = -1;
    return NN_OK;
}

static const nn_netdevOps_t _ops = { NULL, closeDev, transmit };

nn_err_t nn_drv_tapRegister(nn_netdev_t *pDev, const char *ifName, const uint8_t hwaddr[6])
{
    struct ifreq ifr;
    int fd;

    fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if(fd < 0)
        return NN_ERR_NODEV;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, ifName, IFNAMSIZ - 1);
    if(ioctl(fd, TUNSETIFF, &ifr) < 0)
    {
        close(fd);
        return NN_ERR_NODEV;
    }
    _tap.fd = fd;

    memset(pDev, 0, sizeof(*pDev));
    pDev->name = "tap";
    pDev->type = NN_DEV_ETHERNET;
    pDev->flags = NN_DEVF_LINK | NN_DEVF_BROADCAST;
    pDev->hwlen = NN_ETH_ALEN;
    nn_macCopy(pDev->hwaddr, hwaddr);
    pDev->mtu = NN_ETH_MTU;
    pDev->pOps = &_ops;
    pDev->pPriv = &_tap;
    return nn_netdevRegister(pDev);
}

int nn_drv_tapFd(const nn_netdev_t *pDev)
{
    const tap_t * const pT = pDev->pPriv;
    return pT != NULL ? pT->fd : -1;
}

void nn_drv_tapPollIsr(nn_netdev_t *pDev)
{
    tap_t * const pT = pDev->pPriv;

    for(;;)
    {
        nn_buf_t *pB;
        ssize_t n;

        pB = nn_bufAllocFromIsr(NN_CFG_RX_OFFSET);
        if(pB == NULL)
        {
            /* No buffer: leave the frame in the kernel queue, retry on the next poll. */
#if NN_CFG_STATS
            ++ pDev->stats.rxDropped;
#endif
            return;
        }
        n = read(pT->fd, pB->pData, nn_bufTailroom(pB));
        if(n <= 0)
        {
            nn_bufFreeFromIsr(pB);
            return;
        }
        nn_bufPut(pB, (uint16_t)n);
        nn_net_rxFromIsr(pDev, pB);
    }
}
