#ifndef NN_DRV_LOOP_INCLUDED
#define NN_DRV_LOOP_INCLUDED
/**
 * @file nn_drv_loop.h
 * Loopback device: a transmitted frame is queued straight back as received. Ethernet
 * framed with an all-zero address, no ARP.
 */

#include "nn_netdev.h"

/** Fill in \a pDev as the loopback device and register it. */
nn_err_t nn_drv_loopRegister(nn_netdev_t *pDev);

#endif  /* NN_DRV_LOOP_INCLUDED */
