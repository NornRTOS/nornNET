#ifndef NN_DRV_TAP_INCLUDED
#define NN_DRV_TAP_INCLUDED
/**
 * @file nn_drv_tap.h
 * Linux TAP device driver for the host builds: the stack sees an Ethernet device whose
 * peer is the Linux kernel. Creating the interface needs root once, see
 * tools/tap_setup.sh; opening an existing one owned by the user does not.
 */

#include "nn_netdev.h"

/** Open TAP interface \a ifName (persistent, owned by this user) and register the device
    with hardware address \a hwaddr. Returns NN_ERR_NODEV when the interface cannot be
    opened. */
nn_err_t nn_drv_tapRegister(nn_netdev_t *pDev, const char *ifName, const uint8_t hwaddr[6]);

/** File descriptor, for the host's poll loop. -1 if not open. */
int nn_drv_tapFd(const nn_netdev_t *pDev);

/** Read one frame if available and queue it as received. Called from the host's
    "interrupt" (rtos_host_simulateIsr) when the descriptor is readable. */
void nn_drv_tapPollIsr(nn_netdev_t *pDev);

#endif  /* NN_DRV_TAP_INCLUDED */
