#ifndef NN_DRV_OPENETH_INCLUDED
#define NN_DRV_OPENETH_INCLUDED
/**
 * @file nn_drv_openeth.h
 * OpenCores Ethernet MAC as emulated by Espressif's QEMU for the ESP32 (-nic
 * user,model=open_eth). It sits at the real chip's EMAC register base and interrupt
 * source, so this driver only works in the emulator; on the real chip those registers
 * belong to a different MAC that needs a PHY. QEMU only.
 */

#include "nn_netdev.h"

/** Register the device with hardware address \a hwaddr (locally administered). */
nn_err_t nn_drv_openethRegister(nn_netdev_t *pDev, const uint8_t hwaddr[6]);

#endif  /* NN_DRV_OPENETH_INCLUDED */
