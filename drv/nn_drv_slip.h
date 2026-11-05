#ifndef NN_DRV_SLIP_INCLUDED
#define NN_DRV_SLIP_INCLUDED
/**
 * @file nn_drv_slip.h
 * SLIP (RFC 1055): IP packets on a serial line, framed with END (0xC0) and escaped with
 * ESC (0xDB). The driver is independent of the UART: it is given a write function and
 * is fed received bytes one at a time, from an interrupt handler
 * (nn_drv_slipRxByteFromIsr) or from a task that holds the stack lock (nn_drv_slipInput).
 * Every frame is sent as END, data, END. Bytes that arrive between frames are not SLIP
 * data; the peer side (tools/slip_bridge.py) treats them as console text, which lets a
 * board share its only UART between the link and its test output: nn_drv_slipPrint
 * writes such text without tearing a frame.
 */

#include "nn_netdev.h"
#include "nn_buf.h"

typedef void (*nn_slipWriteFunc_t)(const uint8_t *p, uint16_t n, void *arg);

typedef struct nn_slip
{
    nn_netdev_t *pDev;
    nn_slipWriteFunc_t write;
    void *arg;
    nn_buf_t *pRx;              /**< The frame being received, NULL between frames. */
    bool esc;                   /**< An ESC was the last byte. */
    bool dropping;              /**< Ignore the rest of this frame. */
    uint32_t rxFrames, rxDropped, rxOversize, rxBadEscape, txFrames;
} nn_slip_t;

/** Set up \a pDev as a SLIP device whose bytes go out through \a write, and register it.
    Give the device an address with nn_ifaceAdd; the peer's address is the gateway. */
nn_err_t nn_drv_slipRegister(nn_netdev_t *pDev, nn_slip_t *pS, nn_slipWriteFunc_t write, void *arg);

/** A received byte, from the UART interrupt handler. */
void nn_drv_slipRxByteFromIsr(nn_slip_t *pS, uint8_t c);

/** Received bytes, from a task holding the stack lock; complete frames are processed
    synchronously (nn_net_input). Tests and host glue. */
void nn_drv_slipInput(nn_slip_t *pS, const uint8_t *p, uint16_t n);

/** Write console text to the line between frames (takes the stack lock). */
void nn_drv_slipPrint(nn_slip_t *pS, const char *s);

#endif  /* NN_DRV_SLIP_INCLUDED */
