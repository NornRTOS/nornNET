#ifndef NN_NETDEV_INCLUDED
#define NN_NETDEV_INCLUDED
/**
 * @file nn_netdev.h
 * A network device: what a driver gives the stack. The driver fills in the constant
 * fields and the ops, registers the device with nn_netdevRegister, and from then on
 * delivers received frames with nn_net_rx / nn_net_rxFromIsr and transmits what the
 * stack hands to its transmit op.
 */

#include "nn_types.h"
#include "nn_cfg.h"
#include "nn_buf.h"

struct nn_netdev;

typedef struct nn_netdevOps
{
    /** Bring the hardware up; NULL if nothing to do. */
    nn_err_t (*open)(struct nn_netdev *pDev);
    nn_err_t (*close)(struct nn_netdev *pDev);
    /** Send one frame. On NN_OK the driver owns the buffer and frees it when the data
        has left (at once or from a completion interrupt). On an error the caller keeps
        the buffer. Called with the stack lock held, from the net task or an application
        task. */
    nn_err_t (*transmit)(struct nn_netdev *pDev, nn_buf_t *pB);
} nn_netdevOps_t;

#define NN_DEV_LOOPBACK     1u  /**< Ethernet framed, frames come straight back. */
#define NN_DEV_ETHERNET     2u
#define NN_DEV_SLIP         3u  /**< IP packets on a serial line, no link header, no ARP. */

#define NN_DEVF_UP          0x01u
#define NN_DEVF_LINK        0x02u /**< Carrier; the driver reports it with nn_netdevLinkChanged. */
#define NN_DEVF_BROADCAST   0x04u
#define NN_DEVF_NOARP       0x08u /**< Point to point or loopback. */
#define NN_DEVF_PROMISC     0x10u /**< Accept frames for other hardware addresses. */

/** The driver's carrier went up or down: sets or clears NN_DEVF_LINK and has the net
    task act on it (down: the device's ARP entries and parked frames are dropped; up:
    every DHCP client on the device confirms its lease, nn_dhcpLinkUp). From any task;
    the FromIsr form from an interrupt. */
void nn_netdevLinkChanged(struct nn_netdev *pDev, bool up);
void nn_netdevLinkChangedFromIsr(struct nn_netdev *pDev, bool up);

typedef struct nn_devStats
{
    uint32_t rxFrames, rxBytes, rxDropped;
    uint32_t txFrames, txBytes, txErrors;
} nn_devStats_t;

typedef struct nn_netdev
{
    const char *name;
    uint8_t type;               /**< NN_DEV_* */
    uint8_t flags;              /**< NN_DEVF_* */
    uint8_t hwlen;              /**< Hardware address length, 6 for Ethernet, 0 for loopback. */
    uint8_t hwaddr[NN_CFG_HWADDR_LEN];
    uint16_t mtu;               /**< Payload above the link layer. */
    const nn_netdevOps_t *pOps;
    void *pPriv;                /**< Driver state. */
    struct nn_netdev *pNext;    /**< Registry list. */
    struct nn_iface *pIfaces;   /**< Interfaces (addresses) on this device; from v0.2. */
#if NN_CFG_STATS
    nn_devStats_t stats;
#endif
} nn_netdev_t;

#endif  /* NN_NETDEV_INCLUDED */
