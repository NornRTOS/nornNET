#ifndef NN_ETH_INCLUDED
#define NN_ETH_INCLUDED
/**
 * @file nn_eth.h
 * Ethernet II framing: parse and filter on input, prepend the header on output, and
 * dispatch by type to the registered protocol.
 */

#include "nn_types.h"
#include "nn_buf.h"
#include "nn_netdev.h"

#define NN_ETH_HDR_LEN      14u
#define NN_ETH_MIN_FRAME    60u     /**< Without FCS; shorter frames are padded on output. */
#define NN_ETH_MTU          1500u

#define NN_ETH_TYPE_IP      0x0800u
#define NN_ETH_TYPE_ARP     0x0806u
#define NN_ETH_TYPE_IPV6    0x86DDu
#define NN_ETH_TYPE_LOCAL   0x88B5u /**< IEEE 802 local experimental; used by the tests. */

/** The header as bytes: no alignment requirement, no padding. */
typedef struct nn_ethHdr
{
    uint8_t dst[NN_ETH_ALEN];
    uint8_t src[NN_ETH_ALEN];
    uint8_t type[2];
} nn_ethHdr_t;

extern const uint8_t nn_eth_broadcast[NN_ETH_ALEN];

void nn_eth_init(void);

/** Input from a device: filter on destination, strip the header, dispatch. Takes the
    buffer. */
void nn_eth_input(nn_buf_t *pB, nn_netdev_t *pDev);

/** Output: prepend the header with the device's address as source, pad to the minimum
    frame size and transmit. Takes the buffer. */
nn_err_t nn_eth_output(nn_netdev_t *pDev, nn_buf_t *pB, const uint8_t *dst, uint16_t type);

#endif  /* NN_ETH_INCLUDED */
