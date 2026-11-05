/**
 * @file nn_eth.c
 * Ethernet II. Frames for other stations are dropped unless the device is promiscuous;
 * broadcast and multicast are flagged in the buffer for the upper layers.
 */

#include <string.h>

#include "nn_eth.h"
#include "nn_net.h"

const uint8_t nn_eth_broadcast[NN_ETH_ALEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static uint32_t _unknownType, _notForUs, _tooShort;

void nn_eth_init(void)
{
    _unknownType = _notForUs = _tooShort = 0;
}

void nn_eth_input(nn_buf_t *pB, nn_netdev_t *pDev)
{
    const nn_ethHdr_t *pH;
    nn_proto_t *pP;
    uint16_t type;

    if(pB->len < NN_ETH_HDR_LEN)
    {
        ++ _tooShort;
        nn_bufFree(pB);
        return;
    }
    pH = (const nn_ethHdr_t *)pB->pData;

    if(pH->dst[0] & 0x01u)
        pB->flags |= nn_macIsBroadcast(pH->dst) ? NN_BUF_BCAST : NN_BUF_MCAST;
    else if(pDev->hwlen == NN_ETH_ALEN  &&  !(pDev->flags & NN_DEVF_PROMISC)
            &&  !nn_macEqual(pH->dst, pDev->hwaddr))
    {
        ++ _notForUs;
        nn_bufFree(pB);
        return;
    }

    type = nn_get16(pH->type);
    pP = nn_protoFind(type);
    if(pP == NULL)
    {
        ++ _unknownType;
        nn_bufFree(pB);
        return;
    }
    nn_bufPull(pB, NN_ETH_HDR_LEN);
#if NN_CFG_STATS
    ++ pP->rxFrames;
#endif
    pP->input(pB, pDev);
}

nn_err_t nn_eth_output(nn_netdev_t *pDev, nn_buf_t *pB, const uint8_t *dst, uint16_t type)
{
    nn_ethHdr_t *pH;

    if(pB->len + NN_ETH_HDR_LEN < NN_ETH_MIN_FRAME)
    {
        const uint16_t pad = (uint16_t)(NN_ETH_MIN_FRAME - NN_ETH_HDR_LEN - pB->len);
        uint8_t * const p = nn_bufPut(pB, pad);
        if(p != NULL)
            memset(p, 0, pad);
    }
    pH = (nn_ethHdr_t *)nn_bufPush(pB, NN_ETH_HDR_LEN);
    if(pH == NULL)
    {
        nn_bufFree(pB);
        return NN_ERR_NOMEM;
    }
    nn_macCopy(pH->dst, dst);
    nn_macCopy(pH->src, pDev->hwaddr);
    nn_put16(pH->type, type);
    return nn_netdevTransmit(pDev, pB);
}
