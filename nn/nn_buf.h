#ifndef NN_BUF_INCLUDED
#define NN_BUF_INCLUDED
/**
 * @file nn_buf.h
 * Packet buffers. One frame lives in one fixed size block from a pool; the data pointer
 * moves inside the block as headers are pushed (prepended) on the way down and pulled
 * (stripped) on the way up, so no layer ever copies the payload.
 *
 *   data[]: | headroom | pData ....... len ....... | tailroom |
 *
 * Ownership is explicit: whoever holds the pointer frees it, and a function that is
 * documented to "take" a buffer frees it on every path, including errors.
 */

#include "nn_types.h"
#include "nn_cfg.h"

struct nn_netdev;

typedef struct nn_buf
{
    struct nn_buf *pNext;       /**< Chaining in protocol queues (ARP pending, TCP). */
    struct nn_netdev *pDev;     /**< Device the frame arrived on or leaves through. */
    uint8_t *pData;             /**< Current start of data inside data[]. */
    uint16_t len;               /**< Bytes from pData. */
    uint16_t flags;             /**< NN_BUF_* */
    uint32_t aux;               /**< Free for the owning protocol (time stamp, type). */
    uint8_t data[NN_CFG_BUF_DATA];
} nn_buf_t;

#define NN_BUF_BCAST    0x0001u /**< Received with the broadcast destination address. */
#define NN_BUF_MCAST    0x0002u /**< Received with a multicast destination address. */

typedef struct nn_bufStats
{
    uint8_t  numBufs;
    uint8_t  free;
    uint8_t  minFree;           /**< Low water mark of free. */
    uint16_t allocFailed;
} nn_bufStats_t;

/** Create the pool. Called by nn_init. */
void nn_buf_init(void);

/** Allocate a buffer with \a headroom bytes reserved before pData and len 0; NULL when
    the pool is empty (counted). */
nn_buf_t *nn_bufAlloc(uint16_t headroom);
nn_buf_t *nn_bufAllocFromIsr(uint16_t headroom);
void nn_bufFree(nn_buf_t *pB);
void nn_bufFreeFromIsr(nn_buf_t *pB);

void nn_bufGetStats(nn_bufStats_t *pStats);

/** Reset to empty with \a headroom reserved. */
static inline void nn_bufReset(nn_buf_t *pB, uint16_t headroom)
{
    pB->pData = pB->data + headroom;
    pB->len = 0;
    pB->flags = 0;
}

static inline uint16_t nn_bufHeadroom(const nn_buf_t *pB)
{
    return (uint16_t)(pB->pData - pB->data);
}

static inline uint16_t nn_bufTailroom(const nn_buf_t *pB)
{
    return (uint16_t)(NN_CFG_BUF_DATA - nn_bufHeadroom(pB) - pB->len);
}

/** Prepend \a n bytes (a header); returns its start or NULL if the headroom is short. */
static inline uint8_t *nn_bufPush(nn_buf_t *pB, uint16_t n)
{
    if(nn_bufHeadroom(pB) < n)
        return NULL;
    pB->pData -= n;
    pB->len = (uint16_t)(pB->len + n);
    return pB->pData;
}

/** Strip \a n bytes from the front; returns the new start or NULL if len is short. */
static inline uint8_t *nn_bufPull(nn_buf_t *pB, uint16_t n)
{
    if(pB->len < n)
        return NULL;
    pB->pData += n;
    pB->len = (uint16_t)(pB->len - n);
    return pB->pData;
}

/** Append room for \a n bytes at the end; returns where to write them or NULL. */
static inline uint8_t *nn_bufPut(nn_buf_t *pB, uint16_t n)
{
    uint8_t * const pTail = pB->pData + pB->len;
    if(nn_bufTailroom(pB) < n)
        return NULL;
    pB->len = (uint16_t)(pB->len + n);
    return pTail;
}

/** Shorten to \a len bytes (drop padding at the end). */
static inline void nn_bufTrim(nn_buf_t *pB, uint16_t len)
{
    if(len < pB->len)
        pB->len = len;
}

#endif  /* NN_BUF_INCLUDED */
