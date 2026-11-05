/**
 * @file nn_buf.c
 * The packet buffer pool: NN_CFG_NUM_BUFS blocks of sizeof(nn_buf_t) from the OS pool.
 */

#include "nn_buf.h"
#include "nn_os.h"

static nn_buf_t _storage[NN_CFG_NUM_BUFS];
static nn_os_pool_t _pool;
static uint8_t _minFree;
static uint16_t _allocFailed;

void nn_buf_init(void)
{
    nn_os_poolInit(&_pool, _storage, (uint16_t)sizeof(nn_buf_t), NN_CFG_NUM_BUFS);
    _minFree = NN_CFG_NUM_BUFS;
    _allocFailed = 0;
}

static nn_buf_t *prepare(nn_buf_t *pB, uint16_t headroom)
{
    uint8_t free;

    if(pB == NULL)
    {
        if(_allocFailed != 0xFFFFu)
            ++ _allocFailed;
        return NULL;
    }
    free = nn_os_poolFreeCount(&_pool);
    if(free < _minFree)
        _minFree = free;
    pB->pNext = NULL;
    pB->pDev = NULL;
    pB->aux = 0;
    nn_bufReset(pB, headroom);
    return pB;
}

nn_buf_t *nn_bufAlloc(uint16_t headroom)
{
    nn_buf_t *pB;
    const nn_os_cs_t s = nn_os_enterCritical();
    pB = prepare(nn_os_poolAlloc(&_pool), headroom);
    nn_os_exitCritical(s);
    return pB;
}

nn_buf_t *nn_bufAllocFromIsr(uint16_t headroom)
{
    return prepare(nn_os_poolAllocFromIsr(&_pool), headroom);
}

void nn_bufFree(nn_buf_t *pB)
{
    if(pB != NULL)
        nn_os_poolFree(&_pool, pB);
}

void nn_bufFreeFromIsr(nn_buf_t *pB)
{
    if(pB != NULL)
        nn_os_poolFreeFromIsr(&_pool, pB);
}

void nn_bufGetStats(nn_bufStats_t *pStats)
{
    const nn_os_cs_t s = nn_os_enterCritical();
    pStats->numBufs = NN_CFG_NUM_BUFS;
    pStats->free = nn_os_poolFreeCount(&_pool);
    pStats->minFree = _minFree;
    pStats->allocFailed = _allocFailed;
    nn_os_exitCritical(s);
}
