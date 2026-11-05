/**
 * @file nn_os_posix.c
 * nornNET on a POSIX host without nornOS: pthreads, mutexes and condition variables.
 * Used by the pure unit tests and by fuzzing harnesses. "Interrupt" variants are the
 * same as the task variants, because there are no interrupts here.
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>

#include "nn_os.h"

typedef struct nn_os_posixTask
{
    pthread_mutex_t m;
    pthread_cond_t  cv;
    int pending;
} task_t;

static pthread_key_t _selfKey;
static pthread_once_t _once = PTHREAD_ONCE_INIT;
static pthread_mutex_t _critical = PTHREAD_MUTEX_INITIALIZER;
static int _criticalDepth = 0;

static void initKey(void)
{
    pthread_key_create(&_selfKey, NULL);
}

static void deadline(struct timespec *pTs, nn_ms_t ms)
{
    clock_gettime(CLOCK_REALTIME, pTs);
    pTs->tv_sec += (time_t)(ms / 1000u);
    pTs->tv_nsec += (long)(ms % 1000u) * 1000000L;
    if(pTs->tv_nsec >= 1000000000L)
    {
        pTs->tv_nsec -= 1000000000L;
        ++ pTs->tv_sec;
    }
}

static nn_ms_t _offset;
static bool _frozen;

nn_ms_t nn_os_now(void)
{
    struct timespec ts;
    if(_frozen)
        return _offset;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (nn_ms_t)((uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u) + _offset;
}

void nn_os_testFreeze(bool frozen)
{
    _frozen = frozen;
}

void nn_os_testAdvance(uint32_t ms)
{
    _offset += ms;
}

/* --- Task and notifications ---------------------------------------------------------- */

typedef struct { void (*fn)(void *); void *arg; } start_t;

static void *trampoline(void *p)
{
    start_t s = *(start_t *)p;
    free(p);
    s.fn(s.arg);
    return NULL;
}

void nn_os_taskCreate(void (*fn)(void *arg), void *arg)
{
    pthread_t th;
    start_t *pS = malloc(sizeof(*pS));
    pS->fn = fn;
    pS->arg = arg;
    if(pthread_create(&th, NULL, trampoline, pS) != 0)
        nn_os_panic("pthread_create");
    pthread_detach(th);
}

nn_os_taskId_t nn_os_self(void)
{
    task_t *pT;

    pthread_once(&_once, initKey);
    pT = pthread_getspecific(_selfKey);
    if(pT == NULL)
    {
        pT = calloc(1, sizeof(*pT));
        pthread_mutex_init(&pT->m, NULL);
        pthread_cond_init(&pT->cv, NULL);
        pthread_setspecific(_selfKey, pT);
    }
    return pT;
}

void nn_os_notify(nn_os_taskId_t task)
{
    pthread_mutex_lock(&task->m);
    task->pending = 1;
    pthread_cond_signal(&task->cv);
    pthread_mutex_unlock(&task->m);
}

void nn_os_notifyFromIsr(nn_os_taskId_t task)
{
    nn_os_notify(task);
}

bool nn_os_notifyWait(nn_ms_t ms)
{
    task_t * const pT = nn_os_self();
    struct timespec ts;
    int rc = 0;

    if(ms != NN_FOREVER)
        deadline(&ts, ms);
    pthread_mutex_lock(&pT->m);
    while(!pT->pending  &&  rc == 0)
        rc = ms == NN_FOREVER ? pthread_cond_wait(&pT->cv, &pT->m)
                              : pthread_cond_timedwait(&pT->cv, &pT->m, &ts);
    {
        const bool got = pT->pending != 0;
        pT->pending = 0;
        pthread_mutex_unlock(&pT->m);
        return got;
    }
}

/* --- Lock ------------------------------------------------------------------------------ */

void nn_os_lockInit(nn_os_lock_t *pLock)
{
    /* Recursive, so a test may hold the stack lock around public API calls that take
       it themselves. nornOS's mutex is not recursive (it asserts): a double lock in
       stack code shows up in test_net (nornOS host port) and on the target, not here. */
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&pLock->m, &attr);
    pthread_mutexattr_destroy(&attr);
}

void nn_os_lock(nn_os_lock_t *pLock)
{
    pthread_mutex_lock(&pLock->m);
}

void nn_os_unlock(nn_os_lock_t *pLock)
{
    pthread_mutex_unlock(&pLock->m);
}

/* --- Queue ---------------------------------------------------------------------------- */

void nn_os_queueInit(nn_os_queue_t *pQ, void **storage, uint8_t capacity)
{
    pthread_mutex_init(&pQ->m, NULL);
    pthread_cond_init(&pQ->cv, NULL);
    pQ->storage = storage;
    pQ->capacity = capacity;
    pQ->count = pQ->head = pQ->tail = 0;
}

bool nn_os_queuePut(nn_os_queue_t *pQ, void *p)
{
    bool ok = false;

    pthread_mutex_lock(&pQ->m);
    if(pQ->count < pQ->capacity)
    {
        pQ->storage[pQ->tail] = p;
        pQ->tail = (uint8_t)((pQ->tail + 1u) % pQ->capacity);
        ++ pQ->count;
        pthread_cond_signal(&pQ->cv);
        ok = true;
    }
    pthread_mutex_unlock(&pQ->m);
    return ok;
}

bool nn_os_queuePutFromIsr(nn_os_queue_t *pQ, void *p)
{
    return nn_os_queuePut(pQ, p);
}

bool nn_os_queueGet(nn_os_queue_t *pQ, void **pp, nn_ms_t ms)
{
    struct timespec ts;
    int rc = 0;
    bool ok = false;

    if(ms != NN_FOREVER)
        deadline(&ts, ms);
    pthread_mutex_lock(&pQ->m);
    while(pQ->count == 0  &&  rc == 0)
    {
        if(ms == 0)
            break;
        rc = ms == NN_FOREVER ? pthread_cond_wait(&pQ->cv, &pQ->m)
                              : pthread_cond_timedwait(&pQ->cv, &pQ->m, &ts);
    }
    if(pQ->count > 0)
    {
        *pp = pQ->storage[pQ->head];
        pQ->head = (uint8_t)((pQ->head + 1u) % pQ->capacity);
        -- pQ->count;
        ok = true;
    }
    pthread_mutex_unlock(&pQ->m);
    return ok;
}

/* --- Pool ------------------------------------------------------------------------------ */

void nn_os_poolInit(nn_os_pool_t *pPool, void *storage, uint16_t blockSize, uint8_t numBlocks)
{
    uint8_t *p = storage;
    uint8_t i;

    pthread_mutex_init(&pPool->m, NULL);
    pPool->pFree = NULL;
    pPool->numFree = numBlocks;
    /* Build the free list so that the first block is handed out first. */
    for(i=numBlocks; i>0; --i)
    {
        uint8_t * const pBlock = p + (size_t)(i - 1u) * blockSize;
        memcpy(pBlock, &pPool->pFree, sizeof(void *));
        pPool->pFree = pBlock;
    }
}

void *nn_os_poolAlloc(nn_os_pool_t *pPool)
{
    void *p;

    pthread_mutex_lock(&pPool->m);
    p = pPool->pFree;
    if(p != NULL)
    {
        memcpy(&pPool->pFree, p, sizeof(void *));
        -- pPool->numFree;
    }
    pthread_mutex_unlock(&pPool->m);
    return p;
}

void *nn_os_poolAllocFromIsr(nn_os_pool_t *pPool)
{
    return nn_os_poolAlloc(pPool);
}

void nn_os_poolFree(nn_os_pool_t *pPool, void *p)
{
    pthread_mutex_lock(&pPool->m);
    memcpy(p, &pPool->pFree, sizeof(void *));
    pPool->pFree = p;
    ++ pPool->numFree;
    pthread_mutex_unlock(&pPool->m);
}

void nn_os_poolFreeFromIsr(nn_os_pool_t *pPool, void *p)
{
    nn_os_poolFree(pPool, p);
}

uint8_t nn_os_poolFreeCount(const nn_os_pool_t *pPool)
{
    return pPool->numFree;
}

/* --- Critical sections (a recursive global lock) ------------------------------------- */

static pthread_mutex_t _criticalGuard = PTHREAD_MUTEX_INITIALIZER;
static pthread_t _criticalOwner;

nn_os_cs_t nn_os_enterCritical(void)
{
    int depth;

    pthread_mutex_lock(&_criticalGuard);
    if(_criticalDepth > 0  &&  pthread_equal(_criticalOwner, pthread_self()))
    {
        depth = _criticalDepth ++;
        pthread_mutex_unlock(&_criticalGuard);
        return depth;
    }
    pthread_mutex_unlock(&_criticalGuard);

    pthread_mutex_lock(&_critical);
    pthread_mutex_lock(&_criticalGuard);
    _criticalOwner = pthread_self();
    depth = _criticalDepth ++;
    pthread_mutex_unlock(&_criticalGuard);
    return depth;
}

void nn_os_exitCritical(nn_os_cs_t s)
{
    pthread_mutex_lock(&_criticalGuard);
    _criticalDepth = s;
    pthread_mutex_unlock(&_criticalGuard);
    if(s == 0)
        pthread_mutex_unlock(&_critical);
}

/* --- Diagnostics ---------------------------------------------------------------------- */

void nn_os_panic(const char *what)
{
    fprintf(stderr, "nornNET panic: %s\n", what);
    abort();
}

void nn_os_puts(const char *s)
{
    fputs(s, stdout);
    fflush(stdout);
}

void nn_os_putU32(uint32_t n)
{
    printf("%lu", (unsigned long)n);
    fflush(stdout);
}
