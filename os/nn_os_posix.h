#ifndef NN_OS_POSIX_INCLUDED
#define NN_OS_POSIX_INCLUDED
/**
 * @file nn_os_posix.h
 * OS types of nornNET on a POSIX host (pthreads), for unit tests and fuzzing without
 * nornOS. Not a model of real time behaviour: priorities are ignored.
 */

#include <pthread.h>

struct nn_os_posixTask;
typedef struct nn_os_posixTask *nn_os_taskId_t;

typedef struct nn_os_lock
{
    pthread_mutex_t m;
} nn_os_lock_t;

typedef struct nn_os_queue
{
    pthread_mutex_t m;
    pthread_cond_t  cv;
    void **storage;
    uint8_t capacity, count, head, tail;
} nn_os_queue_t;

typedef struct nn_os_pool
{
    pthread_mutex_t m;
    void *pFree;
    uint8_t numFree;
} nn_os_pool_t;

typedef int nn_os_cs_t;

/** Test hooks of the POSIX layer: make nn_os_now jump forward by \a ms, and stop the
    clock so time only moves by nn_os_testAdvance (reproducible fuzzing). */
void nn_os_testAdvance(uint32_t ms);
void nn_os_testFreeze(bool frozen);

#endif  /* NN_OS_POSIX_INCLUDED */
