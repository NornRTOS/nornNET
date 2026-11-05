#ifndef NN_OS_NORNOS_INCLUDED
#define NN_OS_NORNOS_INCLUDED
/**
 * @file nn_os_nornos.h
 * OS types of nornNET on nornOS: the kernel's own objects, used directly.
 */

#include "rtos.h"

typedef uint8_t     nn_os_taskId_t;
/** The stack lock: a nornOS ICPP mutex plus an owner and a depth, so a callback that
    runs inside the net task (with the lock held) may call the socket API. */
typedef struct nn_os_lock
{
    rtos_mutex_t m;
    uint8_t owner;
    uint8_t depth;
} nn_os_lock_t;
typedef rtos_queue_t nn_os_queue_t;
typedef rtos_pool_t  nn_os_pool_t;
typedef rtos_port_cs_t nn_os_cs_t;

#endif  /* NN_OS_NORNOS_INCLUDED */
