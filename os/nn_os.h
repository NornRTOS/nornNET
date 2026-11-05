#ifndef NN_OS_INCLUDED
#define NN_OS_INCLUDED
/**
 * @file nn_os.h
 * Everything nornNET needs from the operating system, in one small contract. There is one
 * implementation per OS: nn_os_nornos.c (the real one) and nn_os_posix.c (host tests and
 * fuzzing without nornOS). The build selects it with -DNN_OS_NORNOS or -DNN_OS_POSIX; the
 * matching nn_os_<os>.h supplies the opaque types.
 *
 * Context rules follow nornOS: a function with a FromIsr suffix is the only one allowed
 * inside an interrupt handler; the others are for tasks. Timeouts are milliseconds, with
 * NN_FOREVER for no timeout and 0 for a poll.
 */

#include "nn_types.h"
#include "nn_cfg.h"

#if defined(NN_OS_NORNOS)
# include "nn_os_nornos.h"
#elif defined(NN_OS_POSIX)
# include "nn_os_posix.h"
#else
# error Define NN_OS_NORNOS or NN_OS_POSIX
#endif

/* --- Time ---------------------------------------------------------------------------- */

/** Milliseconds since start, wrapping. */
nn_ms_t nn_os_now(void);

/* --- The net task and notifications -------------------------------------------------- */

/** Create the net task (nornNET has exactly one task). Priority and stack come from
    NN_CFG_TASK_PRIO and NN_CFG_TASK_STACK. */
void nn_os_taskCreate(void (*fn)(void *arg), void *arg);

/** Identity of the calling task, for nn_os_notify. */
nn_os_taskId_t nn_os_self(void);

/** Wake a task that sleeps in nn_os_notifyWait; a notification sent before the wait is
    remembered (one bit, not counted). */
void nn_os_notify(nn_os_taskId_t task);
void nn_os_notifyFromIsr(nn_os_taskId_t task);

/** Sleep until notified or \a ms elapsed. Returns true when notified. */
bool nn_os_notifyWait(nn_ms_t ms);

/* --- The stack lock ------------------------------------------------------------------ */

void nn_os_lockInit(nn_os_lock_t *pLock);
void nn_os_lock(nn_os_lock_t *pLock);
void nn_os_unlock(nn_os_lock_t *pLock);

/* --- Queue of pointers ---------------------------------------------------------------- */

/** \a storage holds \a capacity pointers. */
void nn_os_queueInit(nn_os_queue_t *pQ, void **storage, uint8_t capacity);

/** Non-blocking put; false if the queue is full. */
bool nn_os_queuePut(nn_os_queue_t *pQ, void *p);
bool nn_os_queuePutFromIsr(nn_os_queue_t *pQ, void *p);

/** Blocking get with timeout; false on timeout. */
bool nn_os_queueGet(nn_os_queue_t *pQ, void **pp, nn_ms_t ms);

/* --- Pool of fixed size blocks -------------------------------------------------------- */

void nn_os_poolInit(nn_os_pool_t *pPool, void *storage, uint16_t blockSize, uint8_t numBlocks);

/** Non-blocking; NULL when empty. */
void *nn_os_poolAlloc(nn_os_pool_t *pPool);
void *nn_os_poolAllocFromIsr(nn_os_pool_t *pPool);
void nn_os_poolFree(nn_os_pool_t *pPool, void *p);
void nn_os_poolFreeFromIsr(nn_os_pool_t *pPool, void *p);
uint8_t nn_os_poolFreeCount(const nn_os_pool_t *pPool);

/* --- Critical sections, for counters shared with interrupt handlers ------------------ */

nn_os_cs_t nn_os_enterCritical(void);
void nn_os_exitCritical(nn_os_cs_t s);

/* --- Diagnostics ---------------------------------------------------------------------- */

/** Stop the system: an invariant of the stack was violated. */
void nn_os_panic(const char *what) __attribute__((noreturn));

/** Console output for logs and test results. */
void nn_os_puts(const char *s);
void nn_os_putU32(uint32_t n);

#endif  /* NN_OS_INCLUDED */
