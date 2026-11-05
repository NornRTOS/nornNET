/**
 * @file nn_os_nornos.c
 * nornNET on nornOS. Thin: every call maps onto one kernel primitive. Built with NN_HOST
 * the console goes to stdio (nornOS host port in the unit tests), otherwise to the HAL
 * UART.
 */

#include "nn_os.h"

#ifdef NN_HOST
# include <stdio.h>
# include <stdlib.h>
#else
# include "uart.h"
#endif

static uint8_t _netStack[NN_CFG_TASK_STACK] __attribute__((aligned(16)));

/* --- Time ---------------------------------------------------------------------------- */

static rtos_tick_t msToTicks(nn_ms_t ms)
{
    if(ms == NN_FOREVER)
        return RTOS_FOREVER;
#if RTOS_CFG_TICK_HZ == 1000ul
    return (rtos_tick_t)ms;
#else
    {
        const uint32_t t = (uint32_t)(((uint64_t)ms * RTOS_CFG_TICK_HZ + 999ul) / 1000ul);
        return (rtos_tick_t)(t == 0 && ms != 0 ? 1 : t);
    }
#endif
}

nn_ms_t nn_os_now(void)
{
#if RTOS_CFG_TICK_HZ == 1000ul
    return (nn_ms_t)rtos_getTick();
#else
    return (nn_ms_t)((uint64_t)rtos_getTick() * 1000ul / RTOS_CFG_TICK_HZ);
#endif
}

/* --- Task and notifications ---------------------------------------------------------- */

void nn_os_taskCreate(void (*fn)(void *arg), void *arg)
{
    rtos_createTask(NN_CFG_TASK_PRIO, fn, arg, _netStack, sizeof(_netStack));
}

nn_os_taskId_t nn_os_self(void)
{
    return rtos_getCurrentTask();
}

void nn_os_notify(nn_os_taskId_t task)
{
    rtos_notify(task, 1u, RTOS_NOTIFY_OR);
}

void nn_os_notifyFromIsr(nn_os_taskId_t task)
{
    rtos_notifyFromIsr(task, 1u, RTOS_NOTIFY_OR);
}

bool nn_os_notifyWait(nn_ms_t ms)
{
    return rtos_notifyTake(msToTicks(ms));
}

/* --- Lock ------------------------------------------------------------------------------ */

void nn_os_lockInit(nn_os_lock_t *pLock)
{
    rtos_mutexInit(&pLock->m, NN_CFG_LOCK_CEILING);
    pLock->owner = RTOS_NO_TASK;
    pLock->depth = 0;
}

void nn_os_lock(nn_os_lock_t *pLock)
{
    const uint8_t self = rtos_getCurrentTask();
    if(pLock->depth != 0  &&  pLock->owner == self)
    {
        ++ pLock->depth;                /* re-entered from a callback in the net task */
        return;
    }
    rtos_mutexLock(&pLock->m);
    pLock->owner = self;
    pLock->depth = 1;
}

void nn_os_unlock(nn_os_lock_t *pLock)
{
    if(-- pLock->depth != 0)
        return;
    pLock->owner = RTOS_NO_TASK;
    rtos_mutexUnlock(&pLock->m);
}

/* --- Queue ---------------------------------------------------------------------------- */

void nn_os_queueInit(nn_os_queue_t *pQ, void **storage, uint8_t capacity)
{
    rtos_queueInit(pQ, (uint8_t *)storage, (uint8_t)sizeof(void *), capacity);
}

bool nn_os_queuePut(nn_os_queue_t *pQ, void *p)
{
    return rtos_queueSend(pQ, &p, RTOS_NO_WAIT);
}

bool nn_os_queuePutFromIsr(nn_os_queue_t *pQ, void *p)
{
    return rtos_queueSendFromIsr(pQ, &p);
}

bool nn_os_queueGet(nn_os_queue_t *pQ, void **pp, nn_ms_t ms)
{
    return rtos_queueReceive(pQ, pp, msToTicks(ms));
}

/* --- Pool ------------------------------------------------------------------------------ */

void nn_os_poolInit(nn_os_pool_t *pPool, void *storage, uint16_t blockSize, uint8_t numBlocks)
{
    rtos_poolInit(pPool, (uint8_t *)storage, blockSize, numBlocks);
}

void *nn_os_poolAlloc(nn_os_pool_t *pPool)
{
    return rtos_poolAlloc(pPool, RTOS_NO_WAIT);
}

void *nn_os_poolAllocFromIsr(nn_os_pool_t *pPool)
{
    return rtos_poolAllocFromIsr(pPool);
}

void nn_os_poolFree(nn_os_pool_t *pPool, void *p)
{
    rtos_poolFree(pPool, p);
}

void nn_os_poolFreeFromIsr(nn_os_pool_t *pPool, void *p)
{
    rtos_poolFreeFromIsr(pPool, p);
}

uint8_t nn_os_poolFreeCount(const nn_os_pool_t *pPool)
{
    return rtos_poolFreeCount(pPool);
}

/* --- Critical sections ---------------------------------------------------------------- */

nn_os_cs_t nn_os_enterCritical(void)
{
    return rtos_port_enterCritical();
}

void nn_os_exitCritical(nn_os_cs_t s)
{
    rtos_port_exitCritical(s);
}

/* --- Diagnostics ---------------------------------------------------------------------- */

void nn_os_panic(const char *what)
{
    nn_os_puts("nornNET panic: ");
    nn_os_puts(what);
    nn_os_puts("\r\n");
    rtos_panic(RTOS_PANIC_APPLICATION, 0x4E4Eu, 0u);  /* 'NN' */
}

#ifdef NN_HOST
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
#else
void nn_os_puts(const char *s)
{
    uart_puts(s);
}

void nn_os_putU32(uint32_t n)
{
    uart_putU32(n);
}
#endif
