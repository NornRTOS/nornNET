#ifndef NN_HOST_INCLUDED
#define NN_HOST_INCLUDED
/**
 * @file nn_host.h
 * Glue for running nornNET on the nornOS host port in real time: an idle hook that
 * advances the kernel tick with the wall clock and turns readable descriptors into
 * simulated receive interrupts. Register it as RTOS_CFG_IDLE_HOOK.
 */

#include "nn_netdev.h"

/** Watch \a fd; when readable, run \a isr(pDev) as an interrupt. */
void nn_host_watchFd(int fd, nn_netdev_t *pDev, void (*isr)(nn_netdev_t *pDev));

/** The idle hook: sleeps up to one tick in poll(), then catches up ticks. */
void nn_host_idleHook(void);

#endif  /* NN_HOST_INCLUDED */
