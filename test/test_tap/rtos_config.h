#ifndef RTOS_CONFIG_INCLUDED
#define RTOS_CONFIG_INCLUDED
/* nornOS configuration of test_tap: real time, the idle hook polls the TAP descriptor
   and advances the tick with the wall clock (host/nn_host.c). */

#define RTOS_CFG_NUM_TASKS      3
#define RTOS_CFG_TICK_HZ        1000ul
#define RTOS_CFG_TICK_BITS      32
#define RTOS_CFG_EVT_BITS       16
#define RTOS_CFG_STACK_CHECK    0
#define RTOS_CFG_IDLE_SLEEP     1
#define RTOS_CFG_ASSERT         1
#define RTOS_CFG_IDLE_HOOK      nn_host_idleHook

void nn_host_idleHook(void);

#endif  /* RTOS_CONFIG_INCLUDED */
