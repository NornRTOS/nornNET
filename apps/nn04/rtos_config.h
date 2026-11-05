#ifndef RTOS_CONFIG_INCLUDED
#define RTOS_CONFIG_INCLUDED
/* Kernel configuration of nn04. */

#define RTOS_CFG_NUM_TASKS      3
#define RTOS_CFG_TICK_HZ        1000ul
#define RTOS_CFG_TICK_BITS      32
#define RTOS_CFG_EVT_BITS       16
#define RTOS_CFG_STACK_CHECK    2
#define RTOS_CFG_IDLE_SLEEP     1
#define RTOS_CFG_ASSERT         1

#endif  /* RTOS_CONFIG_INCLUDED */
