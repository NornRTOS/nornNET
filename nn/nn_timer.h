#ifndef NN_TIMER_INCLUDED
#define NN_TIMER_INCLUDED
/**
 * @file nn_timer.h
 * Stack timers: a list sorted by expiry, run by the net task. All calls require the
 * stack lock (nn_lock) to be held; the callback runs in the net task with the lock held
 * and may start or stop timers, including its own.
 */

#include "nn_types.h"

typedef struct nn_timer nn_timer_t;
typedef void (*nn_timerFunc_t)(nn_timer_t *pT, void *arg);

struct nn_timer
{
    nn_timer_t *pNext;
    nn_ms_t expires;
    nn_ms_t period;             /**< 0: one shot. */
    nn_timerFunc_t cb;
    void *arg;
    bool active;
};

void nn_timer_init(void);

void nn_timerSetup(nn_timer_t *pT, nn_timerFunc_t cb, void *arg);

/** (Re)start: fires after \a ms, then every \a period ms (0: once). Wakes the net task
    so a short timer is honoured even if the task was sleeping for longer. */
void nn_timerStart(nn_timer_t *pT, nn_ms_t ms, nn_ms_t period);
void nn_timerStop(nn_timer_t *pT);
bool nn_timerIsActive(const nn_timer_t *pT);

/** Milliseconds until the first expiry; NN_FOREVER with no timer. 0 if already due. */
nn_ms_t nn_timer_nextMs(void);

/** Run every timer that is due. Called by the net task. */
void nn_timer_run(void);


#endif  /* NN_TIMER_INCLUDED */
