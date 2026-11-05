/**
 * @file nn_host.c
 * Real time on the host port: the idle task is the only place time passes, so it waits
 * in poll() for the earlier of a descriptor becoming readable and the next millisecond,
 * then delivers interrupts and ticks.
 */

#define _POSIX_C_SOURCE 200809L
#include <poll.h>
#include <time.h>

#include "nn_host.h"
#include "rtos.h"

#define MAX_FDS 4

static struct pollfd _fds[MAX_FDS];
static nn_netdev_t *_devs[MAX_FDS];
static void (*_isrs[MAX_FDS])(nn_netdev_t *);
static int _nFds;
static nn_netdev_t *_pIsrDev;
static void (*_isrFn)(nn_netdev_t *);
static uint64_t _startNs;
static uint64_t _ticksDone;

static uint64_t nowNs(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

void nn_host_watchFd(int fd, nn_netdev_t *pDev, void (*isr)(nn_netdev_t *pDev))
{
    if(_nFds < MAX_FDS)
    {
        _fds[_nFds].fd = fd;
        _fds[_nFds].events = POLLIN;
        _devs[_nFds] = pDev;
        _isrs[_nFds] = isr;
        ++ _nFds;
    }
}

static void isrBody(void)
{
    _isrFn(_pIsrDev);
}

void nn_host_idleHook(void)
{
    const uint64_t tickNs = 1000000000ull / RTOS_CFG_TICK_HZ;
    uint64_t elapsed, due;
    int i, n;

    if(_startNs == 0)
        _startNs = nowNs();

    n = poll(_fds, (nfds_t)_nFds, 1);
    for(i=0; n>0 && i<_nFds; ++i)
    {
        if(_fds[i].revents & POLLIN)
        {
            _pIsrDev = _devs[i];
            _isrFn = _isrs[i];
            rtos_host_simulateIsr(isrBody);
        }
    }

    elapsed = nowNs() - _startNs;
    due = elapsed / tickNs;
    /* Catch up at most 100 ticks at once after a stall (debugger, swapped out). */
    if(due > _ticksDone + 100u)
        _ticksDone = due - 100u;
    while(_ticksDone < due)
    {
        rtos_host_tick();
        ++ _ticksDone;
    }
}
