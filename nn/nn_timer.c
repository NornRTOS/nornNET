/**
 * @file nn_timer.c
 * Sorted single linked list of timers; insertion is O(n) in the number of active timers,
 * which is small (ARP ageing, DHCP, DNS retries, TCP per socket).
 */

#include "nn_timer.h"
#include "nn_net.h"
#include "nn_os.h"

static nn_timer_t *_pHead;

void nn_timer_init(void)
{
    _pHead = NULL;
}

void nn_timerSetup(nn_timer_t *pT, nn_timerFunc_t cb, void *arg)
{
    pT->pNext = NULL;
    pT->cb = cb;
    pT->arg = arg;
    pT->period = 0;
    pT->expires = 0;
    pT->active = false;
}

static void unlink(nn_timer_t *pT)
{
    nn_timer_t **pp;
    for(pp=&_pHead; *pp!=NULL; pp=&(*pp)->pNext)
    {
        if(*pp == pT)
        {
            *pp = pT->pNext;
            break;
        }
    }
    pT->pNext = NULL;
    pT->active = false;
}

static void insert(nn_timer_t *pT)
{
    nn_timer_t **pp = &_pHead;
    while(*pp != NULL  &&  !nn_msBefore(pT->expires, (*pp)->expires))
        pp = &(*pp)->pNext;
    pT->pNext = *pp;
    *pp = pT;
    pT->active = true;
}

void nn_timerStart(nn_timer_t *pT, nn_ms_t ms, nn_ms_t period)
{
    if(pT->active)
        unlink(pT);
    pT->expires = nn_os_now() + ms;
    pT->period = period;
    insert(pT);
    if(_pHead == pT)
        nn_net_kick();
}

void nn_timerStop(nn_timer_t *pT)
{
    if(pT->active)
        unlink(pT);
}

bool nn_timerIsActive(const nn_timer_t *pT)
{
    return pT->active;
}

nn_ms_t nn_timer_nextMs(void)
{
    nn_ms_t now;

    if(_pHead == NULL)
        return NN_FOREVER;
    now = nn_os_now();
    return nn_msBefore(_pHead->expires, now + 1u) ? 0u : _pHead->expires - now;
}

void nn_timer_run(void)
{
    const nn_ms_t now = nn_os_now();

    while(_pHead != NULL  &&  !nn_msBefore(now, _pHead->expires))
    {
        nn_timer_t * const pT = _pHead;
        unlink(pT);
        if(pT->period != 0)
        {
            pT->expires += pT->period;
            insert(pT);
        }
        pT->cb(pT, pT->arg);
    }
}
