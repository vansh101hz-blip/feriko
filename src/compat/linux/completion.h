/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef _RTW88_COMPAT_COMPLETION_H
#define _RTW88_COMPAT_COMPLETION_H

#include "types.h"
#include "jiffies.h"
#include "../iokit_shim.h"

struct completion {
    volatile unsigned int done;
    IOLock               *lock;
};

/* Declare only — must call init_completion() before first use */
#define DECLARE_COMPLETION(name) struct completion name = { .done = 0, .lock = NULL }

static inline void init_completion(struct completion *c)
{
    c->done = 0;
    c->lock = IOLockAlloc();
    IOLog("rtw88: init_completion(%p) lock=%p\n", (void *)c, (void *)c->lock);
}

extern bool rtw88_workloop_in_gate(void);
extern unsigned long rtw88_workloop_sleep_timeout(void *event, unsigned long timeout_ms);
extern void rtw88_workloop_wakeup(void *event);

static inline void complete(struct completion *c)
{
    IOLog("rtw88: complete(%p) enter, done=%u\n", (void *)c, c->done);
    IOLockLock(c->lock);
    c->done++;
    IOLockWakeup(c->lock, (void *)c, false);
    rtw88_workloop_wakeup((void *)c);
    IOLockUnlock(c->lock);
    IOLog("rtw88: complete(%p) exit, done=%u\n", (void *)c, c->done);
}

static inline void complete_all(struct completion *c)
{
    IOLog("rtw88: complete_all(%p) enter, done=%u\n", (void *)c, c->done);
    IOLockLock(c->lock);
    c->done = ~0u;
    IOLockWakeup(c->lock, (void *)c, false);
    rtw88_workloop_wakeup((void *)c);
    IOLockUnlock(c->lock);
    IOLog("rtw88: complete_all(%p) exit, done=%u\n", (void *)c, c->done);
}

static inline void wait_for_completion(struct completion *c)
{
    IOLog("rtw88: wait_for_completion(%p) enter, done=%u, lock=%p\n", (void *)c, c->done, (void *)c->lock);
    IOLockLock(c->lock);
    while (!c->done) {
        if (rtw88_workloop_in_gate()) {
            IOLog("rtw88: wait_for_completion(%p) sleeping on workloop...\n", (void *)c);
            IOLockUnlock(c->lock);
            rtw88_workloop_sleep_timeout((void *)c, 1000000000); /* essentially forever */
            IOLockLock(c->lock);
        } else {
            IOLog("rtw88: wait_for_completion(%p) sleeping...\n", (void *)c);
            IOLockSleep(c->lock, (void *)c, THREAD_UNINT);
        }
    }
    if (c->done != ~0u) c->done--;
    IOLockUnlock(c->lock);
    IOLog("rtw88: wait_for_completion(%p) exit, done=%u\n", (void *)c, c->done);
}

/* Returns remaining jiffies (1) on completion, 0 on timeout */
static inline unsigned long wait_for_completion_timeout(struct completion *c,
                                                         unsigned long timeout_j)
{
    IOLog("rtw88: wait_for_completion_timeout(%p) enter\n", (void *)c);
    IOLockLock(c->lock);
    unsigned long remain = timeout_j;
    unsigned long deadline = jiffies + timeout_j;
    while (!c->done) {
        if (rtw88_workloop_in_gate()) {
            IOLog("rtw88: wait_for_completion_timeout(%p) sleeping on workloop... (%lu)\n", (void *)c, remain);
            IOLockUnlock(c->lock);
            remain = rtw88_workloop_sleep_timeout((void *)c, remain * 10);
            IOLockLock(c->lock);
            if (remain == 0) break;
            remain /= 10;
        } else {
            IOLockUnlock(c->lock);
            if (time_after_eq(jiffies, deadline)) { remain = 0; IOLockLock(c->lock); break; }
            IOSleep(1);
            IOLockLock(c->lock);
            remain = deadline - jiffies;
        }
    }
    if (c->done) { if (c->done != ~0u) c->done--; remain = 1; }
    IOLockUnlock(c->lock);
    IOLog("rtw88: wait_for_completion_timeout(%p) exit, remain=%lu\n", (void *)c, remain);
    return remain;
}


static inline int completion_done(struct completion *c)
{
    return c->done > 0;
}

static inline void reinit_completion(struct completion *c)
{
    IOLockLock(c->lock);
    c->done = 0;
    IOLockUnlock(c->lock);
}

#endif /* _RTW88_COMPAT_COMPLETION_H */
