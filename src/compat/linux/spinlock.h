/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef _RTW88_COMPAT_SPINLOCK_H
#define _RTW88_COMPAT_SPINLOCK_H

#include "types.h"
#include "../iokit_shim.h"

/*
 * spinlock_t — backed by IOLock (a sleeping mutex) rather than IOSimpleLock.
 *
 * On Linux, spin_lock_bh() acquires a spinlock and disables softirq bottom-
 * halves, but never sleeps and never disables preemption in a way that would
 * prevent other kernel threads from running.
 *
 * Our macOS port does NOT run real interrupt handlers; the "interrupt thread"
 * (rtw_pci_interrupt_threadfn) is just a regular kernel thread invoked from
 * the IOWorkLoop.  Using IOSimpleLockLock here would:
 *   1. Disable preemption on the calling CPU.
 *   2. Block the scheduler from switching to the workqueue thread that
 *      schedule_work() just woke up inside the same lock region.
 *   => hard deadlock.
 *
 * IOLock is a recursive-safe, preemption-friendly mutex. It is the correct
 * primitive for our threading model.
 */
typedef struct {
    IOLock *lock;
} spinlock_t;

static inline void spin_lock_init(spinlock_t *sl)
{
    sl->lock = IOLockAlloc();
}

static inline void spin_lock(spinlock_t *sl)
{
    IOLockLock(sl->lock);
}

static inline void spin_unlock(spinlock_t *sl)
{
    IOLockUnlock(sl->lock);
}

#define spin_lock_bh(sl)    spin_lock(sl)
#define spin_unlock_bh(sl)  spin_unlock(sl)
#define spin_lock_irq(sl)   spin_lock(sl)
#define spin_unlock_irq(sl) spin_unlock(sl)

typedef unsigned long rtw88_irq_flags_t;

#define spin_lock_irqsave(sl, flags) \
    do { (void)(flags); IOLockLock((sl)->lock); } while (0)

#define spin_unlock_irqrestore(sl, flags) \
    do { (void)(flags); IOLockUnlock((sl)->lock); } while (0)

/*
 * rwlock_t — same approach, plain IOLock.
 */
typedef struct {
    IOLock *lock;
} rwlock_t;

static inline void rwlock_init(rwlock_t *rw)    { rw->lock = IOLockAlloc(); }
static inline void read_lock(rwlock_t *rw)       { IOLockLock(rw->lock); }
static inline void read_unlock(rwlock_t *rw)     { IOLockUnlock(rw->lock); }
static inline void write_lock(rwlock_t *rw)      { IOLockLock(rw->lock); }
static inline void write_unlock(rwlock_t *rw)    { IOLockUnlock(rw->lock); }
#define read_lock_bh(rw)    read_lock(rw)
#define read_unlock_bh(rw)  read_unlock(rw)
#define write_lock_bh(rw)   write_lock(rw)
#define write_unlock_bh(rw) write_unlock(rw)

/* lockdep stubs */
#define lockdep_assert_held(l)      do {} while (0)
#define assert_spin_locked(l)       do {} while (0)
#define lockdep_set_class(l, k)     do {} while (0)

#endif /* _RTW88_COMPAT_SPINLOCK_H */
