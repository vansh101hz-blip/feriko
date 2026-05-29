/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef _RTW88_COMPAT_SPINLOCK_H
#define _RTW88_COMPAT_SPINLOCK_H

#include "types.h"
#include "../iokit_shim.h"

/*
 * spinlock_t — IOSimpleLock (interrupt-safe spinlock).
 * Stores an opaque pointer; IOSimpleLockAlloc() must be called before use.
 */
typedef struct {
    IOSimpleLock *lock;
} spinlock_t;

static inline void spin_lock_init(spinlock_t *sl)
{
    sl->lock = IOSimpleLockAlloc();
}

static inline void spin_lock(spinlock_t *sl)
{
    IOSimpleLockLock(sl->lock);
}

static inline void spin_unlock(spinlock_t *sl)
{
    IOSimpleLockUnlock(sl->lock);
}

#define spin_lock_bh(sl)   spin_lock(sl)
#define spin_unlock_bh(sl) spin_unlock(sl)
#define spin_lock_irq(sl)  spin_lock(sl)
#define spin_unlock_irq(sl) spin_unlock(sl)

typedef IOInterruptState rtw88_irq_flags_t;

#define spin_lock_irqsave(sl, flags) \
    do { (flags) = IOSimpleLockLockDisableInterrupt((sl)->lock); } while (0)

#define spin_unlock_irqrestore(sl, flags) \
    do { IOSimpleLockUnlockEnableInterrupt((sl)->lock, (flags)); } while (0)

/*
 * rwlock_t — use IOLock for both read and write paths (simple mutex).
 * rtw88 does not use rwlock for high-frequency concurrent reads, so the
 * extra read parallelism is not worth the added complexity.
 */
typedef struct {
    IOLock *lock;
} rwlock_t;

static inline void rwlock_init(rwlock_t *rw)   { rw->lock = IOLockAlloc(); }
static inline void read_lock(rwlock_t *rw)      { IOLockLock(rw->lock); }
static inline void read_unlock(rwlock_t *rw)    { IOLockUnlock(rw->lock); }
static inline void write_lock(rwlock_t *rw)     { IOLockLock(rw->lock); }
static inline void write_unlock(rwlock_t *rw)   { IOLockUnlock(rw->lock); }
#define read_lock_bh(rw)   read_lock(rw)
#define read_unlock_bh(rw) read_unlock(rw)
#define write_lock_bh(rw)  write_lock(rw)
#define write_unlock_bh(rw) write_unlock(rw)

/* lockdep stubs */
#define lockdep_assert_held(l)      do {} while (0)
#define assert_spin_locked(l)       do {} while (0)
#define lockdep_set_class(l, k)     do {} while (0)

#endif /* _RTW88_COMPAT_SPINLOCK_H */
