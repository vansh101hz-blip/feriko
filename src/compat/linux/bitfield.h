/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef _RTW88_COMPAT_BITFIELD_H
#define _RTW88_COMPAT_BITFIELD_H

#include "types.h"
#include "bitops.h"

/* FIELD_PREP — set a field value (pre-shifted) */
#define FIELD_PREP(_mask, _val) \
    (((u64)(_val) << __ffs((unsigned long)(_mask))) & (u64)(_mask))

/* FIELD_GET — extract a field value */
#define FIELD_GET(_mask, _val) \
    (((u64)(_val) & (u64)(_mask)) >> __ffs((unsigned long)(_mask)))

/* FIELD_FIT — check value fits in mask */
#define FIELD_FIT(_mask, _val) \
    (!((((u64)(_val)) << __ffs((unsigned long)(_mask))) & ~(u64)(_mask)))

#endif /* _RTW88_COMPAT_BITFIELD_H */
