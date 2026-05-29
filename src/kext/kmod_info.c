/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 * kmod_info.c — defines the mandatory _kmod_info symbol for this kext.
 *
 * kmutil (macOS 11+) and kextutil require every kext binary to export
 * _kmod_info.  For Xcode projects this is auto-generated; for a Makefile
 * build we define it directly using the KMOD_EXPLICIT_DECL macro.
 */
#include <mach/mach_types.h>
#include <mach/kmod.h>

extern kern_return_t _start(kmod_info_t *, void *);
extern kern_return_t _stop(kmod_info_t *, void *);

KMOD_EXPLICIT_DECL(com.rtw88.driver, "1.0.0", _start, _stop)
