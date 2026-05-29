/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 * kmod_info.c — _kmod_info symbol + _realmain/_antimain wiring.
 *
 * libkmod.a's c_start.c (x86_64) defines _start as:
 *   if (_realmain) return (*_realmain)(ki, data);
 * cplus_start.c wraps OSRuntimeInitializeCPP first, but only for i386/ppc.
 * On x86_64 we must supply _realmain/_antimain ourselves.
 */
#include <mach/mach_types.h>
#include <mach/kmod.h>

extern kern_return_t _start(kmod_info_t *, void *);
extern kern_return_t _stop(kmod_info_t *, void *);

KMOD_EXPLICIT_DECL(com.rtw88.driver, "1.0.0", _start, _stop)

/* com.apple.kpi.libkern exports */
extern kern_return_t OSRuntimeInitializeCPP(kmod_info_t *ki, void *data);
extern kern_return_t OSRuntimeFinalizeCPP(kmod_info_t *ki, void *data);

/* rtw88_compat.c */
extern int  rtw88_compat_init(void);
extern void rtw88_compat_exit(void);

static kern_return_t rtw88_module_start(kmod_info_t *ki, void *data)
{
    kern_return_t kr = OSRuntimeInitializeCPP(ki, data);
    if (kr == KERN_SUCCESS)
        kr = (rtw88_compat_init() == 0) ? KERN_SUCCESS : KERN_FAILURE;
    return kr;
}

static kern_return_t rtw88_module_stop(kmod_info_t *ki, void *data)
{
    rtw88_compat_exit();
    return OSRuntimeFinalizeCPP(ki, data);
}

kmod_start_func_t *_realmain = rtw88_module_start;
kmod_stop_func_t  *_antimain = rtw88_module_stop;
