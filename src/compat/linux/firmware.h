/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef _RTW88_COMPAT_FIRMWARE_H
#define _RTW88_COMPAT_FIRMWARE_H

#include "types.h"
#include "kernel.h"
#include "slab.h"

struct firmware {
    size_t    size;
    const u8 *data;
    void     *priv;   /* NULL when data is owned by the kext bundle */
};

struct device;  /* forward decl */

/*
 * Firmware store — the kext C++ layer (RTW88PCIDevice::start) loads firmware
 * blobs from the kext bundle and registers them via rtw88_firmware_register().
 * The C driver calls request_firmware() which looks them up here.
 */
#define RTW88_MAX_FW_ENTRIES 16

struct rtw88_fw_entry {
    const char *name;
    const u8   *data;
    size_t      size;
};

extern struct rtw88_fw_entry rtw88_fw_store[RTW88_MAX_FW_ENTRIES];
extern int                   rtw88_fw_count;

/* Called by kext C++ before rtw_pci_probe() */
static inline void rtw88_firmware_register(const char *name,
                                             const u8   *data,
                                             size_t      size)
{
    if (rtw88_fw_count < RTW88_MAX_FW_ENTRIES) {
        rtw88_fw_store[rtw88_fw_count].name = name;
        rtw88_fw_store[rtw88_fw_count].data = data;
        rtw88_fw_store[rtw88_fw_count].size = size;
        rtw88_fw_count++;
    }
}

/* Strip leading path from a firmware name string */
static inline const char *rtw88_fw_basename(const char *path)
{
    const char *base = path;
    for (const char *p = path; *p; p++)
        if (*p == '/') base = p + 1;
    return base;
}

static inline int request_firmware(const struct firmware **fw_out,
                                     const char *name, struct device *dev)
{
    const char *base = rtw88_fw_basename(name);

    for (int i = 0; i < rtw88_fw_count; i++) {
        const char *ename = rtw88_fw_basename(rtw88_fw_store[i].name);
        if (strcmp(base, ename) == 0) {
            struct firmware *fw = (struct firmware *)kzalloc(sizeof(*fw), GFP_KERNEL);
            if (!fw) return -ENOMEM;
            fw->size = rtw88_fw_store[i].size;
            fw->data = rtw88_fw_store[i].data;
            fw->priv = NULL; /* data owned by kext bundle, not freed here */
            *fw_out  = fw;
            return 0;
        }
    }
    return -ENOENT;
}

static inline void release_firmware(const struct firmware *fw)
{
    if (fw) kfree(fw); /* fw->data is bundle-owned, not freed */
}

static inline int firmware_request_nowarn(const struct firmware **fw,
                                           const char *name, struct device *dev)
{
    return request_firmware(fw, name, dev);
}

#endif /* _RTW88_COMPAT_FIRMWARE_H */
