/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 * rtw88_firmware.c — firmware loading for rtw88 macOS port.
 *
 * Primary path: embedded blobs (fw_blobs.c, generated from firmware/*.bin).
 * These are zlib-compressed arrays linked into the binary, so the kext is
 * fully self-contained and works before any filesystem is mounted (OpenCore
 * injection, BaseSystem, early boot).
 *
 * Compiled WITHOUT Linux compat headers to avoid type conflicts.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <IOKit/IOLib.h>
#include <libkern/zlib.h>

#include "fw_blobs.h"

/* Minimal struct firmware — must match linux/firmware.h */
struct firmware {
    size_t        size;
    const uint8_t *data;
};

/* ------------------------------------------------------------------ */
/*  Blob-based loading (primary path)                                  */
/* ------------------------------------------------------------------ */

static struct firmware *load_fw_from_blob(const char *base)
{
    for (int i = 0; rtw88_fw_blobs[i].name; i++) {
        if (strcmp(rtw88_fw_blobs[i].name, base) != 0)
            continue;

        const struct rtw88_fw_blob *b = &rtw88_fw_blobs[i];
        uint8_t *buf = (uint8_t *)IOMalloc(b->original_size);
        if (!buf) {
            IOLog("rtw88: OOM decompressing %s\n", base);
            return NULL;
        }

        z_stream zs;
        zs.next_in   = (Bytef *)b->data;
        zs.avail_in  = (uInt)b->compressed_size;
        zs.next_out  = (Bytef *)buf;
        zs.avail_out = (uInt)b->original_size;
        zs.zalloc    = Z_NULL;
        zs.zfree     = Z_NULL;
        zs.opaque    = Z_NULL;

        if (inflateInit(&zs) != Z_OK) {
            IOLog("rtw88: inflateInit failed for %s\n", base);
            IOFree(buf, b->original_size);
            return NULL;
        }
        int ret = inflate(&zs, Z_FINISH);
        inflateEnd(&zs);

        if (ret != Z_STREAM_END) {
            IOLog("rtw88: inflate failed for %s: %d\n", base, ret);
            IOFree(buf, b->original_size);
            return NULL;
        }

        struct firmware *fw = (struct firmware *)IOMallocZero(sizeof(*fw));
        if (!fw) { IOFree(buf, b->original_size); return NULL; }
        fw->data = buf;
        fw->size = b->original_size;
        IOLog("rtw88: firmware %s loaded from blob (%zu bytes)\n",
              base, fw->size);
        return fw;
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Shared helper: strip path prefix, try blob then fail               */
/* ------------------------------------------------------------------ */

static struct firmware *load_fw(const char *name)
{
    /* Strip leading path (driver passes "rtlwifi/foo.bin" or bare "foo.bin") */
    const char *base = name;
    for (const char *p = name; *p; p++)
        if (*p == '/') base = p + 1;

    struct firmware *fw = load_fw_from_blob(base);
    if (fw) return fw;

    IOLog("rtw88: firmware %s not found in embedded blobs\n", base);
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Public API — signatures must match linux/firmware.h               */
/* ------------------------------------------------------------------ */

struct module;
struct device;

int request_firmware_nowait(struct module *module, int uevent,
                             const char *name, struct device *device,
                             unsigned int gfp, void *context,
                             void (*cont)(const struct firmware *fw, void *ctx))
{
    (void)module; (void)uevent; (void)device; (void)gfp;
    if (!cont) return -22; /* EINVAL */
    cont(load_fw(name), context);
    return 0;
}

void release_firmware(const struct firmware *fw)
{
    if (!fw) return;
    if (fw->data) IOFree((void *)fw->data, fw->size);
    IOFree((void *)fw, sizeof(*fw));
}

int rtw88_load_firmware_sync(const char *name, const struct firmware **fw_out)
{
    *fw_out = load_fw(name);
    return *fw_out ? 0 : -2; /* ENOENT */
}

/* ------------------------------------------------------------------ */
/*  rtw88_set_fw_dir / rtw88_find_fw_dir — kept as no-ops             */
/*  (blobs are embedded; no filesystem needed)                         */
/* ------------------------------------------------------------------ */

void rtw88_set_fw_dir(const char *dir) { (void)dir; }
void rtw88_find_fw_dir(void) {}
