// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// RTW88IEEE80211.cpp — 802.11 state machine

#include "RTW88IEEE80211.hpp"
#include "RTW88PCIDevice.hpp"
#include "RTW88UserClient.hpp"

#include <IOKit/IOLib.h>
#include <IOKit/IOService.h>
#include <sys/mbuf.h>
#include <string.h>
#include <sys/random.h>

/* Debug stage checkpoint — logs message only (no sleep). */
#define RTW88_STAGE(fmt, ...) IOLog("rtw88: ---- STAGE: " fmt " ----\n", ##__VA_ARGS__)

/* Chain-safe packet mbuf builder (defined below). */
static mbuf_t rtw88_make_packet_mbuf(const void *src, uint32_t len);

extern "C" {
#include "../compat/rtw88_compat.h"

/* Linux driver public API */
int  rtw_core_init(struct rtw_dev *rtwdev);
void rtw_core_deinit(struct rtw_dev *rtwdev);
int  rtw_core_start(struct rtw_dev *rtwdev);
void rtw_core_stop(struct rtw_dev *rtwdev);
void rtw_tx(struct rtw_dev *rtwdev, struct ieee80211_tx_control *control,
            struct sk_buff *skb);

/* PCI probe shim declared in pci.c */
int  rtw_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id);
void rtw_pci_remove(struct pci_dev *pdev);

/* Exported from the compat layer for hooking */
void rtw88_set_hw_callbacks(struct rtw88_hw_callbacks *cbs, void *kext_hw);

/* chip hw_spec structs — driver_data for rtw_pci_probe */
extern const struct rtw_chip_info rtw8822b_hw_spec;
extern const struct rtw_chip_info rtw8822c_hw_spec;
extern const struct rtw_chip_info rtw8821c_hw_spec;
extern const struct rtw_chip_info rtw8814a_hw_spec;

} /* extern "C" */

/* ------------------------------------------------------------------ */
/*  WPA2 cryptographic functions (SHA1, HMAC-SHA1, PBKDF2, PRF)      */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    uint8_t buffer[64];
} KERN_SHA1_CTX;

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

#define blk0(i) (block->l[i] = (rol(block->l[i], 24) & 0xFF00FF00) | (rol(block->l[i], 8) & 0x00FF00FF))
#define blk(i) (block->l[i & 15] = rol(block->l[(i + 13) & 15] ^ block->l[(i + 8) & 15] ^ block->l[(i + 2) & 15] ^ block->l[i & 15], 1))

#define r0(v,w,x,y,z,i) z += ((w & (x ^ y)) ^ y) + blk0(i) + 0x5A827999 + rol(v, 5); w = rol(w, 30);
#define r1(v,w,x,y,z,i) z += ((w & (x ^ y)) ^ y) + blk(i) + 0x5A827999 + rol(v, 5); w = rol(w, 30);
#define r2(v,w,x,y,z,i) z += (w ^ x ^ y) + blk(i) + 0x6ED9EBA1 + rol(v, 5); w = rol(w, 30);
#define r3(v,w,x,y,z,i) z += (((w | x) & y) | (w & x)) + blk(i) + 0x8F1BBCDC + rol(v, 5); w = rol(w, 30);
#define r4(v,w,x,y,z,i) z += (w ^ x ^ y) + blk(i) + 0xCA62C1D6 + rol(v, 5); w = rol(w, 30);

static void kern_sha1_transform(uint32_t state[5], const uint8_t buffer[64]) {
    uint32_t a, b, c, d, e;
    typedef union {
        uint8_t c[64];
        uint32_t l[16];
    } CHAR64LONG16;
    CHAR64LONG16 block[1];
    memcpy(block, buffer, 64);
    a = state[0]; b = state[1]; c = state[2]; d = state[3]; e = state[4];
    r0(a,b,c,d,e,0);  r0(e,a,b,c,d,1);  r0(d,e,a,b,c,2);  r0(c,d,e,a,b,3);
    r0(b,c,d,e,a,4);  r0(a,b,c,d,e,5);  r0(e,a,b,c,d,6);  r0(d,e,a,b,c,7);
    r0(c,d,e,a,b,8);  r0(b,c,d,e,a,9);  r0(a,b,c,d,e,10); r0(e,a,b,c,d,11);
    r0(d,e,a,b,c,12); r0(c,d,e,a,b,13); r0(b,c,d,e,a,14); r0(a,b,c,d,e,15);
    r1(e,a,b,c,d,16); r1(d,e,a,b,c,17); r1(c,d,e,a,b,18); r1(b,c,d,e,a,19);
    r2(a,b,c,d,e,20); r2(e,a,b,c,d,21); r2(d,e,a,b,c,22); r2(c,d,e,a,b,23);
    r2(b,c,d,e,a,24); r2(a,b,c,d,e,25); r2(e,a,b,c,d,26); r2(d,e,a,b,c,27);
    r2(c,d,e,a,b,28); r2(b,c,d,e,a,29); r2(a,b,c,d,e,30); r2(e,a,b,c,d,31);
    r2(d,e,a,b,c,32); r2(c,d,e,a,b,33); r2(b,c,d,e,a,34); r2(a,b,c,d,e,35);
    r2(e,a,b,c,d,36); r2(d,e,a,b,c,37); r2(c,d,e,a,b,38); r2(b,c,d,e,a,39);
    r3(a,b,c,d,e,40); r3(e,a,b,c,d,41); r3(d,e,a,b,c,42); r3(c,d,e,a,b,43);
    r3(b,c,d,e,a,44); r3(a,b,c,d,e,45); r3(e,a,b,c,d,46); r3(d,e,a,b,c,47);
    r3(c,d,e,a,b,48); r3(b,c,d,e,a,49); r3(a,b,c,d,e,50); r3(e,a,b,c,d,51);
    r3(d,e,a,b,c,52); r3(c,d,e,a,b,53); r3(b,c,d,e,a,54); r3(a,b,c,d,e,55);
    r3(e,a,b,c,d,56); r3(d,e,a,b,c,57); r3(c,d,e,a,b,58); r3(b,c,d,e,a,59);
    r4(a,b,c,d,e,60); r4(e,a,b,c,d,61); r4(d,e,a,b,c,62); r4(c,d,e,a,b,63);
    r4(b,c,d,e,a,64); r4(a,b,c,d,e,65); r4(e,a,b,c,d,66); r4(d,e,a,b,c,67);
    r4(c,d,e,a,b,68); r4(b,c,d,e,a,69); r4(a,b,c,d,e,70); r4(e,a,b,c,d,71);
    r4(d,e,a,b,c,72); r4(c,d,e,a,b,73); r4(b,c,d,e,a,74); r4(a,b,c,d,e,75);
    r4(e,a,b,c,d,76); r4(d,e,a,b,c,77); r4(c,d,e,a,b,78); r4(b,c,d,e,a,79);
    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

static void kern_sha1_init(KERN_SHA1_CTX *context) {
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}

static void kern_sha1_update(KERN_SHA1_CTX *context, const uint8_t *data, uint32_t len) {
    uint32_t i, j;
    j = context->count[0];
    if ((context->count[0] += len << 3) < j)
        context->count[1]++;
    context->count[1] += (len >> 29);
    j = (j >> 3) & 63;
    if ((j + len) > 63) {
        memcpy(&context->buffer[j], data, (i = 64 - j));
        kern_sha1_transform(context->state, context->buffer);
        for (; i + 63 < len; i += 64) {
            kern_sha1_transform(context->state, &data[i]);
        }
        j = 0;
    } else {
        i = 0;
    }
    memcpy(&context->buffer[j], &data[i], len - i);
}

static void kern_sha1_final(uint8_t digest[20], KERN_SHA1_CTX *context) {
    unsigned char finalcount[8];
    for (int i = 0; i < 8; i++) {
        finalcount[i] = (unsigned char)((context->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);
    }
    unsigned char c = 0200;
    kern_sha1_update(context, &c, 1);
    while ((context->count[0] & 504) != 448) {
        c = 0;
        kern_sha1_update(context, &c, 1);
    }
    kern_sha1_update(context, finalcount, 8);
    for (int i = 0; i < 20; i++) {
        digest[i] = (uint8_t)((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
    }
}

static void kern_hmac_sha1(const uint8_t *key, size_t key_len,
                           const uint8_t *data, size_t data_len,
                           uint8_t mac[20])
{
    KERN_SHA1_CTX ctx;
    uint8_t k_ipad[64] = {};
    uint8_t k_opad[64] = {};
    uint8_t tmp_key[20];

    if (key_len > 64) {
        kern_sha1_init(&ctx);
        kern_sha1_update(&ctx, key, (uint32_t)key_len);
        kern_sha1_final(tmp_key, &ctx);
        key = tmp_key;
        key_len = 20;
    }

    memcpy(k_ipad, key, key_len);
    memcpy(k_opad, key, key_len);

    for (int i = 0; i < 64; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    kern_sha1_init(&ctx);
    kern_sha1_update(&ctx, k_ipad, 64);
    kern_sha1_update(&ctx, data, (uint32_t)data_len);
    kern_sha1_final(mac, &ctx);

    kern_sha1_init(&ctx);
    kern_sha1_update(&ctx, k_opad, 64);
    kern_sha1_update(&ctx, mac, 20);
    kern_sha1_final(mac, &ctx);
}

static void derivePMK(const uint8_t *passphrase, const uint8_t *ssid, size_t ssid_len, uint8_t pmk[32])
{
    size_t pass_len = strlen((const char *)passphrase);
    uint8_t salt[128];
    if (ssid_len > 120) ssid_len = 120;
    memcpy(salt, ssid, ssid_len);

    for (int block = 1; block <= 2; block++) {
        salt[ssid_len]     = (uint8_t)((block >> 24) & 0xff);
        salt[ssid_len + 1] = (uint8_t)((block >> 16) & 0xff);
        salt[ssid_len + 2] = (uint8_t)((block >> 8) & 0xff);
        salt[ssid_len + 3] = (uint8_t)(block & 0xff);

        uint8_t u[20];
        uint8_t t[20];
        kern_hmac_sha1(passphrase, pass_len, salt, ssid_len + 4, u);
        memcpy(t, u, 20);

        for (int iter = 1; iter < 4096; iter++) {
            kern_hmac_sha1(passphrase, pass_len, u, 20, u);
            for (int i = 0; i < 20; i++) {
                t[i] ^= u[i];
            }
        }

        if (block == 1) {
            memcpy(pmk, t, 20);
        } else {
            memcpy(pmk + 20, t, 12);
        }
    }
}

static void derivePTK(const uint8_t pmk[32], const uint8_t anonce[32], const uint8_t snonce[32],
                      const uint8_t spa[6], const uint8_t aa[6], uint8_t ptk[64])
{
    uint8_t min_mac[6], max_mac[6];
    if (memcmp(spa, aa, 6) < 0) {
        memcpy(min_mac, spa, 6);
        memcpy(max_mac, aa, 6);
    } else {
        memcpy(min_mac, aa, 6);
        memcpy(max_mac, spa, 6);
    }

    uint8_t min_nonce[32], max_nonce[32];
    if (memcmp(snonce, anonce, 32) < 0) {
        memcpy(min_nonce, snonce, 32);
        memcpy(max_nonce, anonce, 32);
    } else {
        memcpy(min_nonce, anonce, 32);
        memcpy(max_nonce, snonce, 32);
    }

    uint8_t data[100];
    const char *label = "Pairwise key expansion";
    memcpy(data, label, 22);
    data[22] = 0;
    memcpy(data + 23, min_mac, 6);
    memcpy(data + 29, max_mac, 6);
    memcpy(data + 35, min_nonce, 32);
    memcpy(data + 67, max_nonce, 32);
    size_t data_len = 23 + 6 + 6 + 32 + 32;

    uint8_t hash[20];
    for (int i = 0; i < 4; i++) {
        data[data_len] = (uint8_t)i;
        kern_hmac_sha1(pmk, 32, data, data_len + 1, hash);
        if (i < 3) {
            memcpy(ptk + i * 20, hash, 20);
        } else {
            memcpy(ptk + i * 20, hash, 4);
        }
    }
}

#undef rol
#undef blk0
#undef blk
#undef r0
#undef r1
#undef r2
#undef r3
#undef r4

/* PCI device-ID → chip_info lookup (PCIe chips only) */
struct rtw88_pci_id_entry {
    uint16_t device;
    const struct rtw_chip_info *chip;
};

static const struct rtw88_pci_id_entry rtw88_pci_chip_table[] = {
    { 0xB822, &rtw8822b_hw_spec },  /* RTL8822BE */
    { 0xC822, &rtw8822c_hw_spec },  /* RTL8822CE */
    { 0xC82F, &rtw8822c_hw_spec },  /* RTL8822CE variant */
    { 0xC821, &rtw8821c_hw_spec },  /* RTL8821CE */
    { 0xB821, &rtw8821c_hw_spec },  /* RTL8821CE variant */
    { 0x8813, &rtw8814a_hw_spec },  /* RTL8814AE */
    { 0, nullptr }
};

/* Forward declaration of hw_callbacks struct from compat.c */
struct rtw88_hw_callbacks {
    void (*rx_frame)(void *kext_hw, struct sk_buff *skb);
    void (*tx_status)(void *kext_hw, struct sk_buff *skb);
    void (*scan_done)(void *kext_hw, bool aborted);
};

#define super OSObject
OSDefineMetaClassAndStructors(RTW88IEEE80211, OSObject)

/* ------------------------------------------------------------------ */
/*  Static compat callbacks                                             */
/* ------------------------------------------------------------------ */

void RTW88IEEE80211::compat_rx_frame(void *kext_hw, struct sk_buff *skb)
{
    RTW88IEEE80211 *self = (RTW88IEEE80211 *)kext_hw;
    if (self) self->rxFrame(skb);
}

void RTW88IEEE80211::compat_tx_status(void *kext_hw, struct sk_buff *skb)
{
    RTW88IEEE80211 *self = (RTW88IEEE80211 *)kext_hw;
    if (self) self->txStatus(skb);
    kfree_skb(skb);
}

void RTW88IEEE80211::compat_scan_done(void *kext_hw, bool aborted)
{
    RTW88IEEE80211 *self = (RTW88IEEE80211 *)kext_hw;
    if (self) self->scanDone(aborted);
}

/* ------------------------------------------------------------------ */
/*  Factory / init / free                                               */
/* ------------------------------------------------------------------ */

RTW88IEEE80211 *RTW88IEEE80211::create(RTW88PCIDevice *dev, struct pci_dev *pci)
{
    RTW88IEEE80211 *obj = new RTW88IEEE80211;
    if (obj && !obj->init(dev, pci)) {
        obj->release();
        return nullptr;
    }
    return obj;
}

bool RTW88IEEE80211::init(RTW88PCIDevice *dev, struct pci_dev *pci)
{
    if (!super::init()) return false;
    _parent = dev;
    _pcidev = pci;

    _lock    = IOLockAlloc();
    _bssLock = IOLockAlloc();
    if (!_lock || !_bssLock) return false;

    _connectTC = thread_call_allocate((thread_call_func_t)RTW88IEEE80211::connectTCFn,
                                       (thread_call_param_t)this);

    /* Install callbacks into compat layer */
    static struct rtw88_hw_callbacks cbs = {
        .rx_frame  = RTW88IEEE80211::compat_rx_frame,
        .tx_status = RTW88IEEE80211::compat_tx_status,
        .scan_done = RTW88IEEE80211::compat_scan_done,
    };
    rtw88_set_hw_callbacks(&cbs, this);

    /* Set up workloop / timer for state machine */
    _wl = IOWorkLoop::workLoop();
    if (!_wl) return false;

    _gate = IOCommandGate::commandGate(this);
    if (!_gate) return false;
    _wl->addEventSource(_gate);

    _timer = IOTimerEventSource::timerEventSource(this,
        &RTW88IEEE80211::timerFired);
    if (!_timer) return false;
    _wl->addEventSource(_timer);

    IOLog("rtw88: RTW88IEEE80211 initialized\n");
    return true;
}

void RTW88IEEE80211::free()
{
    if (_connectTC) { thread_call_cancel(_connectTC); thread_call_free(_connectTC); _connectTC = nullptr; }
    if (_timer)  { _wl->removeEventSource(_timer); _timer->release();  _timer = nullptr; }
    if (_gate)   { _wl->removeEventSource(_gate);  _gate->release();   _gate = nullptr; }
    if (_wl)     { _wl->release();   _wl = nullptr; }
    if (_lock)   { IOLockFree(_lock);    _lock = nullptr; }
    if (_bssLock){ IOLockFree(_bssLock); _bssLock = nullptr; }

    /* Free BSS list */
    RTW88BSS *b = _bssList;
    while (b) {
        RTW88BSS *n = b->next;
        IOFree(b, sizeof(*b));
        b = n;
    }
    _bssList = nullptr;
    super::free();
}

/* ------------------------------------------------------------------ */
/*  start / stop                                                        */
/* ------------------------------------------------------------------ */

IOReturn RTW88IEEE80211::start()
{
    RTW88_STAGE("IEEE80211::start entered");

    /* Look up chip info from PCI device ID */
    const struct rtw_chip_info *chip = nullptr;
    for (int i = 0; rtw88_pci_chip_table[i].device != 0; i++) {
        if (rtw88_pci_chip_table[i].device == _pcidev->device) {
            chip = rtw88_pci_chip_table[i].chip;
            break;
        }
    }
    if (!chip) {
        IOLog("rtw88: unknown PCI device %04x — cannot probe\n", _pcidev->device);
        return kIOReturnUnsupported;
    }
    RTW88_STAGE("chip matched: device=%04x", _pcidev->device);

    const struct pci_device_id fake_id = {
        .vendor      = _pcidev->vendor,
        .device      = _pcidev->device,
        .subvendor   = PCI_ANY_ID,
        .subdevice   = PCI_ANY_ID,
        .driver_data = (unsigned long)chip,
    };

    RTW88_STAGE("calling rtw_pci_probe");
    int ret = rtw_pci_probe(_pcidev, &fake_id);
    RTW88_STAGE("rtw_pci_probe returned %d", ret);
    if (ret != 0) {
        IOLog("rtw88: rtw_pci_probe failed: %d\n", ret);
        return kIOReturnError;
    }

    /* Use the hw pointer that ieee80211_alloc_hw() registered in the compat
     * layer via rtw88_register_hw().  rtw88_get_hw() is the external-linkage
     * accessor for the static g_rtw88_hw variable — avoids both the fragile
     * *(ieee80211_hw **)rtwdev double-dereference and the UB of declaring
     * 'extern' on a static variable from another TU. */
    _hw = rtw88_get_hw();

    /* rtwdev is hw->priv (allocated contiguously after ieee80211_hw in alloc_hw).
     * Note: rtw_pci_probe stores hw (not rtwdev) in pdev->driver_data via pci_set_drvdata(). */
    if (_hw) {
        _rtwdev = (struct rtw_dev *)_hw->priv;
    } else {
        _rtwdev = nullptr;
    }

    RTW88_STAGE("rtwdev=%p hw=%p", (void *)_rtwdev, (void *)_hw);

    /* Read MAC address — SET_IEEE80211_PERM_ADDR() copies EFuse MAC into
     * hw->wiphy->perm_addr during rtw_register_hw(); read it from there. */
    if (_hw && _hw->wiphy) {
        memcpy(_macAddr, _hw->wiphy->perm_addr, 6);
        IOLog("rtw88: MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
              _macAddr[0], _macAddr[1], _macAddr[2],
              _macAddr[3], _macAddr[4], _macAddr[5]);
    }

    /* Create virtual interface in the driver.
     * NOTE: _rtwdev must NOT be reassigned here. It has been correctly set from
     * _hw->priv above. */
    if (_hw) {
        RTW88_STAGE("adding STA interface");
        _vif = (struct ieee80211_vif *)IOMallocZero(
            sizeof(struct ieee80211_vif) + 128);
        if (_vif) {
            _vif->type = NL80211_IFTYPE_STATION;
            memcpy(_vif->addr, _macAddr, 6);
            if (_hw->ops && _hw->ops->add_interface)
                _hw->ops->add_interface(_hw, _vif);
        }
        RTW88_STAGE("add_interface done");

        RTW88_STAGE("calling hw->ops->start");
        if (_hw->ops && _hw->ops->start) {
            int ret = _hw->ops->start(_hw);
            RTW88_STAGE("hw->ops->start returned %d", ret);
            if (ret != 0) {
                IOLog("rtw88: hw->ops->start failed: %d\n", ret);
            }
        }
    }

    _state = RTW88_STATE_IDLE;
    RTW88_STAGE("IEEE80211::start complete — SUCCESS");
    return kIOReturnSuccess;
}

void RTW88IEEE80211::stop()
{
    IOLog("rtw88: IEEE80211 stop\n");
    _timer->cancelTimeout();

    if (_state == RTW88_STATE_CONNECTED) doDisconnect();

    if (_vif && _hw && _hw->ops) {
        if (_hw->ops->stop) {
            _hw->ops->stop(_hw, false);
        }
        if (_hw->ops->remove_interface) {
            _hw->ops->remove_interface(_hw, _vif);
        }
        IOFree(_vif, sizeof(*_vif) + 128);
        _vif = nullptr;
    }

    if (_pcidev) rtw_pci_remove(_pcidev);
    _rtwdev = nullptr;
    _hw     = nullptr;
    _state  = RTW88_STATE_IDLE;
}

/* ------------------------------------------------------------------ */
/*  Power on/off (called from enable/disable)                          */
/* ------------------------------------------------------------------ */

IOReturn RTW88IEEE80211::powerOn()
{
    IOLog("rtw88: IEEE80211 powerOn\n");
    if (!_rtwdev) return kIOReturnNotReady;
    int ret = rtw_core_start(_rtwdev);
    if (ret) {
        IOLog("rtw88: rtw_core_start failed: %d\n", ret);
        return kIOReturnError;
    }
    return kIOReturnSuccess;
}

void RTW88IEEE80211::powerOff()
{
    IOLog("rtw88: IEEE80211 powerOff\n");
    if (!_rtwdev) return;
    rtw_core_stop(_rtwdev);
}

/* ------------------------------------------------------------------ */
/*  Interrupt dispatch                                                  */
/* ------------------------------------------------------------------ */

extern "C" void rtw88_trigger_interrupt(void);

void RTW88IEEE80211::handleInterrupt()
{
    static int intr_cnt = 0;
    IOLog("rtw88: handling interrupt (count=%d) ENTER\n", intr_cnt);
    intr_cnt++;

    rtw88_trigger_interrupt();

    IOLog("rtw88: handling interrupt (count=%d) LEAVE\n", intr_cnt - 1);
}

/* ------------------------------------------------------------------ */
/*  TX path: Ethernet → 802.11 data frame                              */
/* ------------------------------------------------------------------ */

UInt32 RTW88IEEE80211::outputPacket(mbuf_t m)
{
    if (_state != RTW88_STATE_CONNECTED || !_rtwdev || !_hw || !_vif)
        goto drop;

    {
        struct sk_buff *skb = mbufToSkb(m);
        if (!skb) goto drop;

        /* Set up ieee80211_tx_info in skb->cb */
        struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
        memset(info, 0, sizeof(*info));
        info->flags  = IEEE80211_TX_CTL_FIRST_FRAGMENT;
        info->band   = NL80211_BAND_2GHZ; /* updated by channel */
        info->control.vif = _vif;
        info->control.sta = _sta;

        /* Submit to rtw88 driver */
        struct ieee80211_tx_control ctrl = { .sta = _sta };
        if (_hw->ops && _hw->ops->tx)
            _hw->ops->tx(_hw, &ctrl, skb);
        else {
            kfree_skb(skb);
            goto drop;
        }
        mbuf_freem(m); /* driver now owns skb; free original mbuf */
        return kIOReturnOutputSuccess;
    }

drop:
    mbuf_freem(m);
    return kIOReturnOutputDropped;
}

/* ------------------------------------------------------------------ */
/*  RX path: sk_buff from driver → mbuf to macOS                       */
/* ------------------------------------------------------------------ */

void RTW88IEEE80211::rxFrame(struct sk_buff *skb)
{
    if (!skb) return;

    struct ieee80211_rx_status *rxs = IEEE80211_SKB_RXCB(skb);
    _rssi = rxs->signal;

    struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
    __le16 fc = hdr->frame_control;

    /* Diagnostics: log a periodic sample of RX activity so we can confirm
     * whether the firmware is actually delivering frames during scan. */
    _rxFrameCount++;
    if (_state == RTW88_STATE_SCANNING && (_rxFrameCount % 16) == 1) {
        uint16_t fcv = le16_to_cpu(fc);
        IOLog("rtw88: rxFrame #%u (fc=0x%04x type=%u stype=0x%02x len=%u)\n",
              _rxFrameCount, fcv, (fcv >> 2) & 3, fcv & 0x00f0, skb->len);
    }

    if (ieee80211_is_mgmt(fc)) {
        processRxMgmt(skb);
    } else if (ieee80211_is_data(fc)) {
        processRxData(skb);
    } else {
        kfree_skb(skb);
    }
}

void RTW88IEEE80211::processRxMgmt(struct sk_buff *skb)
{
    struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
    __le16 fc = hdr->frame_control;
    uint16_t stype = le16_to_cpu(fc) & 0x00f0;

    switch (stype) {
    case 0x0080: /* beacon */
    case 0x0050: /* probe response */
        if (_state == RTW88_STATE_SCANNING)
            processScanResult(skb);
        else
            kfree_skb(skb);
        break;

    case 0x00B0: /* auth */
        if (_state == RTW88_STATE_AUTHENTICATING) {
            uint8_t *body = skb->data + sizeof(struct ieee80211_hdr_3addr);
            uint32_t body_len = skb->len - sizeof(struct ieee80211_hdr_3addr);
            /* auth body: algo(2), seq(2), status(2) */
            if (body_len >= 6) {
                uint16_t status = (uint16_t)(body[4] | (body[5] << 8));
                if (status == 0) {
                    IOLog("rtw88: auth success, sending assoc\n");
                    doAssociate();
                } else {
                    IOLog("rtw88: auth failed status=%u, retrying\n", status);
                    _state = RTW88_STATE_IDLE;
                }
            } else {
                doAssociate(); /* assume success */
            }
        }
        kfree_skb(skb);
        break;

    case 0x0010: /* assoc response */
        if (_state == RTW88_STATE_ASSOCIATING)
            processAssocResponse(skb);
        else
            kfree_skb(skb);
        break;

    case 0x0030: /* reassoc response */
        if (_state == RTW88_STATE_ASSOCIATING)
            processAssocResponse(skb);
        else
            kfree_skb(skb);
        break;

    case 0x00A0: /* disassoc */
    case 0x00C0: /* deauth */
        if (_state == RTW88_STATE_CONNECTED ||
            _state == RTW88_STATE_HANDSHAKING) {
            _state = RTW88_STATE_IDLE;
            if (_parent)
                _parent->setLinkStatus(kIONetworkLinkValid);
        }
        kfree_skb(skb);
        break;

    default:
        kfree_skb(skb);
        break;
    }
}

void RTW88IEEE80211::processScanResult(struct sk_buff *skb)
{
    if (!skb || skb->len < sizeof(struct ieee80211_hdr) + 12) {
        kfree_skb(skb);
        return;
    }

    /* Parse beacon/probe-resp minimal fields */
    const uint8_t *body = skb->data + sizeof(struct ieee80211_hdr_3addr);
    const uint8_t *end  = skb->data + skb->len;
    /* Skip: timestamp(8), beacon_int(2), capability(2) */
    body += 12;

    RTW88BSS *bss = (RTW88BSS *)IOMallocZero(sizeof(RTW88BSS));
    if (!bss) { kfree_skb(skb); return; }

    /* BSSID is addr3 in a beacon from AP */
    struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
    memcpy(bss->bssid, hdr->addr3, 6);

    /* Walk IEs */
    while (body + 2 <= end) {
        uint8_t id = body[0];
        uint8_t len = body[1];
        if (body + 2 + len > end) break;

        if (id == WLAN_EID_SSID && len > 0 && len <= 32) {
            memcpy(bss->ssid, body + 2, len);
            bss->ssid_len = len;
        } else if (id == WLAN_EID_DS_PARAMS && len >= 1) {
            bss->channel = body[2];
        } else if (id == WLAN_EID_RSN) {
            bss->cipher = WLAN_CIPHER_SUITE_CCMP;
            bss->akm    = 0x000FAC02; /* PSK */
        }

        /* Copy all IEs */
        uint16_t copy = (uint16_t)(2 + len);
        if (bss->ies_len + copy < sizeof(bss->ies)) {
            memcpy(bss->ies + bss->ies_len, body, copy);
            bss->ies_len += copy;
        }
        body += 2 + len;
    }

    struct ieee80211_rx_status *rxs = IEEE80211_SKB_RXCB(skb);
    bss->rssi = rxs->signal;
    bss->freq = rxs->freq;

    /* Add to BSS list (deduplicate by BSSID) */
    IOLockLock(_bssLock);
    for (RTW88BSS *e = _bssList; e; e = e->next) {
        if (memcmp(e->bssid, bss->bssid, 6) == 0) {
            /* Update existing */
            RTW88BSS *saved_next = e->next;
            memcpy(e, bss, sizeof(*bss));
            e->next = saved_next; /* preserve linkage */
            IOFree(bss, sizeof(*bss));
            IOLockUnlock(_bssLock);
            kfree_skb(skb);
            return;
        }
    }
    bss->next = _bssList;
    _bssList  = bss;
    _bssCount++;
    IOLockUnlock(_bssLock);

    kfree_skb(skb);
}

void RTW88IEEE80211::processRxData(struct sk_buff *skb)
{
    if (_state != RTW88_STATE_CONNECTED &&
        _state != RTW88_STATE_HANDSHAKING) {
        kfree_skb(skb);
        return;
    }

    /* Strip 802.11 header, add Ethernet header */
    struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
    uint16_t hdrlen = ieee80211_get_hdrlen_from_skb(skb);

    /* Check for LLC/SNAP */
    const uint8_t *llc = skb->data + hdrlen;
    if (skb->len < (uint32_t)(hdrlen + 8)) { kfree_skb(skb); return; }

    /* LLC SNAP: AA AA 03 00 00 00 ETHERTYPE */
    uint16_t ethertype = 0;
    if (llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03) {
        ethertype = (uint16_t)((llc[6] << 8) | llc[7]);
        /* Check for EAPOL during handshake */
        if (ethertype == ETH_P_PAE && _state == RTW88_STATE_HANDSHAKING) {
            handleEAPOL(llc + 8, skb->len - hdrlen - 8);
            kfree_skb(skb);
            return;
        }
    }

    /* Build Ethernet frame: [dst(6)][src(6)][ethertype(2)][payload] */
    uint32_t paylen = skb->len - hdrlen - 8; /* strip LLC/SNAP */
    uint32_t ethlen = 14 + paylen;

    /* Assemble the 14-byte Ethernet header into a small stack buffer, then
     * copy header+payload into the mbuf with mbuf_copyback().  We must use
     * copyback (not mbuf_data + memcpy): for large frames (A-MSDU can be
     * several KB) mbuf_allocpacket() returns a multi-segment chain, and a
     * raw memcpy of the whole packet into the first segment overflows the
     * mbuf zone and corrupts the kernel heap. */
    mbuf_t m = nullptr;
    if (mbuf_allocpacket(MBUF_WAITOK, ethlen, nullptr, &m) != 0) {
        kfree_skb(skb); return;
    }

    uint8_t ehdr[14];
    /* DA = addr1 (recipient), SA = addr3 (original source via DS) */
    memcpy(ehdr,     hdr->addr1, 6);  /* DA */
    memcpy(ehdr + 6, hdr->addr3, 6);  /* SA */
    ehdr[12] = (uint8_t)(ethertype >> 8);
    ehdr[13] = (uint8_t)(ethertype & 0xff);

    if (mbuf_copyback(m, 0,  14,     ehdr,    MBUF_WAITOK) != 0 ||
        mbuf_copyback(m, 14, paylen, llc + 8, MBUF_WAITOK) != 0) {
        mbuf_freem(m);
        kfree_skb(skb);
        return;
    }

    kfree_skb(skb);
    if (_parent) _parent->injectRxFrame(m);
}

/* ------------------------------------------------------------------ */
/*  TX status                                                           */
/* ------------------------------------------------------------------ */

void RTW88IEEE80211::txStatus(struct sk_buff *skb)
{
    /* Nothing to do — skb freed by caller */
}

/* ------------------------------------------------------------------ */
/*  Scan                                                                */
/* ------------------------------------------------------------------ */

void RTW88IEEE80211::scanDone(bool aborted)
{
    IOLog("rtw88: scan done (aborted=%d), found %u APs, "
          "saw %u RX frames during scan\n",
          aborted, _bssCount, _rxFrameCount);
    if (_state == RTW88_STATE_SCANNING)
        _state = RTW88_STATE_IDLE;
}

IOReturn RTW88IEEE80211::cmdScan()
{
    if (_state != RTW88_STATE_IDLE && _state != RTW88_STATE_SCANNING)
        return kIOReturnBusy;
    if (!_hw || !_hw->ops || !_hw->ops->hw_scan) return kIOReturnNotReady;

    /* Clear old results */
    IOLockLock(_bssLock);
    RTW88BSS *b = _bssList;
    while (b) { RTW88BSS *n = b->next; IOFree(b, sizeof(*b)); b = n; }
    _bssList  = nullptr;
    _bssCount = 0;
    IOLockUnlock(_bssLock);

    _state = RTW88_STATE_SCANNING;

    struct ieee80211_scan_request req = {};
    struct ieee80211_channel *chans[256];
    int n_chans = 0;
    
    if (_hw->wiphy) {
        for (int i = 0; i < NL80211_NUM_BANDS; i++) {
            struct ieee80211_supported_band *band = _hw->wiphy->bands[i];
            if (!band) continue;
            for (int j = 0; j < band->n_channels; j++) {
                if (n_chans < 256) {
                    /* Only scan enabled channels */
                    if (!(band->channels[j].flags & IEEE80211_CHAN_DISABLED)) {
                        chans[n_chans++] = &band->channels[j];
                    }
                }
            }
        }
    }
    
    req.req.channels = chans;
    req.req.n_channels = n_chans;

    _rxFrameCount = 0;  /* reset diagnostic counter at scan start */

    IOLog("rtw88: hw_scan starting -- %d channels (2.4G+5G)\n", n_chans);

    int hw_scan_ret = _hw->ops->hw_scan(_hw, _vif, &req);
    if (hw_scan_ret != 0) {
        IOLog("rtw88: hw_scan returned %d -- scan not started\n", hw_scan_ret);
        _state = RTW88_STATE_IDLE;
        return kIOReturnError;
    }
    /* Timeout: if scan doesn't complete in 10s */
    _timeoutMs = 10000;
    uint64_t d; clock_interval_to_deadline(_timeoutMs, kMillisecondScale, &d); _timer->wakeAtTime(d);
    return kIOReturnSuccess;
}

/* ------------------------------------------------------------------ */
/*  Connect                                                             */
/* ------------------------------------------------------------------ */

IOReturn RTW88IEEE80211::cmdConnect(const char *ssid, const char *password)
{
    if (_state != RTW88_STATE_IDLE) return kIOReturnBusy;
    if (!ssid) return kIOReturnBadArgument;

    /* Find the SSID in our BSS list */
    IOLockLock(_bssLock);
    RTW88BSS *target = nullptr;
    for (RTW88BSS *b = _bssList; b; b = b->next) {
        if (strlen(b->ssid) == strlen(ssid) &&
            memcmp(b->ssid, ssid, strlen(ssid)) == 0) {
            target = b;
            break;
        }
    }
    if (!target) {
        IOLockUnlock(_bssLock);
        return kIOReturnNotFound;
    }
    memcpy(&_targetBSS, target, sizeof(_targetBSS));
    IOLockUnlock(_bssLock);

    strlcpy(_password, password ? password : "", sizeof(_password));
    _wpa2 = (_targetBSS.cipher == WLAN_CIPHER_SUITE_CCMP);
    _state = RTW88_STATE_AUTHENTICATING;

    /* Run doAuthenticate on a background thread_call so the IOUserClient
     * call returns immediately.  The connect machinery (channel change,
     * mutex acquisition, TX) must not block the MIG thread. */
    if (_connectTC)
        thread_call_enter(_connectTC);
    return kIOReturnSuccess;
}

void RTW88IEEE80211::connectTCFn(thread_call_param_t self, thread_call_param_t)
{
    ((RTW88IEEE80211 *)self)->doAuthenticate();
}

void RTW88IEEE80211::doAuthenticate()
{
    if (!_hw || !_vif) return;

    IOLog("rtw88: doAuthenticate entry — BSSID %02x:%02x:%02x:%02x:%02x:%02x ch=%u\n",
          _targetBSS.bssid[0], _targetBSS.bssid[1], _targetBSS.bssid[2],
          _targetBSS.bssid[3], _targetBSS.bssid[4], _targetBSS.bssid[5],
          _targetBSS.channel);

    /* Wait for RTW_FLAG_SCANNING to clear.
     * The flag is cleared inside rtw_core_scan_complete() which runs under
     * rtwdev->mutex in the c2h_work thread. */
    for (int i = 0; i < 100; i++) {
        if (!rtw88_is_scanning()) break;
        IOSleep(50);
    }
    IOLog("rtw88: doAuthenticate: scan flag clear\n");

    /* Firmware settle delay.
     *
     * After HW scan the firmware needs ~200-500 ms to fully exit its
     * internal scan-mode critical section before it can safely process
     * channel-switch register writes.  On Linux/FreeBSD this gap is filled
     * naturally by the wpa_supplicant userspace round-trip; we must add it
     * explicitly.  Without this, rtw_set_channel's BB/RF MMIO reads hit the
     * chip while the firmware is still transitioning → PCIe bus hang →
     * system freeze.  500 ms is comfortably below the watch-dog LPS timer
     * (~2 s), so the chip stays awake. */
    IOSleep(500);
    IOLog("rtw88: doAuthenticate: firmware settled\n");

    /* ----- 1. Channel switch + BSSID (single mutex section) ----- *
     *
     * We call rtw88_connect_hw_setup() instead of ops->config +
     * ops->bss_info_changed because both of those call rtw_leave_lps_deep()
     * → __rtw_fw_leave_lps_check_reg() → polling MMIO reads on REG_TCR.
     * If the chip is slow to respond, those reads stall the calling CPU core
     * indefinitely (PCIe timeout → system freeze).
     *
     * rtw88_connect_hw_setup() holds rtwdev->mutex, calls rtw_set_channel()
     * (MMIO writes) and rtw_vif_port_config(PORT_SET_BSSID) — no reads that
     * can stall, and no LPS wake sequence. */
    struct ieee80211_channel *chan = nullptr;
    for (int b = 0; b < NL80211_NUM_BANDS && !chan; b++) {
        struct ieee80211_supported_band *band =
            (_hw->wiphy) ? _hw->wiphy->bands[b] : nullptr;
        if (!band) continue;
        for (int j = 0; j < band->n_channels; j++) {
            if (band->channels[j].hw_value == _targetBSS.channel) {
                chan = &band->channels[j];
                break;
            }
        }
    }
    if (chan) {
        _hw->conf.chandef.chan         = chan;
        _hw->conf.chandef.width        = NL80211_CHAN_WIDTH_20_NOHT;
        _hw->conf.chandef.center_freq1 = chan->center_freq;
        IOLog("rtw88: doAuthenticate: calling connect_hw_setup ch=%u\n",
              _targetBSS.channel);
        rtw88_connect_hw_setup(_hw, _vif, _targetBSS.bssid);
        IOLog("rtw88: doAuthenticate: connect_hw_setup done\n");
    } else {
        IOLog("rtw88: doAuthenticate: ch=%u not in band table — "
              "skipping channel switch, sending auth anyway\n",
              _targetBSS.channel);
        /* Still set BSSID even if channel is unknown */
        rtw88_connect_hw_setup(_hw, _vif, _targetBSS.bssid);
    }

    /* Also update the vif bss_conf bssid so any driver-internal code
     * that reads it sees the right value. */
    struct ieee80211_bss_conf *bss = &_vif->bss_conf;
    bss->bssid = bss->bssid_buf;
    memcpy(bss->bssid_buf, _targetBSS.bssid, 6);
    bss->assoc = false;
    bss->aid   = 0;

    /* ----- 2. Send Authentication frame ----- */
    IOLog("rtw88: doAuthenticate: building auth frame\n");
    uint8_t auth[30] = {};
    uint32_t authlen = 0;
    buildAuthReq(auth, &authlen);
    IOLog("rtw88: doAuthenticate: transmitting auth frame (%u bytes)\n", authlen);
    txMgmtFrame(auth, authlen);
    IOLog("rtw88: doAuthenticate: auth frame sent — waiting for response\n");

    _state = RTW88_STATE_AUTHENTICATING;
    uint64_t d; clock_interval_to_deadline(3000, kMillisecondScale, &d);
    _timer->wakeAtTime(d);
}

void RTW88IEEE80211::doAssociate()
{
    if (!_hw || !_vif) return;

    uint8_t assoc[256] = {};
    uint32_t assoclen  = 0;
    buildAssocReq(assoc, &assoclen);
    txMgmtFrame(assoc, assoclen);

    _state = RTW88_STATE_ASSOCIATING;
    uint64_t d; clock_interval_to_deadline(3000, kMillisecondScale, &d); _timer->wakeAtTime(d);
}

void RTW88IEEE80211::processAssocResponse(struct sk_buff *skb)
{
    /* Assoc-resp body (after 24-byte 802.11 hdr):
     * capability(2), status(2), AID(2), [IEs...] */
    const uint8_t *body    = skb->data + sizeof(struct ieee80211_hdr_3addr);
    uint32_t       bodylen = skb->len  - sizeof(struct ieee80211_hdr_3addr);
    kfree_skb(skb);

    if (bodylen < 6) {
        IOLog("rtw88: assoc-resp too short\n");
        _state = RTW88_STATE_IDLE;
        return;
    }
    uint16_t status = (uint16_t)(body[2] | (body[3] << 8));
    uint16_t aid    = (uint16_t)((body[4] | (body[5] << 8)) & 0x3FFF);

    if (status != 0) {
        IOLog("rtw88: assoc failed status=%u\n", status);
        _state = RTW88_STATE_IDLE;
        return;
    }
    IOLog("rtw88: associated! AID=%u\n", aid);
    _assocAID = aid;

    /* ----- 1. Allocate and register peer STA ----- */
    if (_sta == nullptr && _hw->ops && _hw->ops->sta_add) {
        size_t sta_sz = sizeof(struct ieee80211_sta) + _hw->sta_data_size;
        _sta = (struct ieee80211_sta *)IOMallocZero(sta_sz);
        if (_sta) {
            memcpy(_sta->addr, _targetBSS.bssid, ETH_ALEN);
            _sta->aid  = aid;
            _sta->wme  = false;
            _hw->ops->sta_add(_hw, _vif, _sta);
        }
    }

    /* ----- 2. Notify driver of full association ----- */
    if (_hw->ops && _hw->ops->bss_info_changed) {
        struct ieee80211_bss_conf *bss = &_vif->bss_conf;
        bss->assoc = true;
        bss->aid   = aid;
        bss->qos   = true;
        bss->bssid = bss->bssid_buf;
        _vif->cfg.assoc = true;
        _vif->cfg.aid   = aid;
        _hw->ops->bss_info_changed(_hw, _vif, bss,
            BSS_CHANGED_ASSOC | BSS_CHANGED_QOS);
    }

    if (_wpa2) {
        _state = RTW88_STATE_HANDSHAKING;
        IOLog("rtw88: WPA2 — waiting for EAPOL M1\n");
        /* Derive PMK from passphrase now */
        derivePMK((uint8_t *)_password, (uint8_t *)_targetBSS.ssid,
                  _targetBSS.ssid_len, _pmk);
    } else {
        _state = RTW88_STATE_CONNECTED;
        if (_parent)
            _parent->setLinkStatus(kIONetworkLinkActive | kIONetworkLinkValid);
    }
    _timer->cancelTimeout();
}

bool RTW88IEEE80211::buildAuthReq(uint8_t *buf, uint32_t *len)
{
    /* 802.11 Authentication frame (open system, seq 1) */
    struct ieee80211_hdr_3addr *hdr = (struct ieee80211_hdr_3addr *)buf;
    hdr->frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_AUTH);
    hdr->duration_id   = 0;
    memcpy(hdr->addr1, _targetBSS.bssid, 6);
    memcpy(hdr->addr2, _macAddr, 6);
    memcpy(hdr->addr3, _targetBSS.bssid, 6);
    hdr->seq_ctrl = cpu_to_le16((uint16_t)(_txSeq++ << 4));

    uint8_t *body = buf + sizeof(*hdr);
    /* Algorithm: 0 (Open), Transaction: 1, Status: 0 */
    body[0] = 0; body[1] = 0; /* algorithm */
    body[2] = 1; body[3] = 0; /* transaction seq */
    body[4] = 0; body[5] = 0; /* status code */
    *len = sizeof(*hdr) + 6;
    return true;
}

bool RTW88IEEE80211::buildAssocReq(uint8_t *buf, uint32_t *len)
{
    struct ieee80211_hdr_3addr *hdr = (struct ieee80211_hdr_3addr *)buf;
    hdr->frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_ASSOC_REQ);
    hdr->duration_id   = 0;
    memcpy(hdr->addr1, _targetBSS.bssid, 6);
    memcpy(hdr->addr2, _macAddr, 6);
    memcpy(hdr->addr3, _targetBSS.bssid, 6);
    hdr->seq_ctrl = cpu_to_le16((uint16_t)(_txSeq++ << 4));

    uint8_t *body = buf + sizeof(*hdr);
    /* Capability: ESS, Short Preamble */
    body[0] = 0x31; body[1] = 0x04;
    /* Listen interval: 10 */
    body[2] = 10; body[3] = 0;
    body += 4;

    /* SSID IE */
    body[0] = WLAN_EID_SSID;
    body[1] = (uint8_t)_targetBSS.ssid_len;
    memcpy(body + 2, _targetBSS.ssid, _targetBSS.ssid_len);
    body += 2 + _targetBSS.ssid_len;

    /* Supported rates: 1,2,5.5,11,6,9,12,18 Mbps */
    static const uint8_t rates[] = { 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24 };
    body[0] = WLAN_EID_SUPP_RATES;
    body[1] = sizeof(rates);
    memcpy(body + 2, rates, sizeof(rates));
    body += 2 + sizeof(rates);

    /* Copy RSN IE from beacon if WPA2 */
    if (_wpa2) {
        const uint8_t *ie = _targetBSS.ies;
        const uint8_t *end = ie + _targetBSS.ies_len;
        while (ie + 2 <= end) {
            if (ie[0] == WLAN_EID_RSN) {
                memcpy(body, ie, 2 + ie[1]);
                body += 2 + ie[1];
                break;
            }
            ie += 2 + ie[1];
        }
    }

    *len = (uint32_t)(body - buf);
    return true;
}

/* ------------------------------------------------------------------ */
/*  Disconnect                                                          */
/* ------------------------------------------------------------------ */

IOReturn RTW88IEEE80211::cmdDisconnect()
{
    if (_state == RTW88_STATE_IDLE) return kIOReturnSuccess;
    doDisconnect();
    return kIOReturnSuccess;
}

void RTW88IEEE80211::doDisconnect()
{
    if (!_hw || !_vif) { _state = RTW88_STATE_IDLE; return; }

    /* Send deauth frame */
    uint8_t deauth[28] = {};
    struct ieee80211_hdr_3addr *hdr = (struct ieee80211_hdr_3addr *)deauth;
    hdr->frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_DEAUTH);
    memcpy(hdr->addr1, _targetBSS.bssid, 6);
    memcpy(hdr->addr2, _macAddr, 6);
    memcpy(hdr->addr3, _targetBSS.bssid, 6);
    uint8_t *body = deauth + sizeof(*hdr);
    body[0] = WLAN_REASON_DEAUTH_LEAVING; body[1] = 0;
    txMgmtFrame(deauth, sizeof(*hdr) + 2);

    /* Notify driver */
    struct ieee80211_bss_conf *bss = &_vif->bss_conf;
    bss->assoc = false;
    if (_hw->ops && _hw->ops->bss_info_changed)
        _hw->ops->bss_info_changed(_hw, _vif, bss, BSS_CHANGED_ASSOC);

    _state = RTW88_STATE_IDLE;
    _timer->cancelTimeout();
    if (_parent)
        _parent->setLinkStatus(kIONetworkLinkValid);
}

/* ------------------------------------------------------------------ */
/*  WPA2 4-way handshake                                                */
/* ------------------------------------------------------------------ */

void RTW88IEEE80211::handleEAPOL(const uint8_t *data, uint32_t len)
{
    /* Minimal EAPOL-Key parser */
    if (len < 99) return;
    if (data[1] != 3) return; /* must be EAPOL-Key */

    uint16_t key_info = (uint16_t)((data[5] << 8) | data[6]);
    /* M1: Pairwise=1, ACK=1, MIC=0, Secure=0 */
    bool is_m1 = (key_info & 0x0108) == 0x0108 && !(key_info & 0x0200);
    /* M3: Pairwise=1, Install=1, ACK=1, MIC=1 */
    bool is_m3 = (key_info & 0x01C8) == 0x01C8 && (key_info & 0x0200);

    IOLog("rtw88: EAPOL key_info=0x%04x M1=%d M3=%d\n", key_info, is_m1, is_m3);

    if (is_m1) {
        /* data[17..48] = ANonce */
        memcpy(_anonce, data + 17, 32);
        /* Generate SNonce */
        read_random(_snonce, 32);
        /* Derive PTK from PMK + ANonce + SNonce + MACs */
        derivePTK(_pmk, _anonce, _snonce, _macAddr, _targetBSS.bssid, _ptk);
        /* Send M2 with MIC */
        memcpy(_replayCtr, data + 9, 8);
        sendEAPOLKey(2, _replayCtr, false, false, true);
    } else if (is_m3) {
        /* Update replay counter and send M4 */
        memcpy(_replayCtr, data + 9, 8);
        sendEAPOLKey(4, _replayCtr, false, false, true);

        /* Install PTK (TK is bytes 32..47 of PTK for CCMP) */
        if (_hw && _hw->ops && _hw->ops->set_key) {
            struct ieee80211_key_conf *key =
                (struct ieee80211_key_conf *)IOMallocZero(
                    sizeof(struct ieee80211_key_conf));
            if (key) {
                key->cipher   = WLAN_CIPHER_SUITE_CCMP;
                key->keyidx   = 0;
                key->flags    = IEEE80211_KEY_FLAG_PAIRWISE;
                key->keylen   = 16;
                memcpy(key->key, _ptk + 32, 16); /* TK */
                _hw->ops->set_key(_hw, SET_KEY, _vif, _sta, key);
                IOFree(key, sizeof(*key));
                IOLog("rtw88: PTK installed\n");
            }
        }
        _state = RTW88_STATE_CONNECTED;
        if (_parent)
            _parent->setLinkStatus(kIONetworkLinkActive | kIONetworkLinkValid);
        IOLog("rtw88: WPA2 connected!\n");
    }
}

void RTW88IEEE80211::sendEAPOLKey(int step, const uint8_t *replay_counter,
                                    bool install, bool ack, bool mic)
{
    /* Build minimal EAPOL-Key response frame (Ethernet wrapped) */
    /* 14 (eth hdr) + 4 (EAPOL hdr) + 95 (EAPOL-Key) */
    uint8_t frame[200] = {};
    uint8_t *eth = frame;
    memcpy(eth,     _targetBSS.bssid, 6); /* DA = AP */
    memcpy(eth + 6, _macAddr, 6);          /* SA = us */
    eth[12] = 0x88; eth[13] = 0x8e;        /* EAPOL ethertype */

    uint8_t *eapol = eth + 14;
    eapol[0] = 2;  /* version 2 */
    eapol[1] = 3;  /* EAPOL-Key */
    eapol[2] = 0; eapol[3] = 95; /* length */

    uint8_t *key = eapol + 4;
    key[0] = 2;  /* key descriptor = RSN */
    uint16_t ki = 0x000A; /* version=2 (HMAC-SHA1/AES), pairwise */
    if (mic)     ki |= 0x0100; /* MIC */
    if (install) ki |= 0x0040; /* Install */
    if (ack)     ki |= 0x0080; /* ACK */
    if (step == 4) ki |= 0x0200; /* Secure (bit 9) */
    key[1] = (uint8_t)(ki >> 8);
    key[2] = (uint8_t)(ki & 0xff);
    key[3] = 0; key[4] = 16; /* key length = 16 (AES-128) */
    memcpy(key + 5, replay_counter, 8);  /* key[5..12]  = Replay Counter */
    memcpy(key + 13, _snonce, 32);       /* key[13..44] = SNonce */
    /* key[45..60] = Key IV (zeros), key[61..68] = RSC (zeros) */
    /* key[69..76] = Reserved (zeros), key[77..92] = MIC (below) */
    /* key[93..94] = Key Data Length = 0 (zeros) */

    if (mic) {
        /* MIC = first 16 bytes of HMAC-SHA1(KCK, EAPOL frame with MIC zeroed)
         * KCK = _ptk[0..15]; EAPOL frame starts at eapol[0], length = 4+95 = 99 */
        uint8_t mic_buf[20];
        kern_hmac_sha1(_ptk, 16, eapol, 4 + 95, mic_buf);
        memcpy(key + 77, mic_buf, 16);
    }

    /* Transmit as 802.11 data frame */
    uint32_t ethlen = 14 + 4 + 95; /* eth(14) + EAPOL header(4) + EAPOL-Key body(95) */
    mbuf_t m = rtw88_make_packet_mbuf(frame, ethlen);
    if (!m) return;
    txDataFrame(m);
}

/* ------------------------------------------------------------------ */
/*  Frame TX helpers                                                    */
/* ------------------------------------------------------------------ */

bool RTW88IEEE80211::txMgmtFrame(const uint8_t *frame, uint32_t len)
{
    if (!_hw || !_hw->ops || !_hw->ops->tx) return false;

    struct sk_buff *skb = alloc_skb(len + 64, GFP_ATOMIC);
    if (!skb) return false;
    skb_reserve(skb, 128); /* headroom for TX descriptor (48 B) + pkt_offset padding */
    skb_put_data(skb, frame, len);

    struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
    memset(info, 0, sizeof(*info));
    info->flags  = IEEE80211_TX_CTL_FIRST_FRAGMENT | IEEE80211_TX_CTL_NO_ACK;
    info->control.vif = _vif;

    struct ieee80211_tx_control ctrl = { .sta = nullptr };
    _hw->ops->tx(_hw, &ctrl, skb);
    return true;
}

bool RTW88IEEE80211::txDataFrame(mbuf_t m)
{
    if (!_hw || !_hw->ops || !_hw->ops->tx || !_vif) {
        mbuf_freem(m);
        return false;
    }
    struct sk_buff *skb = mbufToSkb(m);
    if (!skb) { mbuf_freem(m); return false; }

    struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
    memset(info, 0, sizeof(*info));
    info->flags  = IEEE80211_TX_CTL_FIRST_FRAGMENT;
    info->control.vif = _vif;
    info->control.sta = _sta;

    struct ieee80211_tx_control ctrl = { .sta = _sta };
    _hw->ops->tx(_hw, &ctrl, skb);
    mbuf_freem(m);
    return true;
}

/* ------------------------------------------------------------------ */
/*  mbuf ↔ sk_buff conversion                                           */
/* ------------------------------------------------------------------ */

/*
 * Allocate a packet-header mbuf and copy `len` bytes from `src` into it.
 *
 * IMPORTANT: mbuf_allocpacket() may return a *chain* of mbufs (multiple
 * ~2 KB clusters) for packets larger than one cluster — e.g. A-MSDU
 * aggregated 802.11 data frames, which can be several KB.  In that case
 * mbuf_data(m) points only at the FIRST segment, and writing the whole
 * packet there overflows into adjacent kernel/mbuf-zone memory, corrupting
 * the heap (later manifesting as a GP fault in an unrelated mbuf walk such
 * as sbconcat_mbufs).
 *
 * mbuf_copyback() correctly distributes the data across every segment of
 * the chain and never overflows, so we use it instead of a raw memcpy.
 * mbuf_allocpacket() already sets each segment's length and pkthdr.len, so
 * we must NOT call mbuf_setlen() (which would wrongly set the first
 * segment's length to the whole-packet length).
 */
static mbuf_t rtw88_make_packet_mbuf(const void *src, uint32_t len)
{
    mbuf_t m = nullptr;
    if (mbuf_allocpacket(MBUF_WAITOK, len, nullptr, &m) != 0)
        return nullptr;
    if (mbuf_copyback(m, 0, len, src, MBUF_WAITOK) != 0) {
        mbuf_freem(m);
        return nullptr;
    }
    return m;
}

struct sk_buff *RTW88IEEE80211::mbufToSkb(mbuf_t m)
{
    size_t total = mbuf_pkthdr_len(m);
    struct sk_buff *skb = alloc_skb((uint32_t)(total + 64), GFP_ATOMIC);
    if (!skb) return nullptr;
    skb_reserve(skb, 128); /* headroom for TX descriptor (48 B) + pkt_offset padding */

    /* Copy contiguous mbuf chain data */
    mbuf_t cur = m;
    while (cur) {
        size_t chunk = mbuf_len(cur);
        if (chunk > 0) {
            memcpy(skb_put(skb, (uint32_t)chunk), mbuf_data(cur), chunk);
        }
        cur = mbuf_next(cur);
    }
    return skb;
}

mbuf_t RTW88IEEE80211::skbToMbuf(struct sk_buff *skb)
{
    return rtw88_make_packet_mbuf(skb->data, skb->len);
}

/* ------------------------------------------------------------------ */
/*  Timer (state machine timeout)                                       */
/* ------------------------------------------------------------------ */

void RTW88IEEE80211::timerFired(OSObject *owner, IOTimerEventSource *timer)
{
    RTW88IEEE80211 *self = OSDynamicCast(RTW88IEEE80211, owner);
    if (self) self->onTimer();
}

void RTW88IEEE80211::onTimer()
{
    switch (_state) {
    case RTW88_STATE_SCANNING:
        IOLog("rtw88: scan timeout\n");
        if (_hw && _hw->ops && _hw->ops->cancel_hw_scan)
            _hw->ops->cancel_hw_scan(_hw, _vif);
        _state = RTW88_STATE_IDLE;
        break;

    case RTW88_STATE_AUTHENTICATING:
        IOLog("rtw88: auth timeout, retrying\n");
        doAuthenticate();
        break;

    case RTW88_STATE_ASSOCIATING:
        IOLog("rtw88: assoc timeout\n");
        _state = RTW88_STATE_IDLE;
        break;

    case RTW88_STATE_HANDSHAKING:
        IOLog("rtw88: 4-way handshake timeout\n");
        _state = RTW88_STATE_IDLE;
        break;

    default:
        break;
    }
}

/* ------------------------------------------------------------------ */
/*  Status queries                                                       */
/* ------------------------------------------------------------------ */

IOReturn RTW88IEEE80211::cmdGetState(struct RTW88StateResult *result)
{
    if (!result) return kIOReturnBadArgument;

    result->state = _state;
    result->rssi = _rssi;
    memcpy(result->ssid, _targetBSS.ssid, sizeof(result->ssid));
    memcpy(result->bssid, _targetBSS.bssid, sizeof(result->bssid));
    result->channel = _targetBSS.channel;
    
    memcpy(result->mac_addr, _macAddr, 6);

    rtw88_get_fw_version(_rtwdev, &result->fw_version, &result->fw_sub_version);
    rtw88_get_chip_name(_rtwdev, result->chip_name, sizeof(result->chip_name));
    rtw88_get_stats(_rtwdev, &result->tx_byte_count, &result->rx_byte_count);

    return kIOReturnSuccess;
}

IOReturn RTW88IEEE80211::cmdGetRSSI(int *rssi)
{
    *rssi = _rssi;
    return kIOReturnSuccess;
}

IOReturn RTW88IEEE80211::cmdGetBSSList(uint8_t *buf, uint32_t *len)
{
    if (!buf || !len) return kIOReturnBadArgument;

    uint32_t max     = *len;
    if (max > 4095) max = 4095;

    if (max < 4) {
        *len = 0;
        return kIOReturnSuccess;
    }
    
    uint32_t written = 4; // reserve first 4 bytes for total length

    IOLockLock(_bssLock);
    IOLog("rtw88: cmdGetBSSList: _bssCount=%u _bssList=%p\n",
          _bssCount, (void *)_bssList);
    for (RTW88BSS *b = _bssList; b; b = b->next) {
        /* Each entry: ssid_len(1), ssid(ssid_len), bssid(6), rssi(2),
         *             channel(1), cipher(4) */
        uint32_t entry_sz = 1 + b->ssid_len + 6 + 2 + 1 + 4;
        IOLog("rtw88: BSS entry: ssid_len=%u ssid='%.32s' bssid=%02x:%02x:%02x:%02x:%02x:%02x "
              "rssi=%d ch=%u cipher=0x%08x entry_sz=%u\n",
              b->ssid_len, b->ssid,
              b->bssid[0], b->bssid[1], b->bssid[2],
              b->bssid[3], b->bssid[4], b->bssid[5],
              (int)b->rssi, b->channel, b->cipher, entry_sz);
        if (written + entry_sz > max) {
            IOLog("rtw88: BSS entry skipped (buffer full: written=%u max=%u)\n", written, max);
            break;
        }

        buf[written++] = b->ssid_len;
        memcpy(buf + written, b->ssid, b->ssid_len); written += b->ssid_len;
        memcpy(buf + written, b->bssid, 6);           written += 6;
        buf[written++] = (uint8_t)((b->rssi >> 8) & 0xff);
        buf[written++] = (uint8_t)(b->rssi & 0xff);
        buf[written++] = b->channel;
        memcpy(buf + written, &b->cipher, 4);          written += 4;
    }
    IOLockUnlock(_bssLock);
    IOLog("rtw88: cmdGetBSSList: written=%u total bytes\n", written);

    /* Write total written bytes into the first 4 bytes */
    uint32_t total = written;
    memcpy(buf, &total, sizeof(total));

    *len = written;
    return kIOReturnSuccess;
}

void RTW88IEEE80211::getMACAddress(uint8_t *mac)
{
    memcpy(mac, _macAddr, 6);
}
