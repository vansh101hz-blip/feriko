// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// RTW88IEEE80211.cpp — 802.11 state machine

#include "RTW88IEEE80211.hpp"
#include "RTW88PCIDevice.hpp"

#include <IOKit/IOLib.h>
#include <IOKit/IOService.h>
#include <sys/mbuf.h>
#include <string.h>
#include <sys/random.h>

/* Debug stage checkpoint — logs message and pauses so verbose output
 * is readable before the next stage runs or a panic occurs. */
#define RTW88_STAGE(fmt, ...) do { \
    IOLog("rtw88: ---- STAGE: " fmt " ----\n", ##__VA_ARGS__); \
    IOSleep(1500); \
} while (0)

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

    /* rtw_pci_probe stores rtwdev in pdev->driver_data */
    _rtwdev = (struct rtw_dev *)_pcidev->driver_data;
    _hw     = _rtwdev ? *(struct ieee80211_hw **)_rtwdev : nullptr;

    RTW88_STAGE("rtwdev=%p hw=%p", (void *)_rtwdev, (void *)_hw);

    /* Read MAC address — rtw_register_hw copies it to wiphy->perm_addr
     * via SET_IEEE80211_PERM_ADDR, so read from there after probe. */
    if (_hw && _hw->wiphy) {
        memcpy(_macAddr, _hw->wiphy->perm_addr, 6);
        IOLog("rtw88: MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
              _macAddr[0], _macAddr[1], _macAddr[2],
              _macAddr[3], _macAddr[4], _macAddr[5]);
    }

    /* Create virtual interface in the driver */
    if (_hw && _hw->priv) {
        _rtwdev = (struct rtw_dev *)_hw->priv;
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

    if (_vif && _hw && _hw->ops && _hw->ops->remove_interface) {
        _hw->ops->remove_interface(_hw, _vif);
        IOFree(_vif, sizeof(*_vif) + 128);
        _vif = nullptr;
    }

    if (_pcidev) rtw_pci_remove(_pcidev);
    _rtwdev = nullptr;
    _hw     = nullptr;
    _state  = RTW88_STATE_IDLE;
}

/* ------------------------------------------------------------------ */
/*  Interrupt dispatch                                                  */
/* ------------------------------------------------------------------ */

void RTW88IEEE80211::handleInterrupt()
{
    /* The Linux driver's interrupt handler is registered through the
     * pci.c rtw_pci_interrupt_handler; it was set up during probe.
     * We trigger it by invoking the kext interrupt dispatch here.
     *
     * In the real implementation this is wired via IOInterruptEventSource
     * directly to the Linux handler.  For now dispatch via a workqueue
     * to be safe (the Linux handler may sleep).
     */
    /* NOTE: actual IRQ routing is set up in pci.c via rtw_pci_napi_start */
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
        if (_state == RTW88_STATE_AUTHENTICATING)
            doAssociate();
        kfree_skb(skb);
        break;

    case 0x0010: /* assoc response */
        if (_state == RTW88_STATE_ASSOCIATING) {
            if (_wpa2)
                _state = RTW88_STATE_HANDSHAKING;
            else
                _state = RTW88_STATE_CONNECTED;
        }
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
            memcpy(e, bss, sizeof(*bss));
            e->next = e->next; /* preserve linkage */
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

    mbuf_t m = nullptr;
    if (mbuf_allocpacket(MBUF_WAITOK, ethlen, nullptr, &m) != 0) {
        kfree_skb(skb); return;
    }
    mbuf_setlen(m, ethlen);
    mbuf_pkthdr_setlen(m, ethlen);

    uint8_t *eth = (uint8_t *)mbuf_data(m);
    /* DA = addr1 (recipient), SA = addr2 or addr3 depending on DS bits */
    memcpy(eth,     hdr->addr1, 6);  /* DA */
    memcpy(eth + 6, hdr->addr3, 6);  /* SA */
    eth[12] = (uint8_t)(ethertype >> 8);
    eth[13] = (uint8_t)(ethertype & 0xff);
    memcpy(eth + 14, llc + 8, paylen);

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
    IOLog("rtw88: scan done (aborted=%d), found %u APs\n", aborted, _bssCount);
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
    /* Scan all channels — channels array NULL means "scan all" in our shim */
    if (_hw->ops->hw_scan(_hw, _vif, &req) != 0) {
        _state = RTW88_STATE_IDLE;
        return kIOReturnError;
    }
    /* Timeout: if scan doesn't complete in 10s */
    _timeoutMs = 10000;
    _timer->setTimeoutMS(_timeoutMs);
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

    doAuthenticate();
    return kIOReturnSuccess;
}

void RTW88IEEE80211::doAuthenticate()
{
    if (!_hw || !_vif) return;

    /* Configure BSS parameters */
    struct ieee80211_bss_conf *bss = &_vif->bss_conf;
    bss->bssid = bss->bssid_buf;
    memcpy(bss->bssid_buf, _targetBSS.bssid, 6);
    bss->assoc  = false;

    uint64_t changed = BSS_CHANGED_BSSID;
    if (_hw->ops && _hw->ops->bss_info_changed)
        _hw->ops->bss_info_changed(_hw, _vif, bss, changed);

    /* Build and send Authentication frame */
    uint8_t auth[30] = {};
    uint32_t authlen = 0;
    buildAuthReq(auth, &authlen);
    txMgmtFrame(auth, authlen);

    _state = RTW88_STATE_AUTHENTICATING;
    _timer->setTimeoutMS(3000);
}

void RTW88IEEE80211::doAssociate()
{
    if (!_hw || !_vif) return;

    uint8_t assoc[256] = {};
    uint32_t assoclen  = 0;
    buildAssocReq(assoc, &assoclen);
    txMgmtFrame(assoc, assoclen);

    _state = RTW88_STATE_ASSOCIATING;
    _timer->setTimeoutMS(3000);
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
    /* Minimal EAPOL-Key parser: just log and respond */
    if (len < 99) return;
    /* data[0] = version, data[1] = type (3=key), data[2:3] = length */
    if (data[1] != 3) return;

    uint16_t key_info = (uint16_t)((data[5] << 8) | data[6]);
    int msg = 0;
    /* Bit 8 = ACK, bit 9 = Install, bit 13 = MIC */
    if ((key_info & 0x0100) && !(key_info & 0x0200)) msg = 1; /* M1 */
    if ((key_info & 0x2000) && !(key_info & 0x0100)) msg = 2; /* M2 ack? no */
    if ((key_info & 0x0300) == 0x0300) msg = 3;               /* M3 */

    IOLog("rtw88: EAPOL key_info=0x%04x msg=%d\n", key_info, msg);

    if (msg == 1) {
        /* Copy ANonce from offset 17 */
        memcpy(_anonce, data + 17, 32);
        /* Generate SNonce */
        read_random(_snonce, 32);
        /* Send M2 */
        sendEAPOLKey(2, data + 9, false, false, true);
    } else if (msg == 3) {
        /* Copy replay counter, install PTK, send M4 */
        memcpy(_replayCtr, data + 9, 8);
        sendEAPOLKey(4, _replayCtr, true, false, true);
        /* Install GTK via set_key */
        _state = RTW88_STATE_CONNECTED;
        if (_parent)
            _parent->setLinkStatus(kIONetworkLinkActive | kIONetworkLinkValid);
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
    uint16_t ki = 0x010A; /* pairwise, HMAC-SHA1 */
    if (mic)     ki |= 0x0100;
    if (install) ki |= 0x0040;
    if (ack)     ki |= 0x0080;
    if (step == 4) ki |= 0x2000; /* Secure */
    key[1] = (uint8_t)(ki >> 8);
    key[2] = (uint8_t)(ki & 0xff);
    key[3] = 0; key[4] = 16; /* key length = 16 (AES) */
    memcpy(key + 5, replay_counter, 8);
    memcpy(key + 13, _snonce, 32); /* SNonce */
    /* MIC field at key+77 — compute later; zero for now */
    key[45] = 0; key[46] = 0; /* key data length */

    /* Transmit as 802.11 data frame */
    mbuf_t m = nullptr;
    uint32_t ethlen = 14 + 4 + 99;
    if (mbuf_allocpacket(MBUF_WAITOK, ethlen, nullptr, &m) != 0) return;
    mbuf_setlen(m, ethlen);
    mbuf_pkthdr_setlen(m, ethlen);
    memcpy(mbuf_data(m), frame, ethlen);
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
    skb_reserve(skb, 32); /* headroom for TX descriptor */
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

struct sk_buff *RTW88IEEE80211::mbufToSkb(mbuf_t m)
{
    size_t total = mbuf_pkthdr_len(m);
    struct sk_buff *skb = alloc_skb((uint32_t)(total + 64), GFP_ATOMIC);
    if (!skb) return nullptr;
    skb_reserve(skb, 32);

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
    mbuf_t m = nullptr;
    if (mbuf_allocpacket(MBUF_WAITOK, skb->len, nullptr, &m) != 0)
        return nullptr;
    mbuf_setlen(m, skb->len);
    mbuf_pkthdr_setlen(m, skb->len);
    memcpy(mbuf_data(m), skb->data, skb->len);
    return m;
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

IOReturn RTW88IEEE80211::cmdGetState(RTW88State *state)
{
    *state = _state;
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

    uint32_t written = 0;
    uint32_t max     = *len;

    IOLockLock(_bssLock);
    for (RTW88BSS *b = _bssList; b; b = b->next) {
        /* Each entry: ssid_len(1), ssid(ssid_len), bssid(6), rssi(2),
         *             channel(1), cipher(4) = variable */
        uint32_t entry_sz = 1 + b->ssid_len + 6 + 2 + 1 + 4;
        if (written + entry_sz > max) break;

        buf[written++] = b->ssid_len;
        memcpy(buf + written, b->ssid, b->ssid_len); written += b->ssid_len;
        memcpy(buf + written, b->bssid, 6);           written += 6;
        buf[written++] = (uint8_t)((b->rssi >> 8) & 0xff);
        buf[written++] = (uint8_t)(b->rssi & 0xff);
        buf[written++] = b->channel;
        memcpy(buf + written, &b->cipher, 4);          written += 4;
    }
    IOLockUnlock(_bssLock);

    *len = written;
    return kIOReturnSuccess;
}

void RTW88IEEE80211::getMACAddress(uint8_t *mac)
{
    memcpy(mac, _macAddr, 6);
}
