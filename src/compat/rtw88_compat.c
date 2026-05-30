// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Compatibility layer implementation for rtw88 macOS port.
// Compiled as C with -mkernel; no userspace headers allowed.

#include "rtw88_compat.h"
#include <stdarg.h>

/* ------------------------------------------------------------------ */
/*  Logging                                                             */
/* ------------------------------------------------------------------ */

int rtw88_log_level = KERN_DEBUG;

struct task_struct *__rtw88_current_task = NULL;

void rtw88_printk(int level, const char *fmt, ...)
{
    if (level > rtw88_log_level) return;

    static const char * const level_str[] = { "ERR", "WARN", "INFO", "DBG" };
    const char *ls = (level >= 0 && level <= 3) ? level_str[level] : "???";

    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    IOLog("[rtw88 %s] %s", ls, buf);
}

void rtw88_dev_printk(int level, struct device *dev, const char *fmt, ...)
{
    if (level > rtw88_log_level) return;

    static const char * const level_str[] = { "ERR", "WARN", "INFO", "DBG" };
    const char *ls = (level >= 0 && level <= 3) ? level_str[level] : "???";
    const char *name = dev ? (dev->name ? dev->name : "?") : "?";

    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    IOLog("[rtw88 %s %s] %s", ls, name, buf);
    /* Pause on errors so the message is readable before any subsequent crash */
    if (level == KERN_ERR) IOSleep(2000);
}

void rtw88_hex_dump(const char *prefix, const void *buf, size_t len)
{
    const u8 *p = (const u8 *)buf;
    IOLog("[rtw88] %s (%zu bytes):\n", prefix, len);
    for (size_t i = 0; i < len; i += 16) {
        char line[80];
        int pos = 0;
        pos += snprintf(line + pos, (int)(sizeof(line) - pos), "  %04zx: ", i);
        for (size_t j = i; j < i + 16 && j < len; j++)
            pos += snprintf(line + pos, (int)(sizeof(line) - pos), "%02x ", p[j]);
        IOLog("%s\n", line);
    }
}

/* ------------------------------------------------------------------ */
/*  Symbols not exported by macOS 15+ KPIs — provided internally       */
/* ------------------------------------------------------------------ */

/* fls: declared extern in MacKernelSDK libkern.h but not KPI-exported */
int fls(unsigned int x)
{
    return x ? (32 - __builtin_clz(x)) : 0;
}

/* thread_call_cancel_wait: not exported; cancel without waiting is safe here */
int thread_call_cancel_wait(thread_call_t call)
{
    return thread_call_cancel(call);
}

/* ------------------------------------------------------------------ */
/*  Global DMA / PCI / USB ops pointers                                 */
/* ------------------------------------------------------------------ */

struct rtw88_dma_alloc_ops *rtw88_dma_ops      = NULL;
struct pci_ops_rtw88       *rtw88_pci_io_ops   = NULL;
struct rtw88_usb_ops       *rtw88_usb_io_ops   = NULL;

/* ------------------------------------------------------------------ */
/*  Workqueue implementation (kernel threads + IOLock)                  */
/* ------------------------------------------------------------------ */

struct workqueue_struct *system_wq      = NULL;
struct workqueue_struct *system_long_wq = NULL;

static void wq_thread_fn(void *arg, wait_result_t wr)
{
    struct workqueue_struct *wq = (struct workqueue_struct *)arg;

    IOLockLock(wq->lock);
    while (wq->running || !list_empty(&wq->queue)) {
        if (list_empty(&wq->queue)) {
            IOLockSleep(wq->lock, &wq->queue, THREAD_UNINT);
            continue;
        }
        struct work_struct *work = container_of(wq->queue.next,
                                                struct work_struct, entry);
        list_del(&work->entry);
        work->pending = 0;
        IOLockUnlock(wq->lock);
        if (work->func) work->func(work);
        IOLockLock(wq->lock);
    }

    wq->done = 1;
    IOLockWakeup(wq->lock, &wq->done, false);
    IOLockUnlock(wq->lock);
    thread_terminate(current_thread());
}

struct workqueue_struct *alloc_workqueue(const char *name, unsigned int flags,
                                          int max_active)
{
    struct workqueue_struct *wq =
        (struct workqueue_struct *)IOMalloc(sizeof(*wq));
    if (!wq) return NULL;
    bzero(wq, sizeof(*wq));
    strlcpy(wq->name, name ? name : "wq", sizeof(wq->name));
    INIT_LIST_HEAD(&wq->queue);
    wq->lock    = IOLockAlloc();
    wq->running = 1;
    wq->done    = 0;
    if (!wq->lock) { IOFree(wq, sizeof(*wq)); return NULL; }

    kern_return_t kr = kernel_thread_start(wq_thread_fn, wq, &wq->thread);
    if (kr != KERN_SUCCESS) {
        IOLockFree(wq->lock);
        IOFree(wq, sizeof(*wq));
        return NULL;
    }
    thread_deallocate(wq->thread);
    return wq;
}

struct workqueue_struct *alloc_ordered_workqueue(const char *name,
                                                  unsigned int flags)
{
    return alloc_workqueue(name, flags, 1);
}

void destroy_workqueue(struct workqueue_struct *wq)
{
    if (!wq) return;
    IOLockLock(wq->lock);
    wq->running = 0;
    IOLockWakeup(wq->lock, &wq->queue, false);
    while (!wq->done)
        IOLockSleep(wq->lock, &wq->done, THREAD_UNINT);
    IOLockUnlock(wq->lock);
    IOLockFree(wq->lock);
    IOFree(wq, sizeof(*wq));
}

bool queue_work(struct workqueue_struct *wq, struct work_struct *work)
{
    if (!wq || !work) return false;
    IOLockLock(wq->lock);
    if (work->pending) {
        IOLockUnlock(wq->lock);
        return false;
    }
    work->pending = 1;
    list_add_tail(&work->entry, &wq->queue);
    IOLockWakeup(wq->lock, &wq->queue, false);
    IOLockUnlock(wq->lock);
    return true;
}

bool schedule_work(struct work_struct *work)
{
    return queue_work(system_wq, work);
}

/* Timer callback that dispatches a delayed_work to its workqueue */
static void delayed_work_timer_fn(struct timer_list *t)
{
    struct delayed_work *dwork = from_timer(dwork, t, timer);
    queue_work(system_wq, &dwork->work);
}

bool queue_delayed_work(struct workqueue_struct *wq,
                         struct delayed_work *dwork, unsigned long delay)
{
    if (!wq || !dwork) return false;
    if (delay == 0)
        return queue_work(wq, &dwork->work);
    timer_setup(&dwork->timer, delayed_work_timer_fn, 0);
    mod_timer(&dwork->timer, jiffies + delay);
    return true;
}

bool schedule_delayed_work(struct delayed_work *dwork, unsigned long delay)
{
    return queue_delayed_work(system_wq, dwork, delay);
}

void flush_workqueue(struct workqueue_struct *wq)
{
    if (!wq) return;
    for (int i = 0; i < 1000; i++) {
        IOLockLock(wq->lock);
        int empty = list_empty(&wq->queue);
        IOLockUnlock(wq->lock);
        if (empty) break;
        IOSleep(5);
    }
}

bool cancel_work_sync(struct work_struct *work)
{
    work->pending = 0;
    return true;
}

bool cancel_delayed_work_sync(struct delayed_work *dwork)
{
    del_timer_sync(&dwork->timer);
    return cancel_work_sync(&dwork->work);
}

bool cancel_delayed_work(struct delayed_work *dwork)
{
    del_timer(&dwork->timer);
    dwork->work.pending = 0;
    return true;
}

void flush_work(struct work_struct *work)
{
    for (int i = 0; i < 200 && work->pending; i++)
        IOSleep(5);
}

void flush_scheduled_work(void)
{
    flush_workqueue(system_wq);
}

/* ------------------------------------------------------------------ */
/*  Timer implementation (thread_call)                                  */
/* ------------------------------------------------------------------ */

static void timer_call_fn(thread_call_param_t p0, thread_call_param_t p1)
{
    struct timer_list *timer = (struct timer_list *)p0;
    (void)p1;
    /* Only fire if still marked active (del_timer may have raced) */
    if (timer->active) {
        timer->active = 0;
        if (timer->function) timer->function(timer);
    }
}

void timer_setup(struct timer_list *timer,
                 void (*func)(struct timer_list *t),
                 unsigned int flags)
{
    timer->function = func;
    timer->expires  = 0;
    timer->active   = 0;
    if (timer->call) {
        thread_call_cancel(timer->call);
        thread_call_free(timer->call);
    }
    timer->call = thread_call_allocate(timer_call_fn, (thread_call_param_t)timer);
}

int mod_timer(struct timer_list *timer, unsigned long expires)
{
    int was_active = timer->active;

    if (!timer->call)
        timer->call = thread_call_allocate(timer_call_fn,
                                            (thread_call_param_t)timer);

    long delay_ms = (long)expires - (long)jiffies;
    if (delay_ms <= 0) delay_ms = 1;

    uint64_t deadline;
    clock_interval_to_deadline((uint32_t)delay_ms, kMillisecondScale, &deadline);
    timer->expires = expires;
    timer->active  = 1;
    thread_call_enter_delayed(timer->call, deadline);
    return was_active;
}

int del_timer(struct timer_list *timer)
{
    int was_active = timer->active;
    if (timer->call) thread_call_cancel(timer->call);
    timer->active = 0;
    return was_active;
}

int del_timer_sync(struct timer_list *timer)
{
    timer->active = 0;
    if (timer->call) {
        thread_call_cancel_wait(timer->call);
        thread_call_free(timer->call);
        timer->call = NULL;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  mac80211 callbacks                                                  */
/* ------------------------------------------------------------------ */

struct rtw88_hw_callbacks {
    void (*rx_frame)(void *kext_hw, struct sk_buff *skb);
    void (*tx_status)(void *kext_hw, struct sk_buff *skb);
    void (*scan_done)(void *kext_hw, bool aborted);
};

static struct rtw88_hw_callbacks *g_hw_cbs = NULL;
static void *g_kext_hw = NULL;

void rtw88_set_hw_callbacks(struct rtw88_hw_callbacks *cbs, void *kext_hw)
{
    g_hw_cbs  = cbs;
    g_kext_hw = kext_hw;
}

void ieee80211_rx_irqsafe(struct ieee80211_hw *hw, struct sk_buff *skb)
{
    if (g_hw_cbs && g_hw_cbs->rx_frame)
        g_hw_cbs->rx_frame(hw->kext_hw, skb);
    else
        kfree_skb(skb);
}

void ieee80211_rx_napi(struct ieee80211_hw *hw, struct ieee80211_sta *sta,
                       struct sk_buff *skb, struct napi_struct *napi)
{
    ieee80211_rx_irqsafe(hw, skb);
}

void ieee80211_tx_status_irqsafe(struct ieee80211_hw *hw, struct sk_buff *skb)
{
    if (g_hw_cbs && g_hw_cbs->tx_status)
        g_hw_cbs->tx_status(hw->kext_hw, skb);
    else
        kfree_skb(skb);
}

void ieee80211_tx_status(struct ieee80211_hw *hw, struct sk_buff *skb)
{
    ieee80211_tx_status_irqsafe(hw, skb);
}

void ieee80211_free_txskb(struct ieee80211_hw *hw, struct sk_buff *skb)
{
    kfree_skb(skb);
}

void ieee80211_scan_completed(struct ieee80211_hw *hw,
                               struct cfg80211_scan_info *info)
{
    if (g_hw_cbs && g_hw_cbs->scan_done)
        g_hw_cbs->scan_done(hw->kext_hw, info ? info->aborted : false);
}

void ieee80211_stop_queues(struct ieee80211_hw *hw)  {}
void ieee80211_wake_queues(struct ieee80211_hw *hw)  {}
void ieee80211_stop_queue(struct ieee80211_hw *hw, int q) {}
void ieee80211_wake_queue(struct ieee80211_hw *hw, int q) {}
void ieee80211_schedule_txq(struct ieee80211_hw *hw, struct ieee80211_txq *txq) {}

void ieee80211_connection_loss(struct ieee80211_vif *vif) {}
void ieee80211_beacon_loss(struct ieee80211_vif *vif) {}
void ieee80211_cqm_rssi_notify(struct ieee80211_vif *vif,
                                int event, s32 rssi_level, gfp_t gfp) {}

void ieee80211_iterate_active_interfaces_atomic(
    struct ieee80211_hw *hw, unsigned int iter_flags,
    void (*iterator)(void *data, u8 *mac, struct ieee80211_vif *vif),
    void *data) {}

void ieee80211_iterate_active_interfaces(
    struct ieee80211_hw *hw, unsigned int iter_flags,
    void (*iterator)(void *data, u8 *mac, struct ieee80211_vif *vif),
    void *data) {}

void ieee80211_iterate_stations_atomic(
    struct ieee80211_hw *hw,
    void (*iterator)(void *data, struct ieee80211_sta *sta),
    void *data) {}

void ieee80211_iter_keys(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
    void (*iter)(struct ieee80211_hw *, struct ieee80211_vif *,
                 struct ieee80211_sta *, struct ieee80211_key_conf *, void *),
    void *iter_data) {}

void ieee80211_iter_keys_rcu(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
    void (*iter)(struct ieee80211_hw *, struct ieee80211_vif *,
                 struct ieee80211_sta *, struct ieee80211_key_conf *, void *),
    void *iter_data) {}

struct sk_buff *ieee80211_tx_dequeue(struct ieee80211_hw *hw,
                                      struct ieee80211_txq *txq)
{ return NULL; }

struct sk_buff *ieee80211_tx_dequeue_ni(struct ieee80211_hw *hw,
                                         struct ieee80211_txq *txq)
{ return NULL; }

bool ieee80211_txq_may_transmit(struct ieee80211_hw *hw,
                                 struct ieee80211_txq *txq)
{ return false; }

void ieee80211_txq_schedule_start(struct ieee80211_hw *hw, u8 ac) {}
void ieee80211_txq_schedule_end(struct ieee80211_hw *hw, u8 ac)   {}
bool ieee80211_txq_is_last(struct ieee80211_hw *hw, struct ieee80211_txq *txq)
{ return true; }

struct sk_buff *ieee80211_beacon_get_tim(struct ieee80211_hw *hw,
                                          struct ieee80211_vif *vif,
                                          u16 *tim_offset, u16 *tim_length,
                                          u32 link_id)
{ return NULL; }

struct sk_buff *ieee80211_nullfunc_get(struct ieee80211_hw *hw,
                                        struct ieee80211_vif *vif,
                                        int link_id, bool qos_ok)
{ return NULL; }

struct sk_buff *ieee80211_pspoll_get(struct ieee80211_hw *hw,
                                      struct ieee80211_vif *vif)
{ return NULL; }

struct sk_buff *ieee80211_probereq_get(struct ieee80211_hw *hw,
                                        const u8 *src_addr,
                                        const u8 *ssid, size_t ssid_len,
                                        size_t tailroom)
{ return NULL; }

int  ieee80211_sta_ps_transition(struct ieee80211_sta *sta, bool start) { return 0; }
void ieee80211_sta_pspoll(struct ieee80211_sta *sta) {}
void ieee80211_sta_uapsd_trigger(struct ieee80211_sta *sta, u8 tid) {}

void ieee80211_chswitch_done(struct ieee80211_vif *vif, bool success,
                              unsigned int link_id) {}

int ieee80211_freq_to_channel(int freq)
{
    if (freq >= 2412 && freq <= 2484)
        return (freq - 2407) / 5;
    if (freq >= 5180 && freq <= 5825)
        return (freq - 5000) / 5;
    return 0;
}

int ieee80211_channel_to_frequency(int chan, enum nl80211_band band)
{
    if (band == NL80211_BAND_2GHZ)
        return 2407 + chan * 5;
    return 5000 + chan * 5;
}

/* ------------------------------------------------------------------ */
/*  Workqueue extras                                                    */
/* ------------------------------------------------------------------ */

struct workqueue_struct *create_singlethread_workqueue(const char *name)
{
    return alloc_ordered_workqueue(name, 0);
}

void ieee80211_queue_work(struct ieee80211_hw *hw, struct work_struct *work)
{
    if (hw && hw->priv) {
        struct workqueue_struct *wq = system_wq;
        queue_work(wq, work);
    }
}

void ieee80211_queue_delayed_work(struct ieee80211_hw *hw,
                                   struct delayed_work *dwork,
                                   unsigned long delay)
{
    queue_delayed_work(system_wq, dwork, delay);
}

/* ------------------------------------------------------------------ */
/*  mac80211 stubs                                                      */
/* ------------------------------------------------------------------ */

struct ieee80211_sta *ieee80211_find_sta(struct ieee80211_vif *vif,
                                          const u8 *addr)
{ (void)vif; (void)addr; return NULL; }

struct ieee80211_sta *ieee80211_find_sta_by_ifaddr(struct ieee80211_hw *hw,
                                                    const u8 *addr,
                                                    const u8 *localaddr)
{ (void)hw; (void)addr; (void)localaddr; return NULL; }

struct sk_buff *ieee80211_proberesp_get(struct ieee80211_hw *hw,
                                         struct ieee80211_vif *vif)
{ (void)hw; (void)vif; return NULL; }

void ieee80211_purge_tx_queue(struct ieee80211_hw *hw,
                               struct sk_buff_head *skbs)
{
    struct sk_buff *skb;
    while ((skb = skb_dequeue(skbs)) != NULL)
        kfree_skb(skb);
}

void ieee80211_restart_hw(struct ieee80211_hw *hw) { (void)hw; }

int ieee80211_start_tx_ba_session(struct ieee80211_sta *sta, u16 tid,
                                   u16 timeout)
{ (void)sta; (void)tid; (void)timeout; return -EOPNOTSUPP; }

void ieee80211_stop_tx_ba_cb_irqsafe(struct ieee80211_vif *vif,
                                      const u8 *ra, u16 tid)
{ (void)vif; (void)ra; (void)tid; }

void ieee80211_tx_info_clear_status(struct ieee80211_tx_info *info)
{
    int i;
    for (i = 0; i < IEEE80211_TX_MAX_RATES; i++) {
        info->status.rates[i].idx   = -1;
        info->status.rates[i].count = 0;
        info->status.rates[i].flags = 0;
    }
}

void ieee80211_txq_get_depth(struct ieee80211_txq *txq,
                              unsigned long *frame_cnt,
                              unsigned long *byte_cnt)
{
    if (frame_cnt) *frame_cnt = 0;
    if (byte_cnt)  *byte_cnt  = 0;
}

u8 ieee80211_vif_type_p2p(struct ieee80211_vif *vif)
{
    return vif ? (u8)vif->type : 0;
}

struct ieee80211_hw *wiphy_to_ieee80211_hw(struct wiphy *wiphy)
{ return wiphy ? wiphy->_hw : NULL; }

int cfg80211_get_ies_channel_number(const u8 *ie, size_t ielen,
                                     enum nl80211_band band)
{ (void)ie; (void)ielen; (void)band; return -1; }

bool cfg80211_ssid_eq(struct cfg80211_ssid *a, struct cfg80211_ssid *b)
{
    if (!a || !b) return false;
    if (a->ssid_len != b->ssid_len) return false;
    return memcmp(a->ssid, b->ssid, a->ssid_len) == 0;
}

int regulatory_hint(struct wiphy *wiphy, const char *alpha2)
{ (void)wiphy; (void)alpha2; return 0; }

/* sdio_align_size stub — not needed for PCIe-only build */
void sdio_align_size(void) {}

/* firmware loading is in rtw88_firmware.c (separate TU, no compat header conflicts) */

void *devm_kmemdup(struct device *dev, const void *src, size_t len, gfp_t gfp)
{
    (void)dev;
    void *p = kmalloc(len, gfp);
    if (p) memcpy(p, src, len);
    return p;
}

void *devm_kmemdup_array(struct device *dev, const void *src, size_t n,
                          size_t size, gfp_t gfp)
{
    (void)dev;
    void *p = kmalloc(n * size, gfp);
    if (p && src) memcpy(p, src, n * size);
    return p;
}

void devm_free_irq(struct device *dev, unsigned int irq, void *dev_id)
{ (void)dev; (void)irq; (void)dev_id; }

/* ------------------------------------------------------------------ */
/*  Network device stubs                                                */
/* ------------------------------------------------------------------ */

struct net_device *alloc_netdev_dummy(int sizeof_priv)
{
    return (struct net_device *)kzalloc(
        sizeof(struct net_device) + sizeof_priv, GFP_KERNEL);
}

/* ------------------------------------------------------------------ */
/*  Misc kernel helpers                                                  */
/* ------------------------------------------------------------------ */

void *kmalloc_obj(size_t size, gfp_t flags, const char *name)
{ (void)name; return kmalloc(size, flags); }

void *kzalloc_obj(size_t size, gfp_t flags, const char *name)
{ (void)name; return kzalloc(size, flags); }

void get_random_mask_addr(u8 *buf, const u8 *addr, const u8 *mask)
{
    u8 rand[6];
    read_random(rand, sizeof(rand));
    for (int i = 0; i < 6; i++)
        buf[i] = (addr[i] & ~mask[i]) | (rand[i] & mask[i]);
}

int atomic_dec_if_positive(atomic_t *v)
{
    int c, old;
    c = atomic_read(v);
    for (;;) {
        if (c <= 0) return c - 1;
        old = __sync_val_compare_and_swap(&v->counter, c, c - 1);
        if (old == c) return c - 1;
        c = old;
    }
}

int timer_delete_sync(struct timer_list *timer)
{
    return del_timer_sync(timer);
}

/* ------------------------------------------------------------------ */
/*  Init / exit                                                         */
/* ------------------------------------------------------------------ */

int rtw88_compat_init(void)
{
    system_wq      = alloc_workqueue("rtw88_system_wq", 0, 0);
    system_long_wq = alloc_workqueue("rtw88_long_wq",   0, 0);
    if (!system_wq || !system_long_wq) return -ENOMEM;
    return 0;
}

void rtw88_compat_exit(void)
{
    destroy_workqueue(system_wq);
    destroy_workqueue(system_long_wq);
    system_wq = system_long_wq = NULL;
}
