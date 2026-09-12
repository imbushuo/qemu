/*
 * QEMU thin shim for the product paravirtualized GPU MMIO device.
 *
 * Sibling of apple-gfx-mmio: same sysbus layout on the vmapple machine
 * (mmio 0 / irq 0 = gfx window, mmio 1 / irq 1 = IOSurface mapper). The guest
 * binds Apple's own AppleParavirtGPU.kext; this host device is selected with
 * -M vmapple,gfx-device=reims-vgpu-mmio.
 *
 * Deliberately no more than apple-gfx's wrapper around
 * ParavirtualizedGraphics.framework:
 *   - SysBus registration + MemoryRegionOps
 *   - HostOps callbacks (GPA/KVA R/W, xreg, clock, schedule BH)
 *   - ordered worker: drain Rust without the BQL
 *   - main-loop BH: apply HostActions (IRQ / scanout / cursor)
 *   - GraphicHwOps console surface (mode + update_full); pixels from Rust
 *
 * Protocol, FIFO, decode, mapper capture, and GPU work all live in Rust.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/memalign.h"
#include "qemu/module.h"
#include "qemu/timer.h"
#include "qemu/main-loop.h"
#include "qemu/aio.h"
#include "qapi/error.h"
#include "qemu-main.h"
#include "hw/core/cpu.h"
#include "hw/core/sysbus.h"
#include "hw/core/irq.h"
#include "hw/vmapple/vmapple.h"
#include "qom/object.h"
#include "system/address-spaces.h"
#include "system/hw_accel.h"
#include "system/memory.h"
#include "system/runstate-action.h"
#include "system/runstate.h"
#include "ui/console.h"
#include "ui/surface.h"
#include "trace.h"
#include "reims_vgpu_qemu_abi.h"
#include "reims-vgpu-dirty.h"
#include "reims-vgpu-shim.h"
#include "reims-vgpu-worker.h"

/*
 * Guest X-regs and mach_vm page aliasing are Darwin product paths (arm guest
 * under HVF). TARGET_* macros are poisoned in common softmmu objects, so these
 * paths are gated on CONFIG_DARWIN only. On Linux/x86 the callbacks fail closed;
 * protocol/decode still runs through the Rust staticlib (Metal host stubs).
 */
#if defined(CONFIG_DARWIN)
#include <dispatch/dispatch.h>
#include "target/arm/cpu.h"
#include <mach/mach.h>
#include <mach/mach_vm.h>
#endif

#define TYPE_REIMS_VGPU_MMIO "reims-vgpu-mmio"
OBJECT_DECLARE_SIMPLE_TYPE(ReimsVGPUMMIOState, REIMS_VGPU_MMIO)

/*
 * Window sizes match the live Reims VGPU contract / apple-gfx-mmio:
 * gfx = 16 KiB, iosfc = 64 KiB. The gfx size is the shared
 * REIMS_VGPU_GFX_MMIO_SIZE — Rust bounds its register store against the same
 * number and a private copy here is a window the guest can address past it.
 * The iosfc size stays local; Rust keeps no per-offset state for that rail, so
 * mirroring it would create a source of truth nothing checks.
 */
#define REIMS_VGPU_MMIO_IOSFC_MMIO_SIZE 0x10000

/* Rust device/window action poll cadence (250 Hz, non-blocking). */
#define REIMS_VGPU_MMIO_WINDOW_POLL_MS 4

/*
 * One packed mach_vm_remap view handed out by map_pages, and the length it was
 * allocated at. The length is recorded because unmap_pages cannot trust the
 * caller's: a run whose first page is entered at an offset asks to release
 * fewer bytes than the view spans, and mach_vm_deallocate takes the allocation.
 */
typedef struct ReimsVGPUMMIOPageView {
    void *ptr;
    size_t len;
} ReimsVGPUMMIOPageView;

struct ReimsVGPUMMIOState {
    SysBusDevice parent_obj;

    MemoryRegion iomem_gfx;
    MemoryRegion iomem_iosfc;
    qemu_irq irq_gfx;
    qemu_irq irq_iosfc;

    /* Display (apple-gfx console role only). */
    QemuConsole *con;
    DisplaySurface *surface;
    /*
     * Guest frame-ready (archive apple-pv-gpu present-boundary policy +
     * apple-gfx new_frame_ready). Set when CmdDisplaySwap / early front paint
     * has written a finished frame into `surface`. gfx_update only pushes the
     * console when this is set — never host fixed-rate re-pull of live guest
     * pages (that dual-mid A/B thrash / dock-band mid-composite).
     */
    bool new_frame_ready;
    /* Device poll stays on QEMU's background emulation loop. */
    QEMUTimer *poll_timer;

    /* Filled at realize; address passed into Rust create. */
    ReimsVgpuHostOps host_ops;
    /* Hypervisor dirty-bitmap adapter: the only witness for a write to a
     * surface's guest pages that no device operation made. */
    ReimsVgpuDirty *dirty;
    /* Opaque handle from reims_vgpu_qemu_device_create; 0 when unrealized. */
    uint64_t rust_handle;
    ReimsVgpuWorker drain_worker;
    QEMUBH *action_bh;
    Notifier shutdown_notifier;
    bool shutdown_notifier_registered;
    /*
     * Live packed mach_vm_remap views, so unmap_pages can tell one of ours
     * from a direct RAMBlock HVA — the two are indistinguishable as bare
     * pointers, and mach_vm_deallocate on the latter would unmap guest RAM
     * out from under the VM. Entries are removed as they are released; a
     * non-empty array at teardown is a leak, and reims_vgpu_mmio_free_page_views
     * says so.
     */
    GArray *page_views;
};

#if defined(CONFIG_DARWIN)
/*
 * winit/AppKit owns the initial process thread. QEMU's Darwin main wrapper
 * already moves its emulation loop to a background thread when qemu_main is
 * non-NULL; device realize runs before that handoff and creates the event loop
 * on the same initial thread.
 */
static ReimsVGPUMMIOState *reims_vgpu_mmio_window_owner;

static int reims_vgpu_mmio_window_main_loop(void)
{
    ReimsVGPUMMIOState *s = reims_vgpu_mmio_window_owner;
    int rc;

    if (!s || s->rust_handle == 0) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: host window main loop has no live owner\n",
                      TYPE_REIMS_VGPU_MMIO);
        dispatch_main();
        g_assert_not_reached();
    }

    rc = reims_vgpu_qemu_window_run_main(s->rust_handle);
    if (rc != REIMS_VGPU_QEMU_OK) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: host window main loop failed rc=%d\n",
                      TYPE_REIMS_VGPU_MMIO, rc);
    }

    /*
     * The background QEMU loop owns shutdown and calls exit(). Keep the initial
     * thread available to libdispatch after the winit loop has closed.
     */
    dispatch_main();
    g_assert_not_reached();
}
#endif

/* ---------- HostOps (only host services; apple-gfx equivalents) ---------- */

/*
 * Guest X-register read for the iosfc mapper directed handoff
 * (x19 mapper device, x21 request type, x22 MappingInternal*). Must be
 * invoked on the MMIO path of the publishing vCPU — Rust calls this from
 * iosfc producer write (sync path). No first_cpu fallback: same deadlock
 * class as read_kva if used from the BH.
 */
static int reims_vgpu_mmio_read_xreg(void *ctx, uint32_t index, uint64_t *out)
{
    (void)ctx;
    return vmapple_read_current_xreg(index, out) ? 0 : -1;
}

/*
 * Contiguous host-VA view of guest 16 KiB pages — the ParavirtualizedGraphics
 * mapMemory model (mach_vm_remap of guest RAM into the framework's working
 * VA). The view aliases guest RAM: Metal render targets created on it write
 * guest memory directly, so there is exactly ONE copy of surface content.
 *
 * A host-contiguous page run returns its direct RAMBlock HVA, which is guest
 * RAM itself and outlives every view. A fragmented list gets one packed
 * mach_vm_remap view, which the caller owns and must release through
 * unmap_pages.
 *
 * The view used to be retained for the whole device lifetime instead, because
 * Rust cached VK_EXT_external_memory_host imports over it and could re-read the
 * pages at any later point. Nothing imports guest pages now, so the retention
 * bought nothing and every fragmented map leaked a VA reservation until
 * teardown. `map_pages_stable` is 0 accordingly.
 *
 * Linux cannot manufacture a packed view for fragmented pages without
 * file-backed guest RAM, but QEMU's ordinary RAMBlock mapping is already a
 * stable alias.  Accept runs that are contiguous in both guest-physical and
 * host-virtual space (including every valid one-page request) and fail closed
 * only for fragmented runs.
 */
static int reims_vgpu_mmio_map_pages(void *ctx, const uint64_t *gpas,
                                  size_t count, void **out_ptr,
                                  ReimsVgpuMapPagesFailure *failure)
{
#if defined(CONFIG_DARWIN)
    ReimsVGPUMMIOState *s = ctx;
    uint8_t **hvas = NULL;
    mach_vm_address_t view = 0;
    mach_vm_size_t view_len;
    ReimsVGPUMMIOPageView view_entry;
    kern_return_t kr;
    size_t i;

    if (!s || !gpas || count == 0 || !out_ptr ||
        count > SIZE_MAX / REIMS_VGPU_GUEST_PAGE_SIZE_ARM64E) {
        return reims_vgpu_shim_map_pages_failed(
            failure, REIMS_VGPU_MAP_PAGES_FAILURE_NONE, EINVAL, 0);
    }
    view_len = (mach_vm_size_t)count * REIMS_VGPU_GUEST_PAGE_SIZE_ARM64E;
    hvas = g_new(uint8_t *, count);

    rcu_read_lock();
    for (i = 0; i < count; i++) {
        hwaddr xlat, plen = REIMS_VGPU_GUEST_PAGE_SIZE_ARM64E;
        MemoryRegion *mr;
        uint8_t *hva;

        mr = address_space_translate(&address_space_memory, gpas[i],
                                     &xlat, &plen, true,
                                     MEMTXATTRS_UNSPECIFIED);
        if (!mr || !memory_region_is_ram(mr) ||
            plen < REIMS_VGPU_GUEST_PAGE_SIZE_ARM64E) {
            goto fail;
        }
        hva = (uint8_t *)memory_region_get_ram_ptr(mr) + xlat;
        if (((uintptr_t)hva & (REIMS_VGPU_GUEST_PAGE_SIZE_ARM64E - 1)) != 0) {
            goto fail;
        }
        hvas[i] = hva;
    }
    rcu_read_unlock();

    for (i = 1; i < count; i++) {
        if (hvas[i] != hvas[0] + i * REIMS_VGPU_GUEST_PAGE_SIZE_ARM64E) {
            break;
        }
    }
    if (i == count) {
        *out_ptr = hvas[0];
        g_free(hvas);
        return 0;
    }

    kr = mach_vm_allocate(mach_task_self(), &view, view_len,
                          VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        g_free(hvas);
        return reims_vgpu_shim_map_pages_failed(
            failure, REIMS_VGPU_MAP_PAGES_FAILURE_RESERVATION, kr, 0);
    }
    for (i = 0; i < count; i++) {
        mach_vm_address_t dst = view + i * REIMS_VGPU_GUEST_PAGE_SIZE_ARM64E;
        vm_prot_t cur_prot, max_prot;

        kr = mach_vm_remap(mach_task_self(), &dst, REIMS_VGPU_GUEST_PAGE_SIZE_ARM64E, 0,
                           VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                           mach_task_self(),
                           (mach_vm_address_t)(uintptr_t)hvas[i], FALSE,
                           &cur_prot, &max_prot, VM_INHERIT_NONE);
        if (kr != KERN_SUCCESS) {
            mach_vm_deallocate(mach_task_self(), view, view_len);
            g_free(hvas);
            return reims_vgpu_shim_map_pages_failed(
                failure, REIMS_VGPU_MAP_PAGES_FAILURE_ALIAS, kr, i);
        }
    }

    *out_ptr = (void *)(uintptr_t)view;
    view_entry.ptr = *out_ptr;
    view_entry.len = view_len;
    g_array_append_val(s->page_views, view_entry);
    g_free(hvas);
    return 0;

fail:
    rcu_read_unlock();
    g_free(hvas);
    return reims_vgpu_shim_map_pages_failed(
        failure, REIMS_VGPU_MAP_PAGES_FAILURE_INVALID_GUEST_PAGE, 0, i);
#else
    const hwaddr page = REIMS_VGPU_GUEST_PAGE_SIZE_ARM64E;
    uint8_t *base = NULL;
    MemoryRegion *base_mr = NULL;
    uint32_t failure_stage = REIMS_VGPU_MAP_PAGES_FAILURE_INVALID_GUEST_PAGE;
    int failure_errno = 0;
    size_t i;

    if (!ctx || !gpas || count == 0 || !out_ptr ||
        count > SIZE_MAX / page) {
        return reims_vgpu_shim_map_pages_failed(
            failure, REIMS_VGPU_MAP_PAGES_FAILURE_NONE, EINVAL, 0);
    }

    rcu_read_lock();
    for (i = 0; i < count; i++) {
        hwaddr xlat, plen = page;
        MemoryRegion *mr;
        uint8_t *hva;

        mr = address_space_translate(&address_space_memory, gpas[i],
                                     &xlat, &plen, true,
                                     MEMTXATTRS_UNSPECIFIED);
        if (!mr || !memory_region_is_ram(mr) || plen < page) {
            goto linux_fail;
        }
        hva = (uint8_t *)memory_region_get_ram_ptr(mr) + xlat;
        if (i == 0) {
            base = hva;
            base_mr = mr;
            if (((uintptr_t)base & (page - 1)) != 0) {
                failure_stage = REIMS_VGPU_MAP_PAGES_FAILURE_ALIAS;
                failure_errno = EINVAL;
                goto linux_fail;
            }
        } else if (mr != base_mr || hva != base + i * page) {
            failure_stage = REIMS_VGPU_MAP_PAGES_FAILURE_ALIAS;
            failure_errno = ENOTSUP;
            goto linux_fail;
        }
    }
    rcu_read_unlock();

    *out_ptr = base;
    return 0;

linux_fail:
    rcu_read_unlock();
    return reims_vgpu_shim_map_pages_failed(
        failure, failure_stage, failure_errno, i);
#endif
}

/*
 * Release a view map_pages handed out. A pointer that is not in `page_views` is
 * a direct RAMBlock HVA — guest RAM itself — and must be left alone; there is
 * nothing to free and deallocating it would unmap the guest's own memory.
 *
 * `len` is deliberately ignored in favour of the recorded allocation length.
 * The caller passes the span it asked for, and a run entered at a page offset
 * asks for fewer bytes than the view covers.
 */
static void reims_vgpu_mmio_unmap_pages(void *ctx, void *ptr, size_t len)
{
#if defined(CONFIG_DARWIN)
    ReimsVGPUMMIOState *s = ctx;
    size_t i;

    (void)len;
    if (!s || !ptr || !s->page_views) {
        return;
    }
    for (i = 0; i < s->page_views->len; i++) {
        ReimsVGPUMMIOPageView *view =
            &g_array_index(s->page_views, ReimsVGPUMMIOPageView, i);
        if (view->ptr == ptr) {
            mach_vm_deallocate(mach_task_self(),
                               (mach_vm_address_t)(uintptr_t)ptr, view->len);
            g_array_remove_index_fast(s->page_views, i);
            return;
        }
    }
#else
    (void)ctx;
    (void)ptr;
    (void)len;
#endif
}

/*
 * Teardown backstop. Every view should already have been released by
 * unmap_pages, so anything still here is a caller that mapped and never freed —
 * reclaim it, but say so rather than reclaiming quietly, because the silent
 * version of this function is what hid the leak that made it necessary.
 */
static void reims_vgpu_mmio_free_page_views(ReimsVGPUMMIOState *s)
{
#if defined(CONFIG_DARWIN)
    size_t i;

    if (!s->page_views) {
        return;
    }
    if (s->page_views->len != 0) {
        qemu_log_mask(LOG_UNIMP,
                      "%s: %u guest page view(s) still mapped at teardown\n",
                      TYPE_REIMS_VGPU_MMIO, s->page_views->len);
    }
    for (i = 0; i < s->page_views->len; i++) {
        ReimsVGPUMMIOPageView *view =
            &g_array_index(s->page_views, ReimsVGPUMMIOPageView, i);
        mach_vm_deallocate(mach_task_self(),
                           (mach_vm_address_t)(uintptr_t)view->ptr,
                           view->len);
    }
    g_array_set_size(s->page_views, 0);
#else
    (void)s;
#endif
}

/*
 * Guest-write tracking. A surface's storage is plain guest RAM: the guest CPU
 * stores into it with no device operation, so nothing the Rust device counts
 * can witness such a store and every host-side copy of those pages is stale
 * from that instant. These three forward to the shared dirty-bitmap adapter.
 */
static uint64_t reims_vgpu_mmio_track_guest_writes(void *ctx, const uint64_t *gpas,
                                                   size_t count, size_t page_size)
{
    ReimsVGPUMMIOState *s = ctx;

    return reims_vgpu_dirty_track(s->dirty, gpas, count, page_size);
}

static void reims_vgpu_mmio_untrack_guest_writes(void *ctx, uint64_t token)
{
    ReimsVGPUMMIOState *s = ctx;

    reims_vgpu_dirty_untrack(s->dirty, token);
}

static uint64_t reims_vgpu_mmio_guest_write_gen(void *ctx, uint64_t token)
{
    ReimsVGPUMMIOState *s = ctx;

    return reims_vgpu_dirty_gen(s->dirty, token);
}

static int64_t reims_vgpu_mmio_guest_written_pages(void *ctx, uint64_t token,
                                         uint64_t since_gen, uint64_t *out,
                                         size_t max)
{
    ReimsVGPUMMIOState *s = ctx;

    return reims_vgpu_dirty_written_since(s->dirty, token, since_gen, out, max);
}

static void reims_vgpu_mmio_bh(void *opaque);
static void reims_vgpu_mmio_deliver_actions(ReimsVGPUMMIOState *s);
static void reims_vgpu_mmio_apply_action(ReimsVGPUMMIOState *s, const ReimsVgpuHostAction *a);

static void reims_vgpu_mmio_schedule_bh(void *ctx)
{
    ReimsVGPUMMIOState *s = ctx;

    reims_vgpu_worker_schedule(&s->drain_worker);
}

static void reims_vgpu_mmio_notify_actions(void *ctx)
{
    ReimsVGPUMMIOState *s = ctx;

    if (s->action_bh) {
        qemu_bh_schedule(s->action_bh);
    }
}

/* IRQs can be delivered while the worker is still draining other packets. */
static void reims_vgpu_mmio_deliver_actions(ReimsVGPUMMIOState *s)
{
    ReimsVgpuHostAction action;
    int rc;

    if (s->rust_handle == 0) {
        return;
    }
    while ((rc = reims_vgpu_qemu_device_pop_action(s->rust_handle, &action)) ==
           REIMS_VGPU_QEMU_OK) {
        reims_vgpu_mmio_apply_action(s, &action);
    }
}

/* ---------- Console surface (apple-gfx set_mode / gfx_update) ---------- */

/*
 * Mode change: new DisplaySurface + attach to console.
 * Matches apple-gfx.m set_mode (create + set_surface → cocoa switchSurface).
 * Called only with a finished present's sizeInPixels (CmdDisplaySwap or the
 * first same-geom early paint) — never on a bare size hint without content.
 */
static void reims_vgpu_mmio_set_mode(ReimsVGPUMMIOState *s, uint32_t width,
                                  uint32_t height)
{
    if (width == 0 || height == 0 ||
        width > REIMS_VGPU_MAX_SCANOUT_DIM || height > REIMS_VGPU_MAX_SCANOUT_DIM) {
        return;
    }
    if (s->surface &&
        surface_width(s->surface) == width &&
        surface_height(s->surface) == height) {
        return;
    }

    s->surface = qemu_create_displaysurface(width, height);
    if (s->con) {
        /* apple-gfx: set_surface alone; cocoa switchSurface resizes the window. */
        qemu_console_set_surface(s->con, s->surface);
    }
    trace_reims_vgpu_mmio_mode_change(width, height);
}

/*
 * Paint a named guest mapping into the QEMU surface, at the geometry the caller
 * was handed:
 *   - that geometry is the guest-presented surface size (PG modeChangeHandler's
 *     sizeInPixels from the named IOSurface — not a host size heuristic), so
 *     set_mode(w,h) is exact, like apple-gfx.m set_mode;
 *   - the copy fills that surface; do not invent or clamp dimensions in C.
 *
 * Returns whether the surface now holds a frame worth showing. Unlike the PCI
 * shim's twin this does not push the console itself — see the newFrame note at
 * the tail, which is a measurement of this pathway and not of that one.
 */
static bool reims_vgpu_mmio_paint_scanout(ReimsVGPUMMIOState *s,
                                          uint32_t mapping_id, uint32_t width,
                                          uint32_t height, uint32_t generation)
{
    uint8_t *dst;
    uint32_t stride;
    int rc;

    /* Zero size is not a present; skip (framework would not mode-change to 0). */
    if (width == 0 || height == 0) {
        return false;
    }
    /*
     * One surface path. There used to be two: reims_vgpu_mmio_set_gpu_mode
     * allocated an alignment-negotiated buffer, attached it as the
     * DisplaySurface backing, and handed it to Rust for a resident-to-buffer
     * GPU copy so no framebuffer bytes crossed the CPU. Its alignment came
     * from VK_EXT_external_memory_host, which is no longer requested, and the
     * buffers had to be retained until teardown because the engine cached
     * their imports. Both the retention and the import are gone.
     */
    reims_vgpu_mmio_set_mode(s, width, height);
    if (!s->surface) {
        return false;
    }

    dst = surface_data(s->surface);
    stride = surface_stride(s->surface);
    rc = reims_vgpu_qemu_scanout_copy(s->rust_handle, mapping_id, dst, stride,
                               width, height, generation);
    if (rc != REIMS_VGPU_QEMU_OK && rc != REIMS_VGPU_QEMU_EMPTY) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: scanout_copy failed mapping=%u %ux%u rc=%d\n",
                      TYPE_REIMS_VGPU_MMIO, mapping_id, width, height, rc);
        return false;
    }
    if (rc == REIMS_VGPU_QEMU_OK) {
        trace_reims_vgpu_mmio_scanout(mapping_id, width, height);
    }
    /*
     * apple-gfx newFrame: write the finished frame into the host surface, then
     * mark frame-ready. Console push is gfx_update only (hostPresentCount /
     * pending_frames coalesce) — not update_full on every ScanoutUpdate.
     * Rapid dual-mid DisplaySwaps overwrite surface pixels with the latest
     * +0x188 retain; one vsync shows the latest finished present, not every
     * lagging double-buffer half (logo thrash under hover). An EMPTY copy is
     * ready too: the surface still holds the front it last painted.
     */
    return true;
}

static void reims_vgpu_mmio_apply_scanout(ReimsVGPUMMIOState *s,
                                       const ReimsVgpuHostAction *a)
{
    uint32_t mapping_id = (uint32_t)a->a0;

    if (s->rust_handle == 0 || !s->con) {
        return;
    }
    /*
     * Console ownership, from Rust. This shim used to paint every present it was
     * handed while the PCI shim gated on the same question, so a pre-boundary
     * present naming an unlatched mapping stole the firmware console here and
     * was refused there — one rule, one pathway holding it.
     */
    if (!reims_vgpu_shim_scanout_may_paint(s->rust_handle, mapping_id)) {
        return;
    }
    if (reims_vgpu_mmio_paint_scanout(s, mapping_id, (uint32_t)a->a1,
                                      (uint32_t)a->a2, (uint32_t)a->a3)) {
        s->new_frame_ready = true;
    }
}

static void reims_vgpu_mmio_apply_cursor(ReimsVGPUMMIOState *s,
                                      const ReimsVgpuHostAction *a)
{
    int x = (int)a->a0;
    int y = (int)a->a1;
    bool show = a->a2 != 0;

    if (!s->con) {
        return;
    }
    trace_reims_vgpu_mmio_cursor(a->a0, a->a1, a->a2);
    qemu_console_set_mouse(s->con, x, y, show);
}

/*
 * Pull glyph pixels from Rust and install a QEMUCursor (apple-gfx
 * cursorGlyphHandler role — C only owns the console cursor object).
 */
static void reims_vgpu_mmio_apply_cursor_glyph(ReimsVGPUMMIOState *s)
{
    ReimsVgpuCursorGlyphInfo info;
    QEMUCursor *c;
    g_autofree uint32_t *pixels = NULL;
    int rc;

    if (s->rust_handle == 0 || !s->con) {
        return;
    }
    rc = reims_vgpu_qemu_cursor_glyph_info(s->rust_handle, &info);
    if (rc != REIMS_VGPU_QEMU_OK || info.width == 0 || info.height == 0 ||
        info.pixel_count == 0 ||
        info.pixel_count != info.width * info.height) {
        return;
    }
    pixels = g_new(uint32_t, info.pixel_count);
    rc = reims_vgpu_qemu_cursor_glyph_copy(s->rust_handle, pixels, info.pixel_count);
    if (rc != REIMS_VGPU_QEMU_OK) {
        return;
    }
    c = cursor_alloc(info.width, info.height);
    if (!c) {
        return;
    }
    c->hot_x = info.hot_x;
    c->hot_y = info.hot_y;
    memcpy(c->data, pixels, (size_t)info.pixel_count * sizeof(uint32_t));
    qemu_console_set_cursor(s->con, c);
    cursor_unref(c);
}

static void reims_vgpu_mmio_apply_action(ReimsVGPUMMIOState *s,
                                      const ReimsVgpuHostAction *a)
{
    switch (a->kind) {
    case REIMS_VGPU_HOST_ACTION_IRQ_GFX:
        trace_reims_vgpu_mmio_irq_gfx();
        qemu_irq_pulse(s->irq_gfx);
        break;
    case REIMS_VGPU_HOST_ACTION_IRQ_IOSFC:
        trace_reims_vgpu_mmio_irq_iosfc();
        qemu_irq_pulse(s->irq_iosfc);
        break;
    case REIMS_VGPU_HOST_ACTION_SCANOUT:
        reims_vgpu_mmio_apply_scanout(s, a);
        break;
    case REIMS_VGPU_HOST_ACTION_CURSOR:
        reims_vgpu_mmio_apply_cursor(s, a);
        break;
    case REIMS_VGPU_HOST_ACTION_CURSOR_GLYPH:
        reims_vgpu_mmio_apply_cursor_glyph(s);
        break;
    case REIMS_VGPU_HOST_ACTION_INPUT_KEY:
        reims_vgpu_shim_input_key(s->con, (uint32_t)a->a0, a->a1 != 0);
        break;
    case REIMS_VGPU_HOST_ACTION_INPUT_POINTER_MOVE:
        reims_vgpu_shim_input_pointer_move(s->con, (uint32_t)a->a0,
                                           (uint32_t)a->a1,
                                           (uint32_t)a->a2,
                                           (uint32_t)a->a3);
        break;
    case REIMS_VGPU_HOST_ACTION_INPUT_POINTER_BUTTON:
        reims_vgpu_shim_input_button(s->con, (uint32_t)a->a0, a->a1 != 0);
        break;
    case REIMS_VGPU_HOST_ACTION_WINDOW_CLOSED:
        qemu_system_shutdown_request(SHUTDOWN_CAUSE_HOST_UI);
        break;
    case REIMS_VGPU_HOST_ACTION_TRACE:
    case REIMS_VGPU_HOST_ACTION_NONE:
    default:
        break;
    }
}

static void reims_vgpu_mmio_bh(void *opaque)
{
    ReimsVGPUMMIOState *s = opaque;

    if (s->rust_handle == 0) {
        return;
    }
    reims_vgpu_mmio_deliver_actions(s);
}

static void reims_vgpu_mmio_drain(void *opaque)
{
    ReimsVGPUMMIOState *s = opaque;
    int rc;

    assert(!bql_locked());
    rc = reims_vgpu_qemu_device_drain(s->rust_handle);
    if (rc != REIMS_VGPU_QEMU_OK) {
        qemu_log_mask(LOG_GUEST_ERROR, "%s: worker drain failed rc=%d\n",
                      TYPE_REIMS_VGPU_MMIO, rc);
    }
    qemu_bh_schedule(s->action_bh);
}

static void reims_vgpu_mmio_poll_tick(void *opaque)
{
    ReimsVGPUMMIOState *s = opaque;

    if (s->rust_handle == 0) {
        return;
    }
    if (reims_vgpu_qemu_device_poll(s->rust_handle) == REIMS_VGPU_QEMU_OK) {
        reims_vgpu_mmio_deliver_actions(s);
    }
    timer_mod(s->poll_timer,
              qemu_clock_get_ms(QEMU_CLOCK_HOST) +
              REIMS_VGPU_MMIO_WINDOW_POLL_MS);
}

/*
 * Display refresh (GraphicHwOps.gfx_update).
 *
 * Archive apple-pv-gpu (host/archive/.../apple-pv-gpu.c fb_update_display):
 *   - Pre present-boundary: may re-pull latched front (logo/pill motion).
 *   - Post present-boundary: re-show last painted surface only — never re-read
 *     live guest pages on the Cocoa clock (dual-mid A/B / tile-through).
 *
 * Product tightens the post-boundary push to guest **frame-ready**:
 * CmdDisplaySwap (and early same-geom front paint) set `new_frame_ready` after
 * writing the finished frame into `surface`. Host only calls
 * qemu_console_update_full when that flag is set — not fixed-rate thrash of
 * every vsync with no new guest present (archive present-boundary = newFrame;
 * stamp completes before HostAction apply so guest waiters see stamp first).
 */
static bool reims_vgpu_mmio_fb_update(void *opaque)
{
    ReimsVGPUMMIOState *s = opaque;
    uint32_t mapping_id = 0;
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t generation = 0;
    uint32_t kind;

    if (!s->con) {
        return true;
    }

    /*
     * Re-drive ONLINE once the enable mask (+0x104 bit 2) is published, so
     * createDisplayAttributes consumes TimingElements. May deliver ScanoutUpdate
     * HostActions (guest present → frame ready).
     */
    if (s->rust_handle != 0 &&
        reims_vgpu_qemu_device_poll(s->rust_handle) == REIMS_VGPU_QEMU_OK) {
        reims_vgpu_mmio_deliver_actions(s);
    }

    /* Host-console ownership is Rust's call; this only paints what it names. */
    kind = reims_vgpu_shim_console_feed(s->rust_handle, &mapping_id, &width,
                                        &height, &generation);

    if (kind == REIMS_VGPU_CONSOLE_FEED_EARLY) {
        /*
         * _EARLY ends at the first DisplaySwap, and Rust guarantees a paintable
         * mapping and geometry with it — so paint at the geometry it named
         * rather than at whatever the current surface happens to be. This shim
         * used to hold the opposite rule ("never resize from the refresh path"),
         * which is a decode rule living in C: `device_console_feed`'s own doc
         * records that both shims re-tested the geometry and that neither
         * should. An _EARLY whose size differed from the surface repainted
         * nothing here, forever, while the PCI shim resized and painted it.
         */
        if (reims_vgpu_mmio_paint_scanout(s, mapping_id, width, height,
                                          generation)) {
            qemu_console_update_full(s->con);
            s->new_frame_ready = false;
        }
        return true;
    }
    if (kind == REIMS_VGPU_CONSOLE_FEED_FIRMWARE) {
        /*
         * The guest is still on its firmware console and there is no BAR1 GOP on
         * this pathway to copy from, so nothing is painted. Return rather than
         * fall through: the pending frame below is a product one, and pushing it
         * while Rust says the firmware console owns the screen is the
         * pre-boundary steal this feed exists to prevent.
         */
        return true;
    }

    /* Nothing painted this tick — re-push the last frame if one is pending.
     * _PRODUCT reaches here every tick: apply_scanout does that painting, and
     * this is the hostPresentCount re-show of a guest-finished frame. */
    if (s->new_frame_ready && s->surface) {
        qemu_console_update_full(s->con);
        s->new_frame_ready = false;
    }
    return true;
}

static const GraphicHwOps reims_vgpu_mmio_fb_ops = {
    .gfx_update = reims_vgpu_mmio_fb_update,
};

/* ---------- MMIO (forward only) ---------- */

static uint64_t reims_vgpu_mmio_gfx_read(void *opaque, hwaddr offset,
                                      unsigned size)
{
    ReimsVGPUMMIOState *s = opaque;
    uint64_t val = 0;

    if (s->rust_handle == 0) {
        return 0;
    }
    if (reims_vgpu_qemu_gfx_read(s->rust_handle, offset, size, &val) != REIMS_VGPU_QEMU_OK) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: gfx read failed offset=0x%" HWADDR_PRIx " size=%u\n",
                      TYPE_REIMS_VGPU_MMIO, offset, size);
        return 0;
    }
    trace_reims_vgpu_mmio_gfx_read(offset, val);
    return val;
}

static void reims_vgpu_mmio_gfx_write(void *opaque, hwaddr offset, uint64_t data,
                                   unsigned size)
{
    ReimsVGPUMMIOState *s = opaque;

    if (s->rust_handle == 0) {
        return;
    }
    trace_reims_vgpu_mmio_gfx_write(offset, data);
    /*
     * Before the register write, not after: this is the guest handing the
     * device work, so every guest store ordered before the handoff must be
     * observed before anything that work does can reuse a host-side copy of
     * those pages. Harvesting here is also the only place it can happen — the
     * accelerator's dirty-log sync needs the BQL, which a vCPU MMIO write
     * holds and the drain thread must never take.
     */
    reims_vgpu_dirty_harvest(s->dirty);
    if (reims_vgpu_qemu_gfx_write(s->rust_handle, offset, data, size) != REIMS_VGPU_QEMU_OK) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: gfx write failed offset=0x%" HWADDR_PRIx
                      " data=0x%" PRIx64 " size=%u\n",
                      TYPE_REIMS_VGPU_MMIO, offset, data, size);
        return;
    }
    /* Apply prompt actions without waiting for the GPU worker. */
    reims_vgpu_mmio_deliver_actions(s);
}

static uint64_t reims_vgpu_mmio_iosfc_read(void *opaque, hwaddr offset,
                                        unsigned size)
{
    ReimsVGPUMMIOState *s = opaque;
    Object *owner = OBJECT(s);
    uint64_t val = 0;
    bool inherited_bql = bql_locked();

    object_ref(owner);
    if (!inherited_bql) {
        bql_lock();
    }
    if (s->rust_handle == 0) {
        goto out;
    }
    if (reims_vgpu_qemu_iosfc_read(s->rust_handle, offset, size, &val) !=
        REIMS_VGPU_QEMU_OK) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: iosfc read failed offset=0x%" HWADDR_PRIx
                      " size=%u\n",
                      TYPE_REIMS_VGPU_MMIO, offset, size);
        goto out;
    }
    trace_reims_vgpu_mmio_iosfc_read(offset, val);
out:
    object_unref(owner);
    if (!inherited_bql) {
        bql_unlock();
    }
    return val;
}

static void reims_vgpu_mmio_iosfc_write(void *opaque, hwaddr offset, uint64_t data,
                                     unsigned size)
{
    ReimsVGPUMMIOState *s = opaque;
    Object *owner = OBJECT(s);
    bool inherited_bql = bql_locked();
    uint64_t ticket = 0;
    int rc;

    /*
     * A reset/unrealize may run during the admission wait. It cancels the
     * independent Rust ticket without waiting for this vCPU to reacquire BQL.
     * Keep the QOM allocation, not its backend/HostOps fields, until return.
     */
    object_ref(owner);
    if (!inherited_bql) {
        bql_lock();
    }
    if (s->rust_handle == 0) {
        goto out;
    }
    trace_reims_vgpu_mmio_iosfc_write(offset, data);
    rc = reims_vgpu_qemu_iosfc_begin_write(s->rust_handle, offset, data, size,
                                          &ticket);
    if (rc != REIMS_VGPU_QEMU_OK) {
        goto failed;
    }
    /*
     * The same reason as the gfx path, and both are needed: this shim exposes
     * two guest-facing register windows, and either can be the write that hands
     * the device work. Harvesting on only one would leave the guest-write
     * witness a whole submission stale on whichever rail the guest happens to
     * use. Cheap when nothing has read a generation since the last harvest, so
     * covering both costs a predicate, not a sync.
     */
    reims_vgpu_dirty_harvest(s->dirty);
    rc = reims_vgpu_shim_iosfc_complete(ticket);
    if (rc == REIMS_VGPU_QEMU_CANCELLED) {
        /* No backend fields or callbacks are valid after cancellation. */
        goto out;
    }
    if (rc != REIMS_VGPU_QEMU_OK) {
failed:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: iosfc write failed offset=0x%" HWADDR_PRIx
                      " data=0x%" PRIx64 " size=%u rc=%d\n",
                      TYPE_REIMS_VGPU_MMIO, offset, data, size, rc);
        goto out;
    }
    reims_vgpu_mmio_deliver_actions(s);
out:
    object_unref(owner);
    if (!inherited_bql) {
        bql_unlock();
    }
}

static const MemoryRegionOps reims_vgpu_mmio_gfx_ops = {
    .read = reims_vgpu_mmio_gfx_read,
    .write = reims_vgpu_mmio_gfx_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 8,
    },
    .impl = {
        .min_access_size = 4,
        .max_access_size = 8,
    },
};

static const MemoryRegionOps reims_vgpu_mmio_iosfc_ops = {
    .read = reims_vgpu_mmio_iosfc_read,
    .write = reims_vgpu_mmio_iosfc_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 8,
    },
    .impl = {
        .min_access_size = 4,
        .max_access_size = 8,
    },
};

/* ---------- Lifecycle ---------- */

static void reims_vgpu_mmio_stop_backend(ReimsVGPUMMIOState *s)
{
    assert(bql_locked());
    if (s->poll_timer) {
        timer_del(s->poll_timer);
        timer_free(s->poll_timer);
        s->poll_timer = NULL;
    }
    reims_vgpu_worker_stop(&s->drain_worker);
    if (s->rust_handle != 0) {
        reims_vgpu_qemu_window_stop(s->rust_handle);
        reims_vgpu_qemu_device_destroy(s->rust_handle);
        s->rust_handle = 0;
    }
    /* Keep the notification target alive until every producer has stopped. */
    if (s->action_bh) {
        qemu_bh_delete(s->action_bh);
        s->action_bh = NULL;
    }
}

static void reims_vgpu_mmio_shutdown_notifier(Notifier *n, void *data)
{
    ReimsVGPUMMIOState *s = container_of(n, ReimsVGPUMMIOState,
                                       shutdown_notifier);

    (void)data;
    /* A shutdown pause keeps the device alive for system_reset and cont. */
    if (shutdown_action == SHUTDOWN_ACTION_PAUSE) {
        return;
    }
    reims_vgpu_mmio_stop_backend(s);
}

static void reims_vgpu_mmio_init(Object *obj)
{
    ReimsVGPUMMIOState *s = REIMS_VGPU_MMIO(obj);
    SysBusDevice *sbd = SYS_BUS_DEVICE(obj);

    /*
     * Same sysbus layout as apple-gfx-mmio: mmio 0/irq 0 = gfx,
     * mmio 1/irq 1 = IOSurface mapper.
     */
    memory_region_init_io(&s->iomem_gfx, obj, &reims_vgpu_mmio_gfx_ops, s,
                          TYPE_REIMS_VGPU_MMIO ".gfx",
                          REIMS_VGPU_GFX_MMIO_SIZE);
    memory_region_init_io(&s->iomem_iosfc, obj, &reims_vgpu_mmio_iosfc_ops, s,
                          TYPE_REIMS_VGPU_MMIO ".iosfc",
                          REIMS_VGPU_MMIO_IOSFC_MMIO_SIZE);
    /*
     * An ordinary callback's device reentrancy guard cannot span a BQL-free
     * wait. Rust owns ordered admission and actual same-device reentry refusal;
     * the callback explicitly restores BQL around every HostOps operation.
     */
    memory_region_enable_lockless_io(&s->iomem_iosfc);
    sysbus_init_mmio(sbd, &s->iomem_gfx);
    sysbus_init_mmio(sbd, &s->iomem_iosfc);
    sysbus_init_irq(sbd, &s->irq_gfx);
    sysbus_init_irq(sbd, &s->irq_iosfc);

    s->rust_handle = 0;
    s->con = NULL;
    s->surface = NULL;
    s->new_frame_ready = false;
    s->poll_timer = NULL;
    s->page_views = g_array_new(false, false,
                                sizeof(ReimsVGPUMMIOPageView));
    memset(&s->host_ops, 0, sizeof(s->host_ops));
}

static void reims_vgpu_mmio_realize(DeviceState *dev, Error **errp)
{
    ReimsVGPUMMIOState *s = REIMS_VGPU_MMIO(dev);
    ReimsVgpuQemuCreateInfo info;
    ReimsVgpuQemuDevice out = {
        .abi_version = 0,
        .struct_size = 0,
        .handle = 0,
    };
    char backend[32];
    int rc;

    if (reims_vgpu_qemu_abi_version() != REIMS_VGPU_QEMU_ABI_VERSION) {
        error_setg(errp,
                   "%s: ABI version mismatch (header %u, staticlib %u)",
                   TYPE_REIMS_VGPU_MMIO, REIMS_VGPU_QEMU_ABI_VERSION,
                   reims_vgpu_qemu_abi_version());
        return;
    }

    s->host_ops = (ReimsVgpuHostOps){
        .abi_version = REIMS_VGPU_QEMU_ABI_VERSION,
        .struct_size = sizeof(ReimsVgpuHostOps),
        .ctx = s,
        .read_gpa = reims_vgpu_shim_read_gpa,
        .write_gpa = reims_vgpu_shim_write_gpa,
        .mono_ns = reims_vgpu_shim_mono_ns,
        .schedule_bh = reims_vgpu_mmio_schedule_bh,
        .read_kva = reims_vgpu_shim_read_kva,
        .read_xreg = reims_vgpu_mmio_read_xreg,
        .map_pages = reims_vgpu_mmio_map_pages,
        .unmap_pages = reims_vgpu_mmio_unmap_pages,
        /*
         * Where guest RAM lives. The same implementation the PCI shim points
         * at: it reads the system address space and never builds a view, so the
         * mach_vm_remap lifetime this shim owns for map_pages does not apply
         * and there is nothing bus-specific left to hold.
         *
         * This is also why the import rail does not re-open the retention that
         * map_pages_stable below refuses. An import is over the RAMBlock these
         * spans name, never over a packed remap view, and a fragmented surface
         * is several offsets inside one span rather than a view somebody has to
         * keep alive until teardown.
         */
        .guest_ram_regions = reims_vgpu_shim_guest_ram_regions,
        .is_ram_gpa = reims_vgpu_shim_is_ram_gpa,
        .notify_actions = reims_vgpu_mmio_notify_actions,
        /*
         * Darwin can return transient packed mach_vm_remap views. Linux only
         * accepts direct RAMBlock aliases, which remain valid for the VM
         * lifetime and require no unmap.
         *
         * The GPU rail does not read this and must not: it imports the spans
         * guest_ram_regions names, which are RAMBlock mappings this shim never
         * built and never releases.
         */
#if defined(CONFIG_DARWIN)
        .map_pages_stable = 0,
#else
        .map_pages_stable = 1,
#endif
        .track_guest_writes = reims_vgpu_mmio_track_guest_writes,
        .untrack_guest_writes = reims_vgpu_mmio_untrack_guest_writes,
        .guest_write_gen = reims_vgpu_mmio_guest_write_gen,
        .guest_written_pages = reims_vgpu_mmio_guest_written_pages,
    };
    s->dirty = reims_vgpu_dirty_new();
    reims_vgpu_worker_init(&s->drain_worker, reims_vgpu_mmio_drain, s);
    s->action_bh = aio_bh_new(qemu_get_aio_context(), reims_vgpu_mmio_bh, s);

    info = (ReimsVgpuQemuCreateInfo){
        .abi_version = REIMS_VGPU_QEMU_ABI_VERSION,
        .struct_size = sizeof(ReimsVgpuQemuCreateInfo),
        .host_ops = &s->host_ops,
        /* arm64e / vmapple guest: 16 KiB pages. */
        .guest_page_shift = REIMS_VGPU_GUEST_PAGE_SHIFT_ARM64E,
    };

    rc = reims_vgpu_qemu_device_create(&info, &out);
    if (rc != REIMS_VGPU_QEMU_OK || out.handle == 0) {
        error_setg(errp, "%s: reims_vgpu_qemu_device_create failed (rc=%d)",
                   TYPE_REIMS_VGPU_MMIO, rc);
        qemu_bh_delete(s->action_bh);
        s->action_bh = NULL;
        reims_vgpu_worker_destroy(&s->drain_worker);
        reims_vgpu_dirty_free(s->dirty);
        s->dirty = NULL;
        return;
    }
    s->rust_handle = out.handle;
    reims_vgpu_worker_start(&s->drain_worker, "reims-vgpu-mmio-drain");
    s->shutdown_notifier.notify = reims_vgpu_mmio_shutdown_notifier;
    qemu_register_shutdown_notifier(&s->shutdown_notifier);
    s->shutdown_notifier_registered = true;

    /*
     * Console only at realize (apple-gfx / archive apple-pv-gpu). Surface size
     * comes from the first ScanoutUpdate (guest-presented geom via Rust), the
     * same role as PGDisplay modeChangeHandler → set_mode. Optional black
     * preferred-mode surface matches archive mode-list EFI boot dims so the
     * cocoa window is not zero-sized before the first present.
     */
    s->con = qemu_graphic_console_create(dev, 0, &reims_vgpu_mmio_fb_ops, s);
    reims_vgpu_mmio_set_mode(s, REIMS_VGPU_EFI_BOOT_WIDTH, REIMS_VGPU_EFI_BOOT_HEIGHT);
    if (s->surface) {
        memset(surface_data(s->surface), 0,
               (size_t)surface_stride(s->surface) * REIMS_VGPU_EFI_BOOT_HEIGHT);
        qemu_console_update_full(s->con);
    }
    /* Hidden software cursor until the guest sends a glyph/show. */
    qemu_console_set_cursor(s->con, cursor_builtin_hidden());
    qemu_console_set_mouse(s->con, 0, 0, false);

    rc = reims_vgpu_qemu_window_start(s->rust_handle, REIMS_VGPU_EFI_BOOT_WIDTH,
                               REIMS_VGPU_EFI_BOOT_HEIGHT);
    if (rc == REIMS_VGPU_QEMU_OK) {
        s->poll_timer = timer_new_ms(QEMU_CLOCK_HOST,
                                     reims_vgpu_mmio_poll_tick, s);
        timer_mod(s->poll_timer, qemu_clock_get_ms(QEMU_CLOCK_HOST));
#if defined(CONFIG_DARWIN)
        reims_vgpu_mmio_window_owner = s;
        qemu_main = reims_vgpu_mmio_window_main_loop;
#endif
    } else {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: host window unavailable rc=%d; using QEMU display\n",
                      TYPE_REIMS_VGPU_MMIO, rc);
    }

    backend[0] = '\0';
    reims_vgpu_qemu_backend_name(backend, sizeof(backend));
    trace_reims_vgpu_mmio_realize(s->rust_handle, backend);
}

static void reims_vgpu_mmio_unrealize(DeviceState *dev)
{
    ReimsVGPUMMIOState *s = REIMS_VGPU_MMIO(dev);

    if (s->shutdown_notifier_registered) {
        notifier_remove(&s->shutdown_notifier);
        s->shutdown_notifier_registered = false;
    }
    reims_vgpu_mmio_stop_backend(s);
#if defined(CONFIG_DARWIN)
    if (reims_vgpu_mmio_window_owner == s) {
        reims_vgpu_mmio_window_owner = NULL;
    }
#endif
    /* After the Rust device is destroyed: no tracked set may outlive the
     * token holder, and the free turns region logging back off. */
    reims_vgpu_dirty_free(s->dirty);
    s->dirty = NULL;
    reims_vgpu_mmio_free_page_views(s);
    g_clear_pointer(&s->page_views, g_array_unref);
    reims_vgpu_worker_destroy(&s->drain_worker);
    if (s->con) {
        qemu_console_set_surface(s->con, NULL);
    }
    s->surface = NULL;
}

static void reims_vgpu_mmio_reset(DeviceState *dev)
{
    ReimsVGPUMMIOState *s = REIMS_VGPU_MMIO(dev);
    int rc;

    assert(bql_locked());
    reims_vgpu_worker_pause(&s->drain_worker);
    if (s->rust_handle != 0) {
        rc = reims_vgpu_qemu_device_reset(s->rust_handle);
        if (rc != REIMS_VGPU_QEMU_OK) {
            qemu_log_mask(LOG_GUEST_ERROR, "%s: reset failed rc=%d\n",
                          TYPE_REIMS_VGPU_MMIO, rc);
            reims_vgpu_worker_resume(&s->drain_worker);
            reims_vgpu_worker_schedule(&s->drain_worker);
            return;
        }
    }
    if (s->action_bh) {
        qemu_bh_cancel(s->action_bh);
    }
    /* No worker may access packed aliases between reset and their release. */
    reims_vgpu_mmio_free_page_views(s);
    /* Edge-triggered completion IRQs; leave lines deasserted at reset. */
    qemu_set_irq(s->irq_gfx, 0);
    qemu_set_irq(s->irq_iosfc, 0);
    s->new_frame_ready = false;

    /* Restore EFI black surface. */
    reims_vgpu_mmio_set_mode(s, REIMS_VGPU_EFI_BOOT_WIDTH, REIMS_VGPU_EFI_BOOT_HEIGHT);
    if (s->surface && s->con) {
        memset(surface_data(s->surface), 0,
               (size_t)surface_stride(s->surface) * REIMS_VGPU_EFI_BOOT_HEIGHT);
        qemu_console_set_cursor(s->con, cursor_builtin_hidden());
        qemu_console_set_mouse(s->con, 0, 0, false);
        s->new_frame_ready = true;
        qemu_console_update_full(s->con);
        s->new_frame_ready = false;
    }
    reims_vgpu_worker_resume(&s->drain_worker);
}

static void reims_vgpu_mmio_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->desc = "macOS Paravirtualized GPU (Rust host path)";
    dc->realize = reims_vgpu_mmio_realize;
    dc->unrealize = reims_vgpu_mmio_unrealize;
    device_class_set_legacy_reset(dc, reims_vgpu_mmio_reset);
    /* Created by the vmapple machine (gfx-device property), never -device. */
    dc->user_creatable = false;
    dc->hotpluggable = false;
}

static const TypeInfo reims_vgpu_mmio_types[] = {
    {
        .name = TYPE_REIMS_VGPU_MMIO,
        .parent = TYPE_SYS_BUS_DEVICE,
        .instance_size = sizeof(ReimsVGPUMMIOState),
        .instance_init = reims_vgpu_mmio_init,
        .class_init = reims_vgpu_mmio_class_init,
    },
};

DEFINE_TYPES(reims_vgpu_mmio_types)
