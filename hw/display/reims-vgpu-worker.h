/*
 * Shared Reims vGPU drain-worker lifetime and wakeups.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef REIMS_VGPU_WORKER_H
#define REIMS_VGPU_WORKER_H

#include "qemu/thread.h"

typedef struct ReimsVgpuWorker {
    QemuThread thread;
    QemuMutex mutex;
    QemuCond cond;
    void (*run)(void *);
    void *opaque;
    bool pending;
    bool busy;
    bool paused;
    bool stopping;
    bool started;
} ReimsVgpuWorker;

/*
 * Management calls are serialized by the owner; only schedule may race with
 * them. Callbacks run on one RCU-registered thread without acquiring the BQL.
 * Initialize before publishing the worker to producers, which may schedule
 * before start. Stop producers before destroy.
 */
void reims_vgpu_worker_init(ReimsVgpuWorker *worker, void (*run)(void *),
                            void *opaque);
void reims_vgpu_worker_start(ReimsVgpuWorker *worker, const char *name);
void reims_vgpu_worker_schedule(ReimsVgpuWorker *worker);
/* Quiesce and discard old wakeups; new requests while paused survive resume. */
void reims_vgpu_worker_pause(ReimsVgpuWorker *worker);
void reims_vgpu_worker_resume(ReimsVgpuWorker *worker);
/* Terminal and idempotent, including before start; joins any active callback. */
void reims_vgpu_worker_stop(ReimsVgpuWorker *worker);
void reims_vgpu_worker_destroy(ReimsVgpuWorker *worker);

#endif
