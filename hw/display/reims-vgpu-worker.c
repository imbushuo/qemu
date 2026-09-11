/*
 * Shared Reims vGPU drain-worker lifetime and wakeups.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu/rcu.h"
#include "reims-vgpu-worker.h"

static void *reims_vgpu_worker_thread(void *opaque)
{
    ReimsVgpuWorker *worker = opaque;

    rcu_register_thread();
    qemu_mutex_lock(&worker->mutex);
    for (;;) {
        while (!worker->stopping && (worker->paused || !worker->pending)) {
            qemu_cond_wait(&worker->cond, &worker->mutex);
        }
        if (worker->stopping) {
            break;
        }

        worker->pending = false;
        worker->busy = true;
        qemu_mutex_unlock(&worker->mutex);
        worker->run(worker->opaque);
        qemu_mutex_lock(&worker->mutex);
        worker->busy = false;
        qemu_cond_broadcast(&worker->cond);
    }
    qemu_mutex_unlock(&worker->mutex);
    rcu_unregister_thread();
    return NULL;
}

void reims_vgpu_worker_init(ReimsVgpuWorker *worker, void (*run)(void *),
                            void *opaque)
{
    assert(run);
    *worker = (ReimsVgpuWorker) {
        .run = run,
        .opaque = opaque,
    };
    qemu_mutex_init(&worker->mutex);
    qemu_cond_init(&worker->cond);
}

void reims_vgpu_worker_start(ReimsVgpuWorker *worker, const char *name)
{
    qemu_mutex_lock(&worker->mutex);
    if (!worker->started && !worker->stopping) {
        worker->started = true;
        qemu_thread_create(&worker->thread, name, reims_vgpu_worker_thread,
                           worker, QEMU_THREAD_JOINABLE);
    }
    qemu_mutex_unlock(&worker->mutex);
}

void reims_vgpu_worker_schedule(ReimsVgpuWorker *worker)
{
    qemu_mutex_lock(&worker->mutex);
    if (!worker->stopping) {
        worker->pending = true;
        qemu_cond_signal(&worker->cond);
    }
    qemu_mutex_unlock(&worker->mutex);
}

void reims_vgpu_worker_pause(ReimsVgpuWorker *worker)
{
    qemu_mutex_lock(&worker->mutex);
    if (!worker->stopping) {
        if (!worker->paused) {
            worker->paused = true;
            /* Clear only on entry, not requests arriving while we quiesce. */
            worker->pending = false;
            qemu_cond_broadcast(&worker->cond);
        }
        while (worker->busy) {
            qemu_cond_wait(&worker->cond, &worker->mutex);
        }
    }
    qemu_mutex_unlock(&worker->mutex);
}

void reims_vgpu_worker_resume(ReimsVgpuWorker *worker)
{
    qemu_mutex_lock(&worker->mutex);
    if (!worker->stopping) {
        worker->paused = false;
        qemu_cond_signal(&worker->cond);
    }
    qemu_mutex_unlock(&worker->mutex);
}

void reims_vgpu_worker_stop(ReimsVgpuWorker *worker)
{
    bool started;

    qemu_mutex_lock(&worker->mutex);
    worker->stopping = true;
    worker->pending = false;
    started = worker->started;
    qemu_cond_broadcast(&worker->cond);
    qemu_mutex_unlock(&worker->mutex);

    if (started) {
        qemu_thread_join(&worker->thread);
        qemu_mutex_lock(&worker->mutex);
        worker->started = false;
        qemu_mutex_unlock(&worker->mutex);
    }
}

void reims_vgpu_worker_destroy(ReimsVgpuWorker *worker)
{
    reims_vgpu_worker_stop(worker);
    qemu_cond_destroy(&worker->cond);
    qemu_mutex_destroy(&worker->mutex);
}
