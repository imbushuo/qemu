/*
 * Reims vGPU drain-worker synchronization tests.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu/notify.h"
#include "qemu/rcu.h"
#include "hw/display/reims-vgpu-worker.h"

#define WAIT_MS 5000

typedef struct WorkerTest {
    ReimsVgpuWorker worker;
    QemuSemaphore entered;
    QemuSemaphore release;
    QemuSemaphore forced;
    Notifier force_rcu;
    Notifier thread_exit;
    unsigned runs;
    bool test_rcu;
    bool exited;
} WorkerTest;

typedef struct Control {
    ReimsVgpuWorker *worker;
    void (*action)(ReimsVgpuWorker *);
    QemuThread thread;
    QemuSemaphore done;
} Control;

static void wait_sem(QemuSemaphore *sem)
{
    g_assert_cmpint(qemu_sem_timedwait(sem, WAIT_MS), ==, 0);
}

static void assert_not_posted(QemuSemaphore *sem)
{
    g_assert_cmpint(qemu_sem_timedwait(sem, 0), ==, -1);
}

static void force_rcu(Notifier *notifier, void *unused)
{
    WorkerTest *test = container_of(notifier, WorkerTest, force_rcu);

    qemu_sem_post(&test->forced);
}

static void thread_exit(Notifier *notifier, void *unused)
{
    WorkerTest *test = container_of(notifier, WorkerTest, thread_exit);

    qatomic_set(&test->exited, true);
}

static void run(void *opaque)
{
    WorkerTest *test = opaque;

    g_assert_true(qemu_thread_is_self(&test->worker.thread));
    if (test->test_rcu) {
        rcu_add_force_rcu_notifier(&test->force_rcu);
        rcu_read_lock();
    }
    if (qatomic_fetch_inc(&test->runs) == 0) {
        qemu_thread_atexit_add(&test->thread_exit);
    }
    qemu_sem_post(&test->entered);
    wait_sem(&test->release);
    if (test->test_rcu) {
        rcu_read_unlock();
        rcu_remove_force_rcu_notifier(&test->force_rcu);
    }
}

static void test_init(WorkerTest *test)
{
    *test = (WorkerTest) {
        .force_rcu.notify = force_rcu,
        .thread_exit.notify = thread_exit,
    };
    qemu_sem_init(&test->entered, 0);
    qemu_sem_init(&test->release, 0);
    qemu_sem_init(&test->forced, 0);
    reims_vgpu_worker_init(&test->worker, run, test);
}

static void test_destroy(WorkerTest *test)
{
    reims_vgpu_worker_destroy(&test->worker);
    if (qatomic_read(&test->runs)) {
        g_assert_true(qatomic_read(&test->exited));
    }
    qemu_sem_destroy(&test->forced);
    qemu_sem_destroy(&test->release);
    qemu_sem_destroy(&test->entered);
}

static void *control_thread(void *opaque)
{
    Control *control = opaque;

    control->action(control->worker);
    qemu_sem_post(&control->done);
    return NULL;
}

static void control_start(Control *control, WorkerTest *test,
                          void (*action)(ReimsVgpuWorker *))
{
    control->worker = &test->worker;
    control->action = action;
    qemu_sem_init(&control->done, 0);
    qemu_thread_create(&control->thread, "worker-control", control_thread,
                       control, QEMU_THREAD_JOINABLE);
}

static void control_join(Control *control)
{
    wait_sem(&control->done);
    qemu_thread_join(&control->thread);
    qemu_sem_destroy(&control->done);
}

static void wait_flag(ReimsVgpuWorker *worker, bool *flag, bool value)
{
    int64_t deadline = g_get_monotonic_time() + WAIT_MS * 1000;

    qemu_mutex_lock(&worker->mutex);
    while (*flag != value) {
        int64_t remaining = deadline - g_get_monotonic_time();

        g_assert_cmpint(remaining, >, 0);
        qemu_cond_timedwait(&worker->cond, &worker->mutex,
                            DIV_ROUND_UP(remaining, 1000));
    }
    qemu_mutex_unlock(&worker->mutex);
}

static void assert_state(WorkerTest *test, bool busy, bool pending)
{
    qemu_mutex_lock(&test->worker.mutex);
    g_assert_cmpint(test->worker.busy, ==, busy);
    g_assert_cmpint(test->worker.pending, ==, pending);
    qemu_mutex_unlock(&test->worker.mutex);
}

static void test_before_start(void)
{
    WorkerTest test;

    test_init(&test);
    for (int i = 0; i < 32; i++) {
        reims_vgpu_worker_schedule(&test.worker);
    }
    g_assert_cmpuint(qatomic_read(&test.runs), ==, 0);
    reims_vgpu_worker_start(&test.worker, "worker-test");
    reims_vgpu_worker_start(&test.worker, "worker-test");
    wait_sem(&test.entered);
    assert_state(&test, true, false);
    qemu_sem_post(&test.release);
    reims_vgpu_worker_pause(&test.worker);
    g_assert_cmpuint(qatomic_read(&test.runs), ==, 1);
    assert_not_posted(&test.entered);
    test_destroy(&test);
}

static void *schedule_thread(void *opaque)
{
    ReimsVgpuWorker *worker = opaque;

    for (int i = 0; i < 32; i++) {
        reims_vgpu_worker_schedule(worker);
    }
    return NULL;
}

static void test_during_run(void)
{
    WorkerTest test;
    QemuThread producers[4];

    test_init(&test);
    reims_vgpu_worker_start(&test.worker, "worker-test");
    reims_vgpu_worker_schedule(&test.worker);
    wait_sem(&test.entered);
    for (int i = 0; i < ARRAY_SIZE(producers); i++) {
        qemu_thread_create(&producers[i], "worker-producer", schedule_thread,
                           &test.worker, QEMU_THREAD_JOINABLE);
    }
    for (int i = 0; i < ARRAY_SIZE(producers); i++) {
        qemu_thread_join(&producers[i]);
    }
    assert_state(&test, true, true);
    qemu_sem_post(&test.release);
    wait_sem(&test.entered);
    assert_state(&test, true, false);
    qemu_sem_post(&test.release);
    reims_vgpu_worker_pause(&test.worker);
    g_assert_cmpuint(qatomic_read(&test.runs), ==, 2);
    assert_not_posted(&test.entered);
    test_destroy(&test);
}

static void test_pause(void)
{
    WorkerTest test;
    Control control;

    test_init(&test);
    reims_vgpu_worker_start(&test.worker, "worker-test");
    reims_vgpu_worker_schedule(&test.worker);
    wait_sem(&test.entered);
    reims_vgpu_worker_schedule(&test.worker);
    assert_state(&test, true, true);

    control_start(&control, &test, reims_vgpu_worker_pause);
    wait_flag(&test.worker, &test.worker.paused, true);
    assert_state(&test, true, false);
    assert_not_posted(&control.done);
    /* New requests survive even if they arrive while pause is still waiting. */
    reims_vgpu_worker_schedule(&test.worker);
    reims_vgpu_worker_schedule(&test.worker);
    qemu_sem_post(&test.release);
    control_join(&control);
    assert_state(&test, false, true);
    g_assert_cmpuint(qatomic_read(&test.runs), ==, 1);
    assert_not_posted(&test.entered);

    reims_vgpu_worker_pause(&test.worker);
    reims_vgpu_worker_resume(&test.worker);
    wait_sem(&test.entered);
    assert_state(&test, true, false);
    qemu_sem_post(&test.release);
    reims_vgpu_worker_pause(&test.worker);
    g_assert_cmpuint(qatomic_read(&test.runs), ==, 2);
    assert_not_posted(&test.entered);

    reims_vgpu_worker_schedule(&test.worker);
    assert_state(&test, false, true);
    reims_vgpu_worker_resume(&test.worker);
    wait_sem(&test.entered);
    qemu_sem_post(&test.release);
    reims_vgpu_worker_pause(&test.worker);
    g_assert_cmpuint(qatomic_read(&test.runs), ==, 3);
    test_destroy(&test);
}

static void assert_stopped(WorkerTest *test, unsigned runs)
{
    reims_vgpu_worker_schedule(&test->worker);
    reims_vgpu_worker_resume(&test->worker);
    reims_vgpu_worker_start(&test->worker, "must-not-restart");
    reims_vgpu_worker_pause(&test->worker);
    reims_vgpu_worker_stop(&test->worker);
    assert_state(test, false, false);
    qemu_mutex_lock(&test->worker.mutex);
    g_assert_false(test->worker.started);
    g_assert_true(test->worker.stopping);
    qemu_mutex_unlock(&test->worker.mutex);
    g_assert_cmpuint(qatomic_read(&test->runs), ==, runs);
    if (runs) {
        g_assert_true(qatomic_read(&test->exited));
    }
    assert_not_posted(&test->entered);
}

static void test_stop_busy(void)
{
    WorkerTest test;
    Control control;

    test_init(&test);
    reims_vgpu_worker_start(&test.worker, "worker-test");
    reims_vgpu_worker_schedule(&test.worker);
    wait_sem(&test.entered);
    reims_vgpu_worker_schedule(&test.worker);

    control_start(&control, &test, reims_vgpu_worker_stop);
    wait_flag(&test.worker, &test.worker.stopping, true);
    assert_state(&test, true, false);
    assert_not_posted(&control.done);
    reims_vgpu_worker_schedule(&test.worker);
    assert_state(&test, true, false);
    qemu_sem_post(&test.release);
    control_join(&control);
    assert_stopped(&test, 1);
    test_destroy(&test);
}

static void test_stop_idle(void)
{
    WorkerTest test;

    test_init(&test);
    reims_vgpu_worker_start(&test.worker, "worker-test");
    reims_vgpu_worker_schedule(&test.worker);
    wait_sem(&test.entered);
    qemu_sem_post(&test.release);
    wait_flag(&test.worker, &test.worker.busy, false);
    reims_vgpu_worker_stop(&test.worker);
    assert_stopped(&test, 1);
    test_destroy(&test);
}

static void test_stop_paused(void)
{
    WorkerTest test;

    test_init(&test);
    reims_vgpu_worker_start(&test.worker, "worker-test");
    reims_vgpu_worker_schedule(&test.worker);
    wait_sem(&test.entered);
    qemu_sem_post(&test.release);
    reims_vgpu_worker_pause(&test.worker);
    reims_vgpu_worker_schedule(&test.worker);
    reims_vgpu_worker_stop(&test.worker);
    assert_stopped(&test, 1);
    test_destroy(&test);
}

static void test_stop_before_start(void)
{
    WorkerTest test;

    test_init(&test);
    reims_vgpu_worker_schedule(&test.worker);
    reims_vgpu_worker_stop(&test.worker);
    assert_stopped(&test, 0);
    test_destroy(&test);
}

static void sync_rcu(ReimsVgpuWorker *unused)
{
    synchronize_rcu();
}

static void test_rcu(void)
{
    WorkerTest test;
    Control control;

    test_init(&test);
    test.test_rcu = true;
    reims_vgpu_worker_start(&test.worker, "worker-test");
    reims_vgpu_worker_schedule(&test.worker);
    wait_sem(&test.entered);
    control_start(&control, &test, sync_rcu);
    /* The grace-period waiter must see the worker's registered reader. */
    wait_sem(&test.forced);
    assert_not_posted(&control.done);
    qemu_sem_post(&test.release);
    control_join(&control);
    reims_vgpu_worker_stop(&test.worker);
    synchronize_rcu();
    g_assert_cmpuint(qatomic_read(&test.runs), ==, 1);
    test_destroy(&test);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/reims-vgpu-worker/before-start", test_before_start);
    g_test_add_func("/reims-vgpu-worker/during-run", test_during_run);
    g_test_add_func("/reims-vgpu-worker/pause", test_pause);
    g_test_add_func("/reims-vgpu-worker/stop/busy", test_stop_busy);
    g_test_add_func("/reims-vgpu-worker/stop/idle", test_stop_idle);
    g_test_add_func("/reims-vgpu-worker/stop/paused", test_stop_paused);
    g_test_add_func("/reims-vgpu-worker/stop/before-start",
                    test_stop_before_start);
    g_test_add_func("/reims-vgpu-worker/rcu", test_rcu);
    return g_test_run();
}
