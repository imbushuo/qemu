/*
 * ARM KVM VMApple regression tests.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "libqtest.h"

#if defined(CONFIG_LINUX) && defined(__aarch64__)
#include <sys/ioctl.h>
#include <linux/kvm.h>
#endif

#define CODE_BASE   0x40010000
#define RESULT_BASE 0x40100000
#define DONE_ADDR   (RESULT_BASE + 40)

/*
 * Query the default keys without requiring host pointer authentication.
 * Save x0-x4 so the test checks both the status and the output registers.
 */
static const uint32_t guest_code[] = {
    0xd2800020, /* mov x0, #1 */
    0xf2b82000, /* movk x0, #0xc100, lsl #16 */
    0xd4000002, /* hvc #0 */
    0xd2a80205, /* mov x5, #0x40100000 */
    0xa90004a0, /* stp x0, x1, [x5] */
    0xa9010ca2, /* stp x2, x3, [x5, #16] */
    0xf90010a4, /* str x4, [x5, #32] */
    0xd5033fbf, /* dmb sy */
    0x52800026, /* mov w6, #1 */
    0xb90028a6, /* str w6, [x5, #40] */
    0xd503207f, /* wait: wfi */
    0x17ffffff, /* b wait */
};

static bool host_supports_test(bool writable_imp_id_regs, bool in_kernel_hvc)
{
#if defined(CONFIG_LINUX) && defined(__aarch64__)
    struct kvm_create_device dev = {
        .type = KVM_DEV_TYPE_ARM_VGIC_V3,
        .flags = KVM_CREATE_DEVICE_TEST,
    };
    struct kvm_device_attr attr = {
        .group = KVM_ARM_VM_SMCCC_CTRL,
        .attr = KVM_ARM_VM_SMCCC_FILTER,
    };
    struct kvm_enable_cap cap = {
        .cap = KVM_CAP_ARM_APPLE_HYPERVISOR_FUNCTIONS,
    };
    int fd = open("/dev/kvm", O_RDWR);
    int ipa_bits;
    int vm;
    bool supported = false;

    if (fd < 0) {
        return false;
    }
    ipa_bits = ioctl(fd, KVM_CHECK_EXTENSION, KVM_CAP_ARM_VM_IPA_SIZE);
    vm = ioctl(fd, KVM_CREATE_VM, ipa_bits > 0 ? ipa_bits : 0);
    if (vm >= 0) {
        supported = (in_kernel_hvc ?
                     (ioctl(fd, KVM_CHECK_EXTENSION, cap.cap) > 0 &&
                      ioctl(vm, KVM_ENABLE_CAP, &cap) == 0) :
                     ioctl(vm, KVM_HAS_DEVICE_ATTR, &attr) == 0) &&
                    ioctl(vm, KVM_CREATE_DEVICE, &dev) == 0 &&
                    (!writable_imp_id_regs ||
                     ioctl(fd, KVM_CHECK_EXTENSION,
                           KVM_CAP_ARM_WRITABLE_IMP_ID_REGS) > 0);
        close(vm);
    }
    close(fd);
    return supported;
#else
    return false;
#endif
}

static void test_vmapple_hvc_return(const void *opaque)
{
    static const uint64_t expected[] = {
        0,
        0xfeedfacefeedfad5ULL,
        0xfeedfacefeedfacfULL,
        0xfeedfacefeedfad3ULL,
        0xfeedfacefeedfad9ULL,
    };
    bool in_kernel_hvc = GPOINTER_TO_INT(opaque);
    g_autofree char *old_hvc = g_strdup(g_getenv("QEMU_VMAPPLE_KVM_HVC"));
    QTestState *qts;

    if (!host_supports_test(false, in_kernel_hvc)) {
        g_test_skip("KVM ARM hypercall support and VGICv3 are required");
        return;
    }

    if (in_kernel_hvc) {
        g_unsetenv("QEMU_VMAPPLE_KVM_HVC");
    } else {
        g_setenv("QEMU_VMAPPLE_KVM_HVC", "1", true);
    }
    qts = qtest_init("-machine virt,gic-version=3 -accel kvm -cpu host "
                     "-m 64M -nodefaults -S "
                     "-device loader,addr=0x40010000,cpu-num=0");
    if (old_hvc) {
        g_setenv("QEMU_VMAPPLE_KVM_HVC", old_hvc, true);
    } else {
        g_unsetenv("QEMU_VMAPPLE_KVM_HVC");
    }

    for (int round = 0; round < 2; round++) {
        int64_t deadline;

        for (size_t i = 0; i < ARRAY_SIZE(guest_code); i++) {
            qtest_writel(qts, CODE_BASE + i * 4, guest_code[i]);
        }
        qtest_writel(qts, DONE_ADDR, 0);
        qtest_qmp_assert_success(qts, "{ 'execute': 'cont' }");
        deadline = g_get_monotonic_time() + 20 * G_TIME_SPAN_SECOND;
        while (!qtest_readl(qts, DONE_ADDR)) {
            g_assert_cmpint(g_get_monotonic_time(), <, deadline);
            g_usleep(1000);
        }
        qtest_qmp_assert_success(qts, "{ 'execute': 'stop' }");
        for (size_t i = 0; i < ARRAY_SIZE(expected); i++) {
            g_assert_cmphex(qtest_readq(qts, RESULT_BASE + i * 8),
                            ==, expected[i]);
        }
        if (round == 0) {
            qtest_qmp_assert_success(qts, "{ 'execute': 'system_reset' }");
            qtest_qmp_eventwait(qts, "RESET");
        }
    }
    qtest_quit(qts);
}

static void test_vmapple_timer(const void *opaque)
{
    static const uint32_t timer_code[] = {
        0xd53be000, /* mrs x0, cntfrq_el0 */
        0xd53900e1, /* mrs x1, aidr_el1 */
        0xd2a80205, /* mov x5, #0x40100000 */
        0xa90004a0, /* stp x0, x1, [x5] */
        0xd5033fbf, /* dmb sy */
        0x52800026, /* mov w6, #1 */
        0xb90028a6, /* str w6, [x5, #40] */
        0xd503207f, /* wait: wfi */
        0x17ffffff, /* b wait */
    };
    const char *set_aidr = opaque;
    g_autofree char *old_set_aidr = g_strdup(g_getenv("XNU_SET_AIDR"));
    uint64_t expected_agt = set_aidr && set_aidr[0] ? 1ULL << 32 : 0;
    QTestState *qts;

    if (!host_supports_test(true, false)) {
        g_test_skip("KVM ARM writable implementation ID registers, "
                    "userspace hypercalls and VGICv3 are required");
        return;
    }

    if (set_aidr) {
        g_setenv("XNU_SET_AIDR", set_aidr, true);
    } else {
        g_unsetenv("XNU_SET_AIDR");
    }
    qts = qtest_init("-machine virt,gic-version=3 -accel kvm -cpu host "
                     "-m 64M -nodefaults -S "
                     "-device loader,addr=0x40010000,cpu-num=0");
    if (old_set_aidr) {
        g_setenv("XNU_SET_AIDR", old_set_aidr, true);
    } else {
        g_unsetenv("XNU_SET_AIDR");
    }
    for (int round = 0; round < 2; round++) {
        int64_t deadline;
        uint64_t cntfrq;

        for (size_t i = 0; i < ARRAY_SIZE(timer_code); i++) {
            qtest_writel(qts, CODE_BASE + i * 4, timer_code[i]);
        }
        qtest_writel(qts, DONE_ADDR, 0);
        qtest_qmp_assert_success(qts, "{ 'execute': 'cont' }");
        deadline = g_get_monotonic_time() + 20 * G_TIME_SPAN_SECOND;
        while (!qtest_readl(qts, DONE_ADDR)) {
            g_assert_cmpint(g_get_monotonic_time(), <, deadline);
            g_usleep(1000);
        }
        qtest_qmp_assert_success(qts, "{ 'execute': 'stop' }");
        cntfrq = qtest_readq(qts, RESULT_BASE);
        if (cntfrq < 900000000ULL) {
            g_test_skip("A timer frequency of at least 900 MHz is required");
            break;
        }
        g_assert_cmphex(qtest_readq(qts, RESULT_BASE + 8) & (1ULL << 32),
                        ==, expected_agt);
        if (round == 0) {
            qtest_qmp_assert_success(qts, "{ 'execute': 'system_reset' }");
            qtest_qmp_eventwait(qts, "RESET");
        }
    }
    qtest_quit(qts);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    if (qtest_has_machine("virt") && qtest_has_accel("kvm")) {
        qtest_add_data_func("/arm/kvm/vmapple-hvc-return",
                           GINT_TO_POINTER(false), test_vmapple_hvc_return);
        qtest_add_data_func("/arm/kvm/vmapple-hvc-return-in-kernel",
                           GINT_TO_POINTER(true), test_vmapple_hvc_return);
        qtest_add_data_func("/arm/kvm/vmapple-timer/unset", NULL,
                           test_vmapple_timer);
        qtest_add_data_func("/arm/kvm/vmapple-timer/empty", "",
                           test_vmapple_timer);
        qtest_add_data_func("/arm/kvm/vmapple-timer/enabled", "1",
                           test_vmapple_timer);
        qtest_add_data_func("/arm/kvm/vmapple-timer/zero", "0",
                           test_vmapple_timer);
    }
    return g_test_run();
}
