/*
 * ARM KVM non-ISV VGIC MMIO regression test.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "libqtest.h"

#ifdef CONFIG_LINUX
#include <sys/ioctl.h>
#include <linux/kvm.h>
#endif

#define CODE_BASE   0x40010000
#define RESULT_BASE 0x40100000
#define RESULT(cpu) (RESULT_BASE + (cpu) * 0x100)

/*
 * CPU 0 first writes GICR_IGROUPR0 while CPU 1 is powered off, then starts
 * CPU 1 with PSCI. Both CPUs repeatedly use pre-indexed stores and
 * post-indexed loads on their own redistributor, checking writeback and
 * comparing the result with an ordinary in-kernel MMIO load. Each CPU
 * reports 1 on success or 2 on failure before waiting in WFI.
 */
static const uint32_t guest_code[] = {
    0xd2a80214, /* mov x20, #0x40100000 */
    0xd53800b5, /* mrs x21, mpidr_el1 */
    0x92401eb5, /* and x21, x21, #0xff */
    0x8b152294, /* add x20, x20, x21, lsl #8 */
    0xd2a10176, /* mov x22, #0x080b0000 (CPU 0 SGI frame) */
    0x8b1546d6, /* add x22, x22, x21, lsl #17 */
    0xaa1603e8, /* mov x8, x22 */
    0x3201f3e9, /* mov w9, #0xaaaaaaaa */
    0xb8080d09, /* str w9, [x8, #0x80]! */
    0xb5000115, /* cbnz x21, loop_setup */
    0xd2800060, /* mov x0, #3 */
    0xf2b88000, /* movk x0, #0xc400, lsl #16 (PSCI CPU_ON) */
    0xd2800021, /* mov x1, #1 */
    0x10fffe62, /* adr x2, guest_code */
    0xd2800003, /* mov x3, #0 */
    0xd4000002, /* hvc #0 */
    0xb50002e0, /* cbnz x0, fail */
    0x52800817, /* loop_setup: mov w23, #64 */
    0xaa1603e8, /* loop: mov x8, x22 */
    0xb8080d09, /* str w9, [x8, #0x80]! */
    0x910202ca, /* add x10, x22, #0x80 */
    0xeb0a011f, /* cmp x8, x10 */
    0x54000221, /* b.ne fail */
    0xb840450b, /* ldr w11, [x8], #4 */
    0x6b09017f, /* cmp w11, w9 */
    0x540001c1, /* b.ne fail */
    0x910212ca, /* add x10, x22, #0x84 */
    0xeb0a011f, /* cmp x8, x10 */
    0x54000161, /* b.ne fail */
    0xb94082cb, /* ldr w11, [x22, #0x80] */
    0x6b09017f, /* cmp w11, w9 */
    0x54000101, /* b.ne fail */
    0x2a2903e9, /* mvn w9, w9 */
    0x710006f7, /* subs w23, w23, #1 */
    0x54fffe01, /* b.ne loop */
    0x52800020, /* mov w0, #1 */
    0xb9000280, /* str w0, [x20] */
    0xd503207f, /* wait: wfi */
    0x17ffffff, /* b wait */
    0x52800040, /* fail: mov w0, #2 */
    0xb9000280, /* str w0, [x20] */
    0x17fffffc, /* b wait */
};

static bool host_supports_test(void)
{
#ifdef CONFIG_LINUX
    struct kvm_create_device dev = {
        .type = KVM_DEV_TYPE_ARM_VGIC_V3,
        .flags = KVM_CREATE_DEVICE_TEST,
    };
    int fd = open("/dev/kvm", O_RDWR);
    int ipa_bits;
    int vm;
    bool supported = false;

    if (fd < 0) {
        return false;
    }
    if (ioctl(fd, KVM_CHECK_EXTENSION, KVM_CAP_ARM_NISV_TO_USER) > 0) {
        ipa_bits = ioctl(fd, KVM_CHECK_EXTENSION, KVM_CAP_ARM_VM_IPA_SIZE);
        vm = ioctl(fd, KVM_CREATE_VM, ipa_bits > 0 ? ipa_bits : 0);
        if (vm >= 0) {
            supported = ioctl(vm, KVM_CREATE_DEVICE, &dev) == 0;
            close(vm);
        }
    }
    close(fd);
    return supported;
#else
    return false;
#endif
}

static void test_vgic_nisv(void)
{
    QTestState *qts;

    if (!host_supports_test()) {
        g_test_skip("KVM ARM NISV exits and VGICv3 are required");
        return;
    }

    qts = qtest_init("-machine virt,gic-version=3 -accel kvm -cpu host "
                     "-smp 2 -m 64M -nodefaults -S "
                     "-device loader,addr=0x40010000,cpu-num=0");
    for (int round = 0; round < 2; round++) {
        int64_t deadline;
        uint32_t results[2];

        for (size_t i = 0; i < ARRAY_SIZE(guest_code); i++) {
            qtest_writel(qts, CODE_BASE + i * 4, guest_code[i]);
        }
        qtest_writel(qts, RESULT(0), 0);
        qtest_writel(qts, RESULT(1), 0);
        qtest_qmp_assert_success(qts, "{ 'execute': 'cont' }");

        /* Exercise management pauses alongside the exclusive slow path. */
        for (int i = 0; i < 3; i++) {
            g_usleep(1000);
            qtest_qmp_assert_success(qts, "{ 'execute': 'stop' }");
            qtest_qmp_assert_success(qts, "{ 'execute': 'cont' }");
        }

        deadline = g_get_monotonic_time() + 20 * G_TIME_SPAN_SECOND;
        do {
            results[0] = qtest_readl(qts, RESULT(0));
            results[1] = qtest_readl(qts, RESULT(1));
            g_assert_cmpuint(results[0], !=, 2);
            g_assert_cmpuint(results[1], !=, 2);
            if (g_get_monotonic_time() >= deadline) {
                g_autofree char *regs = qtest_hmp(qts, "info registers -a");

                g_test_message("Round %d, guest results: %u, %u, code: %08x\n%s",
                               round, results[0], results[1],
                               qtest_readl(qts, CODE_BASE), regs);
            }
            g_assert_cmpint(g_get_monotonic_time(), <, deadline);
            g_usleep(1000);
        } while (results[0] != 1 || results[1] != 1);

        qtest_qmp_assert_success(qts, "{ 'execute': 'stop' }");
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
        qtest_add_func("/arm/kvm/vgic-nisv", test_vgic_nisv);
    }
    return g_test_run();
}
