/*
 * QEMU Hypervisor.framework support for Apple Silicon

 * Copyright 2020 Alexander Graf <agraf@csgraf.de>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qemu/error-report.h"

#include "sysemu/runstate.h"
#include "sysemu/hvf.h"
#include "sysemu/hvf_int.h"
#include "sysemu/hw_accel.h"

#include <Hypervisor/Hypervisor.h>

#include "exec/address-spaces.h"
#include "hw/irq.h"
#include "qemu/main-loop.h"
#include "sysemu/accel.h"
#include "sysemu/cpus.h"
#include "target/arm/cpu.h"
#include "target/arm/internals.h"

#define HVF_DEBUG 0
#define DPRINTF(...)                                        \
    if (HVF_DEBUG) {                                        \
        fprintf(stderr, "HVF %s:%d ", __func__, __LINE__);  \
        fprintf(stderr, __VA_ARGS__);                       \
        fprintf(stderr, "\n");                              \
    }

#define SYSREG(op0, op1, op2, crn, crm) \
    ((op0 << 20) | (op2 << 17) | (op1 << 14) | (crn << 10) | (crm << 1))
#define SYSREG_MASK           SYSREG(0x3, 0x7, 0x7, 0xf, 0xf)
#define SYSREG_CNTPCT_EL0     SYSREG(3, 3, 1, 14, 0)
#define SYSREG_PMCCNTR_EL0    SYSREG(3, 3, 0, 9, 13)

#define WFX_IS_WFE (1 << 0)

struct hvf_reg_match {
    int reg;
    uint64_t offset;
};

static const struct hvf_reg_match hvf_reg_match[] = {
    { HV_REG_X0,   offsetof(CPUARMState, xregs[0]) },
    { HV_REG_X1,   offsetof(CPUARMState, xregs[1]) },
    { HV_REG_X2,   offsetof(CPUARMState, xregs[2]) },
    { HV_REG_X3,   offsetof(CPUARMState, xregs[3]) },
    { HV_REG_X4,   offsetof(CPUARMState, xregs[4]) },
    { HV_REG_X5,   offsetof(CPUARMState, xregs[5]) },
    { HV_REG_X6,   offsetof(CPUARMState, xregs[6]) },
    { HV_REG_X7,   offsetof(CPUARMState, xregs[7]) },
    { HV_REG_X8,   offsetof(CPUARMState, xregs[8]) },
    { HV_REG_X9,   offsetof(CPUARMState, xregs[9]) },
    { HV_REG_X10,  offsetof(CPUARMState, xregs[10]) },
    { HV_REG_X11,  offsetof(CPUARMState, xregs[11]) },
    { HV_REG_X12,  offsetof(CPUARMState, xregs[12]) },
    { HV_REG_X13,  offsetof(CPUARMState, xregs[13]) },
    { HV_REG_X14,  offsetof(CPUARMState, xregs[14]) },
    { HV_REG_X15,  offsetof(CPUARMState, xregs[15]) },
    { HV_REG_X16,  offsetof(CPUARMState, xregs[16]) },
    { HV_REG_X17,  offsetof(CPUARMState, xregs[17]) },
    { HV_REG_X18,  offsetof(CPUARMState, xregs[18]) },
    { HV_REG_X19,  offsetof(CPUARMState, xregs[19]) },
    { HV_REG_X20,  offsetof(CPUARMState, xregs[20]) },
    { HV_REG_X21,  offsetof(CPUARMState, xregs[21]) },
    { HV_REG_X22,  offsetof(CPUARMState, xregs[22]) },
    { HV_REG_X23,  offsetof(CPUARMState, xregs[23]) },
    { HV_REG_X24,  offsetof(CPUARMState, xregs[24]) },
    { HV_REG_X25,  offsetof(CPUARMState, xregs[25]) },
    { HV_REG_X26,  offsetof(CPUARMState, xregs[26]) },
    { HV_REG_X27,  offsetof(CPUARMState, xregs[27]) },
    { HV_REG_X28,  offsetof(CPUARMState, xregs[28]) },
    { HV_REG_X29,  offsetof(CPUARMState, xregs[29]) },
    { HV_REG_X30,  offsetof(CPUARMState, xregs[30]) },
    { HV_REG_PC,   offsetof(CPUARMState, pc) },
};

static const struct hvf_reg_match hvf_sreg_match[] = {
    { HV_SYS_REG_DBGBVR0_EL1, offsetof(CPUARMState, cp15.dbgbvr[0]) },
    { HV_SYS_REG_DBGBCR0_EL1, offsetof(CPUARMState, cp15.dbgbcr[0]) },
    { HV_SYS_REG_DBGWVR0_EL1, offsetof(CPUARMState, cp15.dbgwvr[0]) },
    { HV_SYS_REG_DBGWCR0_EL1, offsetof(CPUARMState, cp15.dbgwcr[0]) },
    { HV_SYS_REG_DBGBVR1_EL1, offsetof(CPUARMState, cp15.dbgbvr[1]) },
    { HV_SYS_REG_DBGBCR1_EL1, offsetof(CPUARMState, cp15.dbgbcr[1]) },
    { HV_SYS_REG_DBGWVR1_EL1, offsetof(CPUARMState, cp15.dbgwvr[1]) },
    { HV_SYS_REG_DBGWCR1_EL1, offsetof(CPUARMState, cp15.dbgwcr[1]) },
    { HV_SYS_REG_MDSCR_EL1, offsetof(CPUARMState, cp15.mdscr_el1) },
    { HV_SYS_REG_DBGBVR2_EL1, offsetof(CPUARMState, cp15.dbgbvr[2]) },
    { HV_SYS_REG_DBGBCR2_EL1, offsetof(CPUARMState, cp15.dbgbcr[2]) },
    { HV_SYS_REG_DBGWVR2_EL1, offsetof(CPUARMState, cp15.dbgwvr[2]) },
    { HV_SYS_REG_DBGWCR2_EL1, offsetof(CPUARMState, cp15.dbgwcr[2]) },
    { HV_SYS_REG_DBGBVR3_EL1, offsetof(CPUARMState, cp15.dbgbvr[3]) },
    { HV_SYS_REG_DBGBCR3_EL1, offsetof(CPUARMState, cp15.dbgbcr[3]) },
    { HV_SYS_REG_DBGWVR3_EL1, offsetof(CPUARMState, cp15.dbgwvr[3]) },
    { HV_SYS_REG_DBGWCR3_EL1, offsetof(CPUARMState, cp15.dbgwcr[3]) },
    { HV_SYS_REG_DBGBVR4_EL1, offsetof(CPUARMState, cp15.dbgbvr[4]) },
    { HV_SYS_REG_DBGBCR4_EL1, offsetof(CPUARMState, cp15.dbgbcr[4]) },
    { HV_SYS_REG_DBGWVR4_EL1, offsetof(CPUARMState, cp15.dbgwvr[4]) },
    { HV_SYS_REG_DBGWCR4_EL1, offsetof(CPUARMState, cp15.dbgwcr[4]) },
    { HV_SYS_REG_DBGBVR5_EL1, offsetof(CPUARMState, cp15.dbgbvr[5]) },
    { HV_SYS_REG_DBGBCR5_EL1, offsetof(CPUARMState, cp15.dbgbcr[5]) },
    { HV_SYS_REG_DBGWVR5_EL1, offsetof(CPUARMState, cp15.dbgwvr[5]) },
    { HV_SYS_REG_DBGWCR5_EL1, offsetof(CPUARMState, cp15.dbgwcr[5]) },
    { HV_SYS_REG_DBGBVR6_EL1, offsetof(CPUARMState, cp15.dbgbvr[6]) },
    { HV_SYS_REG_DBGBCR6_EL1, offsetof(CPUARMState, cp15.dbgbcr[6]) },
    { HV_SYS_REG_DBGWVR6_EL1, offsetof(CPUARMState, cp15.dbgwvr[6]) },
    { HV_SYS_REG_DBGWCR6_EL1, offsetof(CPUARMState, cp15.dbgwcr[6]) },
    { HV_SYS_REG_DBGBVR7_EL1, offsetof(CPUARMState, cp15.dbgbvr[7]) },
    { HV_SYS_REG_DBGBCR7_EL1, offsetof(CPUARMState, cp15.dbgbcr[7]) },
    { HV_SYS_REG_DBGWVR7_EL1, offsetof(CPUARMState, cp15.dbgwvr[7]) },
    { HV_SYS_REG_DBGWCR7_EL1, offsetof(CPUARMState, cp15.dbgwcr[7]) },
    { HV_SYS_REG_DBGBVR8_EL1, offsetof(CPUARMState, cp15.dbgbvr[8]) },
    { HV_SYS_REG_DBGBCR8_EL1, offsetof(CPUARMState, cp15.dbgbcr[8]) },
    { HV_SYS_REG_DBGWVR8_EL1, offsetof(CPUARMState, cp15.dbgwvr[8]) },
    { HV_SYS_REG_DBGWCR8_EL1, offsetof(CPUARMState, cp15.dbgwcr[8]) },
    { HV_SYS_REG_DBGBVR9_EL1, offsetof(CPUARMState, cp15.dbgbvr[9]) },
    { HV_SYS_REG_DBGBCR9_EL1, offsetof(CPUARMState, cp15.dbgbcr[9]) },
    { HV_SYS_REG_DBGWVR9_EL1, offsetof(CPUARMState, cp15.dbgwvr[9]) },
    { HV_SYS_REG_DBGWCR9_EL1, offsetof(CPUARMState, cp15.dbgwcr[9]) },
    { HV_SYS_REG_DBGBVR10_EL1, offsetof(CPUARMState, cp15.dbgbvr[10]) },
    { HV_SYS_REG_DBGBCR10_EL1, offsetof(CPUARMState, cp15.dbgbcr[10]) },
    { HV_SYS_REG_DBGWVR10_EL1, offsetof(CPUARMState, cp15.dbgwvr[10]) },
    { HV_SYS_REG_DBGWCR10_EL1, offsetof(CPUARMState, cp15.dbgwcr[10]) },
    { HV_SYS_REG_DBGBVR11_EL1, offsetof(CPUARMState, cp15.dbgbvr[11]) },
    { HV_SYS_REG_DBGBCR11_EL1, offsetof(CPUARMState, cp15.dbgbcr[11]) },
    { HV_SYS_REG_DBGWVR11_EL1, offsetof(CPUARMState, cp15.dbgwvr[11]) },
    { HV_SYS_REG_DBGWCR11_EL1, offsetof(CPUARMState, cp15.dbgwcr[11]) },
    { HV_SYS_REG_DBGBVR12_EL1, offsetof(CPUARMState, cp15.dbgbvr[12]) },
    { HV_SYS_REG_DBGBCR12_EL1, offsetof(CPUARMState, cp15.dbgbcr[12]) },
    { HV_SYS_REG_DBGWVR12_EL1, offsetof(CPUARMState, cp15.dbgwvr[12]) },
    { HV_SYS_REG_DBGWCR12_EL1, offsetof(CPUARMState, cp15.dbgwcr[12]) },
    { HV_SYS_REG_DBGBVR13_EL1, offsetof(CPUARMState, cp15.dbgbvr[13]) },
    { HV_SYS_REG_DBGBCR13_EL1, offsetof(CPUARMState, cp15.dbgbcr[13]) },
    { HV_SYS_REG_DBGWVR13_EL1, offsetof(CPUARMState, cp15.dbgwvr[13]) },
    { HV_SYS_REG_DBGWCR13_EL1, offsetof(CPUARMState, cp15.dbgwcr[13]) },
    { HV_SYS_REG_DBGBVR14_EL1, offsetof(CPUARMState, cp15.dbgbvr[14]) },
    { HV_SYS_REG_DBGBCR14_EL1, offsetof(CPUARMState, cp15.dbgbcr[14]) },
    { HV_SYS_REG_DBGWVR14_EL1, offsetof(CPUARMState, cp15.dbgwvr[14]) },
    { HV_SYS_REG_DBGWCR14_EL1, offsetof(CPUARMState, cp15.dbgwcr[14]) },
    { HV_SYS_REG_DBGBVR15_EL1, offsetof(CPUARMState, cp15.dbgbvr[15]) },
    { HV_SYS_REG_DBGBCR15_EL1, offsetof(CPUARMState, cp15.dbgbcr[15]) },
    { HV_SYS_REG_DBGWVR15_EL1, offsetof(CPUARMState, cp15.dbgwvr[15]) },
    { HV_SYS_REG_DBGWCR15_EL1, offsetof(CPUARMState, cp15.dbgwcr[15]) },
    { HV_SYS_REG_MIDR_EL1, offsetof(CPUARMState, cp15.c0_cpuid) },
    { HV_SYS_REG_SCTLR_EL1, offsetof(CPUARMState, cp15.sctlr_ns) },
    { HV_SYS_REG_CPACR_EL1, offsetof(CPUARMState, cp15.cpacr_el1) },
    { HV_SYS_REG_TTBR0_EL1, offsetof(CPUARMState, cp15.ttbr0_ns) },
    { HV_SYS_REG_TTBR1_EL1, offsetof(CPUARMState, cp15.ttbr1_ns) },
    { HV_SYS_REG_TCR_EL1, offsetof(CPUARMState, cp15.tcr_el[1]) },
    { HV_SYS_REG_APIAKEYLO_EL1, offsetof(CPUARMState, keys.apia.lo) },
    { HV_SYS_REG_APIAKEYHI_EL1, offsetof(CPUARMState, keys.apia.hi) },
    { HV_SYS_REG_APIBKEYLO_EL1, offsetof(CPUARMState, keys.apib.lo) },
    { HV_SYS_REG_APIBKEYHI_EL1, offsetof(CPUARMState, keys.apib.hi) },
    { HV_SYS_REG_APDAKEYLO_EL1, offsetof(CPUARMState, keys.apda.lo) },
    { HV_SYS_REG_APDAKEYHI_EL1, offsetof(CPUARMState, keys.apda.hi) },
    { HV_SYS_REG_APDBKEYLO_EL1, offsetof(CPUARMState, keys.apdb.lo) },
    { HV_SYS_REG_APDBKEYHI_EL1, offsetof(CPUARMState, keys.apdb.hi) },
    { HV_SYS_REG_APGAKEYLO_EL1, offsetof(CPUARMState, keys.apga.lo) },
    { HV_SYS_REG_APGAKEYHI_EL1, offsetof(CPUARMState, keys.apga.hi) },
    { HV_SYS_REG_SPSR_EL1, offsetof(CPUARMState, banked_spsr[BANK_SVC]) },
    { HV_SYS_REG_ELR_EL1, offsetof(CPUARMState, elr_el[1]) },
    { HV_SYS_REG_SP_EL0, offsetof(CPUARMState, sp_el[0]) },
    { HV_SYS_REG_ESR_EL1, offsetof(CPUARMState, cp15.esr_el[1]) },
    { HV_SYS_REG_FAR_EL1, offsetof(CPUARMState, cp15.far_el[1]) },
    { HV_SYS_REG_PAR_EL1, offsetof(CPUARMState, cp15.par_el[1]) },
    { HV_SYS_REG_MAIR_EL1, offsetof(CPUARMState, cp15.mair_el[1]) },
    { HV_SYS_REG_VBAR_EL1, offsetof(CPUARMState, cp15.vbar_ns) },
    { HV_SYS_REG_CONTEXTIDR_EL1, offsetof(CPUARMState, cp15.contextidr_el[1]) },
    { HV_SYS_REG_TPIDR_EL1, offsetof(CPUARMState, cp15.tpidr_el[1]) },
    { HV_SYS_REG_CNTKCTL_EL1, offsetof(CPUARMState, cp15.c14_cntkctl) },
    { HV_SYS_REG_CSSELR_EL1, offsetof(CPUARMState, cp15.csselr_ns) },
    { HV_SYS_REG_TPIDR_EL0, offsetof(CPUARMState, cp15.tpidr_el[0]) },
    { HV_SYS_REG_TPIDRRO_EL0, offsetof(CPUARMState, cp15.tpidrro_el[0]) },
    { HV_SYS_REG_CNTV_CTL_EL0, offsetof(CPUARMState, cp15.c14_timer[GTIMER_VIRT].ctl) },
    { HV_SYS_REG_CNTV_CVAL_EL0, offsetof(CPUARMState, cp15.c14_timer[GTIMER_VIRT].cval) },
    { HV_SYS_REG_SP_EL1, offsetof(CPUARMState, sp_el[1]) },
};

int hvf_get_registers(CPUState *cpu)
{
    ARMCPU *arm_cpu = ARM_CPU(cpu);
    CPUARMState *env = &arm_cpu->env;
    hv_return_t ret;
    uint64_t val;
    int i;

    for (i = 0; i < ARRAY_SIZE(hvf_reg_match); i++) {
        ret = hv_vcpu_get_reg(cpu->hvf->fd, hvf_reg_match[i].reg, &val);
        *(uint64_t *)((void *)env + hvf_reg_match[i].offset) = val;
        assert_hvf_ok(ret);
    }

    val = 0;
    ret = hv_vcpu_get_reg(cpu->hvf->fd, HV_REG_FPCR, &val);
    assert_hvf_ok(ret);
    vfp_set_fpcr(env, val);

    val = 0;
    ret = hv_vcpu_get_reg(cpu->hvf->fd, HV_REG_FPSR, &val);
    assert_hvf_ok(ret);
    vfp_set_fpsr(env, val);

    ret = hv_vcpu_get_reg(cpu->hvf->fd, HV_REG_CPSR, &val);
    assert_hvf_ok(ret);
    pstate_write(env, val);

    for (i = 0; i < ARRAY_SIZE(hvf_sreg_match); i++) {
        ret = hv_vcpu_get_sys_reg(cpu->hvf->fd, hvf_sreg_match[i].reg, &val);
        *(uint64_t *)((void *)env + hvf_sreg_match[i].offset) = val;
        assert_hvf_ok(ret);
    }

    return 0;
}

int hvf_put_registers(CPUState *cpu)
{
    ARMCPU *arm_cpu = ARM_CPU(cpu);
    CPUARMState *env = &arm_cpu->env;
    hv_return_t ret;
    uint64_t val;
    int i;

    for (i = 0; i < ARRAY_SIZE(hvf_reg_match); i++) {
        val = *(uint64_t *)((void *)env + hvf_reg_match[i].offset);
        ret = hv_vcpu_set_reg(cpu->hvf->fd, hvf_reg_match[i].reg, val);

        assert_hvf_ok(ret);
    }

    ret = hv_vcpu_set_reg(cpu->hvf->fd, HV_REG_FPCR, vfp_get_fpcr(env));
    assert_hvf_ok(ret);

    ret = hv_vcpu_set_reg(cpu->hvf->fd, HV_REG_FPSR, vfp_get_fpsr(env));
    assert_hvf_ok(ret);

    ret = hv_vcpu_set_reg(cpu->hvf->fd, HV_REG_CPSR, pstate_read(env));
    assert_hvf_ok(ret);

    for (i = 0; i < ARRAY_SIZE(hvf_sreg_match); i++) {
        val = *(uint64_t *)((void *)env + hvf_sreg_match[i].offset);
        ret = hv_vcpu_set_sys_reg(cpu->hvf->fd, hvf_sreg_match[i].reg, val);

        assert_hvf_ok(ret);
    }

    ret = hv_vcpu_set_sys_reg(cpu->hvf->fd, HV_SYS_REG_MPIDR_EL1,
                              arm_cpu->mp_affinity);
    assert_hvf_ok(ret);

    return 0;
}

static void flush_cpu_state(CPUState *cpu)
{
    if (cpu->vcpu_dirty) {
        hvf_put_registers(cpu);
        cpu->vcpu_dirty = false;
    }
}

static void hvf_set_reg(CPUState *cpu, int rt, uint64_t val)
{
    hv_return_t r;

    flush_cpu_state(cpu);

    if (rt < 31) {
        r = hv_vcpu_set_reg(cpu->hvf->fd, HV_REG_X0 + rt, val);
        assert_hvf_ok(r);
    }
}

static uint64_t hvf_get_reg(CPUState *cpu, int rt)
{
    uint64_t val = 0;
    hv_return_t r;

    flush_cpu_state(cpu);

    if (rt < 31) {
        r = hv_vcpu_get_reg(cpu->hvf->fd, HV_REG_X0 + rt, &val);
        assert_hvf_ok(r);
    }

    return val;
}

void hvf_arch_vcpu_destroy(CPUState *cpu)
{
}

int hvf_arch_init_vcpu(CPUState *cpu)
{
    ARMCPU *arm_cpu = ARM_CPU(cpu);
    CPUARMState *env = &arm_cpu->env;
    hv_return_t ret;

    env->aarch64 = 1;
    asm volatile("mrs %0, cntfrq_el0" : "=r"(arm_cpu->gt_cntfrq_hz));

    ret = hv_vcpu_set_sys_reg(cpu->hvf->fd, HV_SYS_REG_SCTLR_EL1,
                              arm_cpu->reset_sctlr);
    assert_hvf_ok(ret);

    /* We're limited to local hardware caps, override internal versions */
    ret = hv_vcpu_get_sys_reg(cpu->hvf->fd, HV_SYS_REG_ID_AA64MMFR0_EL1,
                              &arm_cpu->isar.id_aa64mmfr0);

    return 0;
}

void hvf_kick_vcpu_thread(CPUState *cpu)
{
    if (cpu->hvf->sleeping) {
        /*
         * When sleeping, make sure we always send signals. Also, clear the
         * timespec, so that an IPI that arrives between setting hvf->sleeping
         * and the nanosleep syscall still aborts the sleep.
         */
        cpu->thread_kicked = false;
        cpu->hvf->ts = (struct timespec){ };
        cpus_kick_thread(cpu);
    } else {
        hv_vcpus_exit(&cpu->hvf->fd, 1);
    }
}

static int hvf_inject_interrupts(CPUState *cpu)
{
    if (cpu->interrupt_request & CPU_INTERRUPT_FIQ) {
        DPRINTF("injecting FIQ");
        hv_vcpu_set_pending_interrupt(cpu->hvf->fd, HV_INTERRUPT_TYPE_FIQ, true);
    }

    if (cpu->interrupt_request & CPU_INTERRUPT_HARD) {
        DPRINTF("injecting IRQ");
        hv_vcpu_set_pending_interrupt(cpu->hvf->fd, HV_INTERRUPT_TYPE_IRQ, true);
    }

    return 0;
}

int hvf_vcpu_exec(CPUState *cpu)
{
    ARMCPU *arm_cpu = ARM_CPU(cpu);
    CPUARMState *env = &arm_cpu->env;
    hv_vcpu_exit_t *hvf_exit = cpu->hvf->exit;
    hv_return_t r;
    int ret = 0;

    qemu_mutex_unlock_iothread();

    do {
        bool advance_pc = false;

        qemu_mutex_lock_iothread();
        current_cpu = cpu;
        qemu_wait_io_event_common(cpu);
        qemu_mutex_unlock_iothread();

        flush_cpu_state(cpu);

        if (hvf_inject_interrupts(cpu)) {
            return EXCP_INTERRUPT;
        }

        if (cpu->halted) {
            qemu_mutex_lock_iothread();
            return EXCP_HLT;
        }

        assert_hvf_ok(hv_vcpu_run(cpu->hvf->fd));

        /* handle VMEXIT */
        uint64_t exit_reason = hvf_exit->reason;
        uint64_t syndrome = hvf_exit->exception.syndrome;
        uint32_t ec = syn_get_ec(syndrome);

        switch (exit_reason) {
        case HV_EXIT_REASON_EXCEPTION:
            /* This is the main one, handle below. */
            break;
        case HV_EXIT_REASON_VTIMER_ACTIVATED:
            qemu_mutex_lock_iothread();
            current_cpu = cpu;
            qemu_set_irq(arm_cpu->gt_timer_outputs[GTIMER_VIRT], 1);
            qemu_mutex_unlock_iothread();
            continue;
        case HV_EXIT_REASON_CANCELED:
            /* we got kicked, no exit to process */
            continue;
        default:
            assert(0);
        }

        ret = 0;
        switch (ec) {
        case EC_DATAABORT: {
            bool isv = syndrome & ARM_EL_ISV;
            bool iswrite = (syndrome >> 6) & 1;
            bool s1ptw = (syndrome >> 7) & 1;
            uint32_t sas = (syndrome >> 22) & 3;
            uint32_t len = 1 << sas;
            uint32_t srt = (syndrome >> 16) & 0x1f;
            uint64_t val = 0;

            qemu_mutex_lock_iothread();
            current_cpu = cpu;

            DPRINTF("data abort: [pc=0x%llx va=0x%016llx pa=0x%016llx isv=%x "
                    "iswrite=%x s1ptw=%x len=%d srt=%d]\n",
                    env->pc, hvf_exit->exception.virtual_address,
                    hvf_exit->exception.physical_address, isv, iswrite,
                    s1ptw, len, srt);

            assert(isv);

            if (iswrite) {
                val = hvf_get_reg(cpu, srt);
                address_space_write(&address_space_memory,
                                    hvf_exit->exception.physical_address,
                                    MEMTXATTRS_UNSPECIFIED, &val, len);

                /*
                 * We do not have a callback to see if the timer is out of
                 * pending state. That means every MMIO write could
                 * potentially be an EOI ends the vtimer. Until we get an
                 * actual callback, let's just see if the timer is still
                 * pending on every possible toggle point.
                 */
                qemu_set_irq(arm_cpu->gt_timer_outputs[GTIMER_VIRT], 0);
                hv_vcpu_set_vtimer_mask(cpu->hvf->fd, false);
            } else {
                address_space_read(&address_space_memory,
                                   hvf_exit->exception.physical_address,
                                   MEMTXATTRS_UNSPECIFIED, &val, len);
                hvf_set_reg(cpu, srt, val);
            }

            qemu_mutex_unlock_iothread();

            advance_pc = true;
            break;
        }
        case EC_SYSTEMREGISTERTRAP: {
            bool isread = (syndrome >> 21) & 1;
            uint32_t rt = (syndrome >> 5) & 0x1f;
            uint32_t reg = syndrome & SYSREG_MASK;
            uint64_t val = 0;

            if (isread) {
                switch (reg) {
                case SYSREG_CNTPCT_EL0:
                    val = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) /
                          gt_cntfrq_period_ns(arm_cpu);
                    break;
                case SYSREG_PMCCNTR_EL0:
                    val = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
                    break;
                default:
                    DPRINTF("unhandled sysreg read %08x (op0=%d op1=%d op2=%d "
                            "crn=%d crm=%d)", reg, (reg >> 20) & 0x3,
                            (reg >> 14) & 0x7, (reg >> 17) & 0x7,
                            (reg >> 10) & 0xf, (reg >> 1) & 0xf);
                    break;
                }

                hvf_set_reg(cpu, rt, val);
            } else {
                val = hvf_get_reg(cpu, rt);

                switch (reg) {
                case SYSREG_CNTPCT_EL0:
                    break;
                default:
                    DPRINTF("unhandled sysreg write %08x", reg);
                    break;
                }
            }

            advance_pc = true;
            break;
        }
        case EC_WFX_TRAP:
            if (!(syndrome & WFX_IS_WFE) && !(cpu->interrupt_request &
                (CPU_INTERRUPT_HARD | CPU_INTERRUPT_FIQ))) {
                uint64_t cval, ctl, val, diff, now;

                /* Set up a local timer for vtimer if necessary ... */
                r = hv_vcpu_get_sys_reg(cpu->hvf->fd, HV_SYS_REG_CNTV_CTL_EL0, &ctl);
                assert_hvf_ok(r);
                r = hv_vcpu_get_sys_reg(cpu->hvf->fd, HV_SYS_REG_CNTV_CVAL_EL0, &cval);
                assert_hvf_ok(r);

                asm volatile("mrs %0, cntvct_el0" : "=r"(val));
                diff = cval - val;

                now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) /
                      gt_cntfrq_period_ns(arm_cpu);

                /* Timer disabled or masked, just wait for long */
                if (!(ctl & 1) || (ctl & 2)) {
                    diff = (120 * NANOSECONDS_PER_SECOND) /
                           gt_cntfrq_period_ns(arm_cpu);
                }

                if (diff < INT64_MAX) {
                    uint64_t ns = diff * gt_cntfrq_period_ns(arm_cpu);
                    struct timespec *ts = &cpu->hvf->ts;

                    *ts = (struct timespec){
                        .tv_sec = ns / NANOSECONDS_PER_SECOND,
                        .tv_nsec = ns % NANOSECONDS_PER_SECOND,
                    };

                    /*
                     * Waking up easily takes 1ms, don't go to sleep for smaller
                     * time periods than 2ms.
                     */
                    if (!ts->tv_sec && (ts->tv_nsec < (SCALE_MS * 2))) {
                        advance_pc = true;
                        break;
                    }

                    /* Set cpu->hvf->sleeping so that we get a SIG_IPI signal. */
                    cpu->hvf->sleeping = true;
                    smp_mb();

                    /* Bail out if we received an IRQ meanwhile */
                    if (cpu->thread_kicked || (cpu->interrupt_request &
                        (CPU_INTERRUPT_HARD | CPU_INTERRUPT_FIQ))) {
                        cpu->hvf->sleeping = false;
                        break;
                    }

                    /* nanosleep returns on signal, so we wake up on kick. */
                    nanosleep(ts, NULL);

                    /* Out of sleep - either naturally or because of a kick */
                    cpu->hvf->sleeping = false;
                }

                advance_pc = true;
            }
            break;
        case EC_AA64_HVC:
            cpu_synchronize_state(cpu);
            qemu_mutex_lock_iothread();
            current_cpu = cpu;
            if (arm_is_psci_call(arm_cpu, EXCP_HVC)) {
                arm_handle_psci_call(arm_cpu);
            } else {
                DPRINTF("unknown HVC! %016llx", env->xregs[0]);
                env->xregs[0] = -1;
            }
            qemu_mutex_unlock_iothread();
            break;
        case EC_AA64_SMC:
            cpu_synchronize_state(cpu);
            qemu_mutex_lock_iothread();
            current_cpu = cpu;
            if (arm_is_psci_call(arm_cpu, EXCP_SMC)) {
                arm_handle_psci_call(arm_cpu);
            } else {
                DPRINTF("unknown SMC! %016llx", env->xregs[0]);
                env->xregs[0] = -1;
                env->pc += 4;
            }
            qemu_mutex_unlock_iothread();
            break;
        default:
            cpu_synchronize_state(cpu);
            DPRINTF("exit: %llx [ec=0x%x pc=0x%llx]", syndrome, ec, env->pc);
            error_report("%llx: unhandled exit %llx", env->pc, exit_reason);
        }

        if (advance_pc) {
            uint64_t pc;

            flush_cpu_state(cpu);

            r = hv_vcpu_get_reg(cpu->hvf->fd, HV_REG_PC, &pc);
            assert_hvf_ok(r);
            pc += 4;
            r = hv_vcpu_set_reg(cpu->hvf->fd, HV_REG_PC, pc);
            assert_hvf_ok(r);
        }
    } while (ret == 0);

    qemu_mutex_lock_iothread();
    current_cpu = cpu;

    return ret;
}
