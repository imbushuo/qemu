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

int hvf_get_registers(CPUState *cpu)
{
    ARMCPU *arm_cpu = ARM_CPU(cpu);
    CPUARMState *env = &arm_cpu->env;
    hv_return_t ret;
    uint64_t val;
    int i;

    for (i = 0; i < ARRAY_SIZE(hvf_reg_match); i++) {
        ret = hv_vcpu_get_reg(cpu->hvf_fd, hvf_reg_match[i].reg, &val);
        *(uint64_t *)((void *)env + hvf_reg_match[i].offset) = val;
        assert_hvf_ok(ret);
    }

    val = 0;
    ret = hv_vcpu_get_reg(cpu->hvf_fd, HV_REG_FPCR, &val);
    assert_hvf_ok(ret);
    vfp_set_fpcr(env, val);

    val = 0;
    ret = hv_vcpu_get_reg(cpu->hvf_fd, HV_REG_FPSR, &val);
    assert_hvf_ok(ret);
    vfp_set_fpsr(env, val);

    ret = hv_vcpu_get_reg(cpu->hvf_fd, HV_REG_CPSR, &val);
    assert_hvf_ok(ret);
    pstate_write(env, val);

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
        ret = hv_vcpu_set_reg(cpu->hvf_fd, hvf_reg_match[i].reg, val);

        assert_hvf_ok(ret);
    }

    ret = hv_vcpu_set_reg(cpu->hvf_fd, HV_REG_FPCR, vfp_get_fpcr(env));
    assert_hvf_ok(ret);

    ret = hv_vcpu_set_reg(cpu->hvf_fd, HV_REG_FPSR, vfp_get_fpsr(env));
    assert_hvf_ok(ret);

    ret = hv_vcpu_set_reg(cpu->hvf_fd, HV_REG_CPSR, pstate_read(env));
    assert_hvf_ok(ret);

    ret = hv_vcpu_set_sys_reg(cpu->hvf_fd, HV_SYS_REG_MPIDR_EL1,
                              arm_cpu->mp_affinity);
    assert_hvf_ok(ret);

    return 0;
}

void hvf_arch_vcpu_destroy(CPUState *cpu)
{
}

int hvf_arch_init_vcpu(CPUState *cpu)
{
    ARMCPU *arm_cpu = ARM_CPU(cpu);
    CPUARMState *env = &arm_cpu->env;

    env->aarch64 = 1;

    return 0;
}

static int hvf_process_events(CPUState *cpu)
{
    DPRINTF("");
    return 0;
}

static int hvf_inject_interrupts(CPUState *cpu)
{
    if (cpu->interrupt_request & CPU_INTERRUPT_FIQ) {
        DPRINTF("injecting FIQ");
        hv_vcpu_set_pending_interrupt(cpu->hvf_fd, HV_INTERRUPT_TYPE_FIQ, true);
    }

    if (cpu->interrupt_request & CPU_INTERRUPT_HARD) {
        DPRINTF("injecting IRQ");
        hv_vcpu_set_pending_interrupt(cpu->hvf_fd, HV_INTERRUPT_TYPE_IRQ, true);
    }

    return 0;
}

int hvf_vcpu_exec(CPUState *cpu)
{
    ARMCPU *arm_cpu = ARM_CPU(cpu);
    CPUARMState *env = &arm_cpu->env;
    hv_vcpu_exit_t *hvf_exit = cpu->hvf_exit;
    int ret = 0;

    if (hvf_process_events(cpu)) {
        return EXCP_HLT;
    }

    do {
        process_queued_cpu_work(cpu);

        if (cpu->vcpu_dirty) {
            hvf_put_registers(cpu);
            cpu->vcpu_dirty = false;
        }

        if (hvf_inject_interrupts(cpu)) {
            return EXCP_INTERRUPT;
        }

        qemu_mutex_unlock_iothread();
        if (cpu->cpu_index && cpu->halted) {
            qemu_mutex_lock_iothread();
            return EXCP_HLT;
        }

        assert_hvf_ok(hv_vcpu_run(cpu->hvf_fd));

        /* handle VMEXIT */
        uint64_t exit_reason = hvf_exit->reason;
        uint64_t syndrome = hvf_exit->exception.syndrome;
        uint32_t ec = syn_get_ec(syndrome);

        cpu_synchronize_state(cpu);

        qemu_mutex_lock_iothread();

        current_cpu = cpu;

        switch (exit_reason) {
        case HV_EXIT_REASON_EXCEPTION:
            /* This is the main one, handle below. */
            break;
        case HV_EXIT_REASON_VTIMER_ACTIVATED:
            qemu_set_irq(arm_cpu->gt_timer_outputs[GTIMER_VIRT], 1);
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

            DPRINTF("data abort: [pc=0x%llx va=0x%016llx pa=0x%016llx isv=%x "
                    "iswrite=%x s1ptw=%x len=%d srt=%d]\n",
                    env->pc, hvf_exit->exception.virtual_address,
                    hvf_exit->exception.physical_address, isv, iswrite,
                    s1ptw, len, srt);

            assert(isv);

            if (iswrite) {
                val = env->xregs[srt];
                address_space_write(&address_space_memory,
                                    hvf_exit->exception.physical_address,
                                    MEMTXATTRS_UNSPECIFIED, &val, len);

                /*
                 * We do not have a callback to see if the timer is out of
                 * state. That means every MMIO write could potentially be
                 * an EOI ends the vtimer. Until we get an actual callback,
                 * let's just see if the timer is still pending on every
                 * possible toggle point.
                 */
                qemu_set_irq(arm_cpu->gt_timer_outputs[GTIMER_VIRT], 0);
                hv_vcpu_set_vtimer_mask(cpu->hvf_fd, false);
            } else {
                address_space_read(&address_space_memory,
                                   hvf_exit->exception.physical_address,
                                   MEMTXATTRS_UNSPECIFIED, &val, len);
                env->xregs[srt] = val;
            }

            env->pc += 4;
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

                env->xregs[rt] = val;
            } else {
                val = env->xregs[rt];
                switch (reg) {
                case SYSREG_CNTPCT_EL0:
                    break;
                default:
                    DPRINTF("unhandled sysreg write %08x", reg);
                    break;
                }
            }

            env->pc += 4;
            break;
        }
        case EC_WFX_TRAP:
            /* No halting yet */
            break;
        case EC_AA64_HVC:
            if (arm_is_psci_call(arm_cpu, EXCP_HVC)) {
                arm_handle_psci_call(arm_cpu);
            } else {
                DPRINTF("unknown HVC! %016llx", env->xregs[0]);
                env->xregs[0] = -1;
            }
            break;
        case EC_AA64_SMC:
            if (arm_is_psci_call(arm_cpu, EXCP_SMC)) {
                arm_handle_psci_call(arm_cpu);
            } else {
                DPRINTF("unknown SMC! %016llx", env->xregs[0]);
                env->xregs[0] = -1;
                env->pc += 4;
            }
            break;
        default:
            DPRINTF("exit: %llx [ec=0x%x pc=0x%llx]", syndrome, ec, env->pc);
            error_report("%llx: unhandled exit %llx", env->pc, exit_reason);
        }
    } while (ret == 0);

    return ret;
}
