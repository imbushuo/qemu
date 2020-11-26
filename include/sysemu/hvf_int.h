/*
 * QEMU Hypervisor.framework (HVF) support
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

/* header to be included in HVF-specific code */

#ifndef HVF_INT_H
#define HVF_INT_H

#include <Hypervisor/Hypervisor.h>

#define HVF_MAX_VCPU 0x10

extern struct hvf_state hvf_global;

struct hvf_vm {
    int id;
    struct hvf_vcpu_state *vcpus[HVF_MAX_VCPU];
};

struct hvf_state {
    uint32_t version;
    struct hvf_vm *vm;
    uint64_t mem_quota;
};

/* hvf_slot flags */
#define HVF_SLOT_LOG (1 << 0)

typedef struct hvf_slot {
    uint64_t start;
    uint64_t size;
    uint8_t *mem;
    int slot_id;
    uint32_t flags;
    MemoryRegion *region;
} hvf_slot;

typedef struct hvf_vcpu_caps {
    uint64_t vmx_cap_pinbased;
    uint64_t vmx_cap_procbased;
    uint64_t vmx_cap_procbased2;
    uint64_t vmx_cap_entry;
    uint64_t vmx_cap_exit;
    uint64_t vmx_cap_preemption_timer;
} hvf_vcpu_caps;

struct HVFState {
    AccelState parent;
    hvf_slot slots[32];
    int num_slots;

    hvf_vcpu_caps *hvf_caps;
};
extern HVFState *hvf_state;

void assert_hvf_ok(hv_return_t ret);
int hvf_get_registers(CPUState *cpu);
int hvf_put_registers(CPUState *cpu);
int hvf_arch_init_vcpu(CPUState *cpu);
void hvf_arch_vcpu_destroy(CPUState *cpu);
int hvf_vcpu_exec(CPUState *cpu);
hvf_slot *hvf_find_overlap_slot(uint64_t, uint64_t);

#endif
