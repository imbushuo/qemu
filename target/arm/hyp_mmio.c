/*
 * ARM MMIO emulation shared by hardware accelerators
 *
 * Copyright 2020 Alexander Graf <agraf@csgraf.de>
 * Copyright 2020 Google LLC
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/bswap.h"
#include "cpu.h"
#include "internals.h"
#include "system/hw_accel.h"

static void load_simd_reg(CPUARMState *env, unsigned int reg,
                          const uint8_t *buf, unsigned int size)
{
    /* Scalar and AdvSIMD loads also clear the upper SVE lanes. */
    memset(&env->vfp.zregs[reg], 0, sizeof(env->vfp.zregs[reg]));
    env->vfp.zregs[reg].d[0] = ldq_le_p(buf);
    env->vfp.zregs[reg].d[1] = size == 16 ? ldq_le_p(buf + 8) : 0;
}

/*
 * Emulate a load/store that took a data abort with ISV=0, i.e. with no
 * instruction syndrome. macOS 13+ guest kernels perform such accesses
 * against device memory during early boot.
 *
 * Decode the faulting instruction and access the already-translated fault
 * IPA. Supported classes are GPR and SIMD&FP load/store pairs, single GPR
 * imm9/register-offset forms, and single SIMD&FP loads/stores. Unsupported
 * instructions (including exclusives, atomics and SP-based writeback) and
 * failed memory transactions return false so the accelerator can handle
 * the abort, without committing register or PC updates.
 */
bool arm_emulate_isv0_mmio(CPUState *cpu, hwaddr ipa, uint32_t *insn_out)
{
    CPUARMState *env = cpu_env(cpu);
    AddressSpace *as = cpu_get_address_space(cpu, ARMASIdx_NS);
    uint32_t insn = 0;

    cpu_synchronize_state(cpu);

    *insn_out = 0;
    if (!is_a64(env) || arm_cpu_data_is_big_endian(env)) {
        return false;
    }

    if (cpu_memory_rw_debug(cpu, env->pc, &insn, sizeof(insn), false)) {
        return false;
    }
    insn = ldl_le_p(&insn);
    *insn_out = insn;

    if ((insn & 0x38000000) == 0x28000000) {
        /* Load/store pair (incl. no-allocate): C4.1.66 op0=x101. */
        uint32_t opc = extract32(insn, 30, 2);
        bool is_vector = extract32(insn, 26, 1);
        /* 0=STNP/LDNP, 1=post-index, 2=offset, 3=pre-index */
        uint32_t mode = extract32(insn, 23, 2);
        bool is_load = extract32(insn, 22, 1);
        int64_t imm7 = sextract32(insn, 15, 7);
        uint32_t rt2 = extract32(insn, 10, 5);
        uint32_t rn = extract32(insn, 5, 5);
        uint32_t rt = extract32(insn, 0, 5);
        bool wback = (mode == 1) || (mode == 3);
        bool sext = false;
        int esize;
        uint8_t bufs[2][16] = { 0 };

        if (is_vector) {
            if (opc == 3) {
                return false;               /* unallocated */
            }
            esize = 4 << opc;               /* S/D/Q */
        } else if (opc == 0) {
            esize = 4;
        } else if (opc == 1 && is_load) {
            esize = 4;
            sext = true;                    /* LDPSW */
        } else if (opc == 2) {
            esize = 8;
        } else {
            return false;                   /* unallocated / STGP */
        }
        if (wback && rn == 31) {
            return false;                   /* SP-based MMIO writeback: refuse */
        }

        /* Check both accesses before touching a device or changing registers. */
        for (int i = 0; i < 2; i++) {
            if (!address_space_access_valid(as, ipa + (hwaddr)i * esize,
                                            esize, !is_load,
                                            MEMTXATTRS_UNSPECIFIED)) {
                return false;
            }
        }

        for (int i = 0; i < 2; i++) {
            uint32_t reg = i ? rt2 : rt;
            hwaddr addr = ipa + (hwaddr)i * esize;
            uint8_t *buf = bufs[i];

            if (is_load) {
                if (address_space_read(as, addr, MEMTXATTRS_UNSPECIFIED,
                                       buf, esize) != MEMTX_OK) {
                    return false;
                }
            } else {
                if (is_vector) {
                    stq_le_p(buf, env->vfp.zregs[reg].d[0]);
                    if (esize == 16) {
                        stq_le_p(buf + 8, env->vfp.zregs[reg].d[1]);
                    }
                } else if (reg != 31) {
                    if (esize == 4) {
                        stl_le_p(buf, (uint32_t)env->xregs[reg]);
                    } else {
                        stq_le_p(buf, env->xregs[reg]);
                    }
                }
                if (address_space_write(as, addr, MEMTXATTRS_UNSPECIFIED,
                                        buf, esize) != MEMTX_OK) {
                    return false;
                }
            }
        }
        if (is_load) {
            for (int i = 0; i < 2; i++) {
                uint32_t reg = i ? rt2 : rt;
                const uint8_t *buf = bufs[i];

                if (is_vector) {
                    load_simd_reg(env, reg, buf, esize);
                } else if (reg != 31) {
                    uint64_t v = esize == 4 ? ldl_le_p(buf) : ldq_le_p(buf);
                    env->xregs[reg] = sext ? sextract64(v, 0, 32) : v;
                }
            }
        }
        if (wback) {
            env->xregs[rn] += imm7 * esize;
        }
        env->pc += 4;
        return true;
    }

    if (extract32(insn, 24, 6) == 0x38) {
        /*
         * Load/store single GPR, imm9/register-offset forms: bits[29:24]=
         * 111000. The pre/post-indexed (writeback) forms report ISV=0
         * because the syndrome cannot describe the base update -- macOS 13+
         * uses e.g. "str w9, [x8, #128]!" on MMIO.
         */
        uint32_t size = extract32(insn, 30, 2);
        uint32_t opc = extract32(insn, 22, 2);
        uint32_t rn = extract32(insn, 5, 5);
        uint32_t rt = extract32(insn, 0, 5);
        bool wback = false;
        int esize = 1 << size;
        uint8_t buf[8] = { 0 };

        if (extract32(insn, 21, 1)) {
            if (extract32(insn, 10, 2) != 2) {
                return false;           /* atomics etc., not register-offset */
            }
        } else {
            switch (extract32(insn, 10, 2)) {
            case 0:                     /* LDUR/STUR: no writeback */
            case 2:                     /* LDTR/STTR: treat as plain access */
                break;
            case 1:                     /* post-index */
            case 3:                     /* pre-index */
                wback = true;
                break;
            }
        }
        if (size == 3 && opc == 2) {
            return false;               /* PRFUM: prefetch never aborts */
        }
        if (wback && rn == 31) {
            return false;               /* SP-based MMIO writeback: refuse */
        }

        if (opc == 0) {                 /* store */
            if (rt != 31) {
                stq_le_p(buf, env->xregs[rt]);
            }
            if (address_space_write(as, ipa, MEMTXATTRS_UNSPECIFIED,
                                    buf, esize) != MEMTX_OK) {
                return false;
            }
        } else {                        /* load: 01 zext, 10 sext to X, 11 to W */
            uint64_t v;

            if (address_space_read(as, ipa, MEMTXATTRS_UNSPECIFIED,
                                   buf, esize) != MEMTX_OK) {
                return false;
            }
            v = ldq_le_p(buf) & MAKE_64BIT_MASK(0, esize * 8);
            if (opc == 2) {
                v = sextract64(v, 0, esize * 8);
            } else if (opc == 3) {
                v = (uint32_t)sextract64(v, 0, esize * 8);
            }
            if (rt != 31) {
                env->xregs[rt] = v;
            }
        }
        if (wback) {
            env->xregs[rn] += sextract32(insn, 12, 9);
        }
        env->pc += 4;
        return true;
    }

    if (extract32(insn, 24, 6) == 0x3d || extract32(insn, 24, 6) == 0x3c) {
        /* Load/store single SIMD&FP register: bits[29:24]=1111 0V. */
        uint32_t size = extract32(insn, 30, 2);
        uint32_t opc = extract32(insn, 22, 2);
        bool unsigned_imm = extract32(insn, 24, 2) == 1;
        bool is_load = opc & 1;
        uint32_t rn = extract32(insn, 5, 5);
        uint32_t rt = extract32(insn, 0, 5);
        uint32_t scale = size;
        bool wback = false;
        int esize;
        uint8_t buf[16] = { 0 };

        if (opc & 2) {
            if (size != 0) {
                return false;               /* only Q extends the size range */
            }
            scale = 4;
        }
        esize = 1 << scale;

        if (!unsigned_imm) {
            if (extract32(insn, 21, 1)) {
                if (extract32(insn, 10, 2) != 2) {
                    return false;           /* not a register-offset form */
                }
            } else {
                switch (extract32(insn, 10, 2)) {
                case 0:                     /* LDUR/STUR: no writeback */
                    break;
                case 1:                     /* post-index */
                case 3:                     /* pre-index */
                    wback = true;
                    break;
                default:
                    return false;
                }
            }
        }
        if (wback && rn == 31) {
            return false;                   /* SP-based MMIO writeback: refuse */
        }

        if (is_load) {
            if (address_space_read(as, ipa, MEMTXATTRS_UNSPECIFIED,
                                   buf, esize) != MEMTX_OK) {
                return false;
            }
            load_simd_reg(env, rt, buf, esize);
        } else {
            stq_le_p(buf, env->vfp.zregs[rt].d[0]);
            if (esize == 16) {
                stq_le_p(buf + 8, env->vfp.zregs[rt].d[1]);
            }
            if (address_space_write(as, ipa, MEMTXATTRS_UNSPECIFIED,
                                    buf, esize) != MEMTX_OK) {
                return false;
            }
        }
        if (wback) {
            env->xregs[rn] += sextract32(insn, 12, 9);
        }
        env->pc += 4;
        return true;
    }

    return false;
}
