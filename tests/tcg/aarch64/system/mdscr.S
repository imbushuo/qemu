/*
 * Exercise MDSCR_EL1 accesses while the gdbstub owns the debug registers.
 * Standalone startup avoids semihosting, which is not supported by HVF.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

        .text
        .global __start
__start:
        adr     x0, vectors
        msr     vbar_el1, x0
        isb

        mrs     x0, mdscr_el1
        orr     x2, x0, #0x1000
        msr     mdscr_el1, x2
        mrs     x3, mdscr_el1
        bic     x2, x2, #0x1000
        msr     mdscr_el1, x2
        mrs     x4, mdscr_el1
        msr     mdscr_el1, x0

        .global mdscr_done
mdscr_done:
        wfi
        b       mdscr_done

        .global mdscr_exception
mdscr_exception:
        mrs     x1, esr_el1
        wfi
        b       mdscr_exception

        .balign 2048
vectors:
        .rept 16
        b       mdscr_exception
        .balign 128
        .endr
