# SPDX-License-Identifier: GPL-2.0-or-later
"""MDSCR_EL1 must remain accessible with hardware breakpoints armed.

Run with tests/guest-debug/run-test.py and the system/mdscr.S guest.
Use -accel hvf on an AArch64 macOS host to exercise trapped register accesses.
"""

import gdb

from test_gdbstub import main, report


def run_test():
    done = int(gdb.parse_and_eval("&mdscr_done"))
    gdb.Breakpoint("*mdscr_done", type=gdb.BP_HARDWARE_BREAKPOINT)
    gdb.Breakpoint("*mdscr_exception", type=gdb.BP_HARDWARE_BREAKPOINT)
    gdb.execute("continue")
    reached_done = int(gdb.parse_and_eval("$pc")) == done
    report(reached_done, "MDSCR_EL1 accesses do not raise an exception")
    if reached_done:
        report(int(gdb.parse_and_eval("$x3")) & 0x1000 != 0,
               "MDSCR_EL1 read observes TDCC set")
        report(int(gdb.parse_and_eval("$x4")) & 0x1000 == 0,
               "MDSCR_EL1 read observes TDCC cleared")


main(run_test, expected_arch="aarch64")
