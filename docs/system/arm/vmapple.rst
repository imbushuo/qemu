.. SPDX-License-Identifier: GPL-2.0-or-later

VMApple machine emulation
========================================================================================

VMApple is the device model that the macOS built-in hypervisor called "Virtualization.framework"
exposes to Apple Silicon macOS guests. The "vmapple" machine model in QEMU implements the same
device model, but does not use any code from Virtualization.Framework.

Prerequisites
-------------

To run the vmapple machine model, you need to

 * Run on Apple Silicon
 * Run on macOS 12.0 or above
 * Have an already installed copy of a Virtualization.Framework macOS 12 virtual
   machine. Note that newer versions than 12.x are currently NOT supported on
   the guest side. I will assume that you installed it using the
   `macosvm <https://github.com/s-u/macosvm>`__ CLI.

First, we need to extract the UUID from the virtual machine that you installed. You can do this
by running the shell script in contrib/vmapple/uuid.sh on the macosvm.json file.

.. code-block:: bash
  :caption: uuid.sh script to extract the UUID from a macosvm.json file

  $ contrib/vmapple/uuid.sh "path/to/macosvm.json"

Now we also need to trim the aux partition. It contains metadata that we can just discard:

.. code-block:: bash
  :caption: Command to trim the aux file

  $ dd if="aux.img" of="aux.img.trimmed" bs=$(( 0x4000 )) skip=1

How to run
----------

Then, we can launch QEMU with the Virtualization.Framework pre-boot environment and the readily
installed target disk images. I recommend to port forward the VM's ssh and vnc ports to the host
to get better interactive access into the target system:

.. code-block:: bash
  :caption: Example execution command line

  $ UUID="$(contrib/vmapple/uuid.sh 'macosvm.json')"
  $ AVPBOOTER="/System/Library/Frameworks/Virtualization.framework/Resources/AVPBooter.vmapple2.bin"
  $ AUX="aux.img.trimmed"
  $ DISK="disk.img"
  $ qemu-system-aarch64 \
       -serial mon:stdio \
       -m 4G \
       -accel hvf \
       -M vmapple,uuid="$UUID" \
       -bios "$AVPBOOTER" \
       -drive file="$AUX",if=pflash,format=raw \
       -drive file="$DISK",if=pflash,format=raw \
       -drive file="$AUX",if=none,id=aux,format=raw \
       -drive file="$DISK",if=none,id=root,format=raw \
       -device vmapple-virtio-blk-pci,variant=aux,drive=aux \
       -device vmapple-virtio-blk-pci,variant=root,drive=root \
       -netdev user,id=net0,ipv6=off,hostfwd=tcp::2222-:22,hostfwd=tcp::5901-:5900 \
       -device virtio-net-pci,netdev=net0

KVM Apple hypervisor support
---------------------------

On Linux hosts with the downstream ``KVM_CAP_ARM_APPLE_HYPERVISOR_FUNCTIONS``
capability, QEMU automatically attempts to enable in-kernel Apple HVC and
ISV=0 MMIO handling during ARM KVM initialization. Successful enablement is
always logged and bypasses both QEMU's Apple HVC forwarding filter (even
when ``QEMU_VMAPPLE_KVM_HVC`` is set) and its ISV=0 MMIO emulator.

If enablement fails, QEMU logs a warning and retains the existing userspace
handling. The same fallback applies when the capability is unavailable,
without a warning: Apple HVC forwarding requires ``QEMU_VMAPPLE_KVM_HVC``
to be set, while ISV=0 MMIO emulation uses KVM's non-ISV exits as before.

Tracing KVM pointer authentication calls
---------------------------------------

Apple pointer authentication HVCs forwarded to QEMU by KVM can be traced by
adding the following option to the QEMU command line::

  -trace 'enable=kvm_arm_vmapple_pauth_hvc*'

These events are disabled by default. They record the vCPU index, HVC number,
input registers x1-x4, and handler completion status (zero or a negative host
error code). If reading an input register fails, only the completion event is
emitted. Enabling tracing does not itself enable HVC forwarding.
HVCs handled by the in-kernel Apple hypervisor capability do not produce
these QEMU trace events.

The input registers can contain pointer authentication key material, so treat
the trace output as sensitive.
