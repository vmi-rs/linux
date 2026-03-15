.. SPDX-License-Identifier: GPL-2.0

==============================================
KVM Virtual Machine Introspection (VMI) API
==============================================

.. contents:: :local:

1. Overview
===========

Virtual Machine Introspection (VMI) allows an external agent process to
monitor and control the execution of a KVM guest. The agent can intercept
guest events (control register writes, MSR writes, CPUID execution,
breakpoints, memory accesses, etc.), inspect and modify guest state, and
maintain alternate memory views with per-page access controls and GFN
remapping.

KVM VMI follows the kernel's philosophy of providing mechanisms, not
policies. The kernel exposes generic capabilities - intercepting register
writes, setting EPT permissions, remapping guest pages - and the agent
decides what to monitor and how to respond. There are no
introspection-specific concepts in the uAPI.

All VMI operations go through a ``vmi_fd`` file descriptor obtained via
``KVM_CREATE_VMI`` on the VM fd. Events are delivered via per-vCPU shared
ring buffers with eventfd signaling. When the ``vmi_fd`` is closed, all VMI
state is cleaned up automatically: views are destroyed, events are disabled,
vCPUs are switched back to view 0, and per-vCPU state is freed.

2. Architecture
===============

Control Plane vs Execution Plane
---------------------------------

VMI separates the control plane from the execution plane:

- **Control plane** (``vmi_fd``): All VMI configuration - ring setup, event
  control, view management, memory access, pause, injection. No VMI ioctls
  are issued on the VM fd or vCPU fd.

- **Execution plane** (``vcpu_fd``): Standard KVM vCPU operations.
  ``KVM_RUN`` drives guest execution; events cause the vCPU to block inside
  ``KVM_RUN`` with ``vcpu->mutex`` released, allowing the agent to call
  standard KVM vCPU ioctls (``KVM_GET_REGS``, ``KVM_GET_FPU``, etc.) on a
  duplicated vCPU fd without deadlock.

External Agent Model
---------------------

The VMI agent is a separate process from QEMU. No QEMU patching is required.
The agent attaches to a running VM by:

1. Discovering the QEMU process (e.g., via ``/proc``)
2. Duplicating QEMU's VM fd and vCPU fds via ``pidfd_getfd()`` or
   ``/proc/<pid>/fd``
3. Issuing ``KVM_CREATE_VMI`` on the duplicated VM fd
4. Setting up rings and enabling events via the returned ``vmi_fd``

``KVM_CREATE_VMI`` bypasses the normal ``kvm->mm`` check that restricts KVM
ioctls to the process that created the VM, since VMI agents are inherently
cross-process.

::

   Agent process                    QEMU process
   +---------------------------+    +---------------------------+
   | vmi_fd (control plane)    |    | VM fd                     |
   |  - ring setup             |    | vCPU fds                  |
   |  - event control          |    | KVM_RUN loop              |
   |  - view management        |    |                           |
   |  - memory access          |    |                           |
   |                           |    |                           |
   | Duplicated vCPU fds       |    |                           |
   |  - KVM_GET_REGS (exotic)  |    |                           |
   +----------+----------------+    +----------+----------------+
              |                                |
              | ioctls                         | KVM_RUN
              v                                v
   +-------------------------------------------------------+
   |                     KVM kernel                         |
   |  - Event generation (VM-exit interception)             |
   |  - Ring-based event delivery (per-vCPU)                |
   |  - Alternate EPT views (dynamic allocation)            |
   |  - GFN remapping (shadow pages)                        |
   |  - Guest memory mapping (fault-based)                  |
   +-------------------------------------------------------+

Reserved Exit Reason
---------------------

``KVM_EXIT_VMI`` (44) is reserved in the ``kvm_run`` exit reason space but
is not used. All event delivery uses the ring buffer mechanism described in
section 5. The exit reason is reserved to prevent conflicts with future
KVM changes.

3. Capabilities
===============

All capabilities are checked via ``KVM_CHECK_EXTENSION`` on the VM fd.

.. list-table::
   :header-rows: 1
   :widths: 30 10 60

   * - Capability
     - Value
     - Description
   * - ``KVM_CAP_VMI``
     - 248
     - VMI subsystem available. Requires ``CONFIG_KVM_VMI=y`` and EPT
       support on x86 (Intel VT-x).
   * - ``KVM_CAP_VMI_RING``
     - 260
     - Ring-based event delivery (per-vCPU shared ring buffers with
       eventfd signaling).
   * - ``KVM_CAP_VMI_GUEST_MMAP``
     - 261
     - Guest physical memory mapping via ``vmi_fd`` mmap.
   * - ``KVM_CAP_VMI_PAUSE``
     - 262
     - VM-wide and per-vCPU pause support with refcounting.
   * - ``KVM_CAP_VMI_INJECT``
     - 263
     - Exception, interrupt, and NMI injection into guest vCPUs.
   * - ``KVM_CAP_VMI_ALLOC_GFN``
     - 264
     - Shadow GFN allocation for GFN remapping workflows.
   * - ``KVM_CAP_VMI_EPT_PW``
     - 265
     - EPT paging-write (PW) access monitoring. Controls whether CPU
       A/D bit updates trigger EPT violations.

4. Session Lifecycle
====================

4.1 KVM_CREATE_VMI
-------------------

:Capability: KVM_CAP_VMI
:Architectures: x86
:Type: vm ioctl
:Parameters: none
:Returns: a ``vmi_fd`` file descriptor on success, <0 on error

Creates a VMI session for the VM. Only one VMI session may be active per VM;
a second call returns ``-EBUSY``. The returned ``vmi_fd`` is the single
control channel for all VMI operations.

Requires ``CONFIG_KVM_VMI=y`` in the kernel configuration and hardware VMX
(Intel VT-x) support with EPT.

4.2 Cleanup on Close
----------------------

Closing the ``vmi_fd`` (or agent process exit) performs full cleanup:

1. All pending events are cancelled and blocked vCPUs are woken
2. Event monitoring is disabled (VMCS intercept bits cleared)
3. All vCPUs are switched back to view 0 (default host EPT)
4. All alternate views are destroyed (alternate EPT roots freed)
5. Per-vCPU rings are torn down
6. Shadow GFNs are freed
7. Per-vCPU VMI state is freed (deferred to VM destruction)

This ensures no VMI state leaks if the agent crashes or is killed.

4.3 Cross-Process Access
-------------------------

``KVM_CREATE_VMI`` bypasses the ``kvm->mm`` check that normally restricts
KVM ioctls to the creating process. This allows a separate VMI agent process
to create a session on a VM owned by QEMU.

The agent obtains QEMU's file descriptors via ``pidfd_getfd()``::

    int pidfd = pidfd_open(qemu_pid, 0);
    int vm_fd = pidfd_getfd(pidfd, qemu_vm_fd_num, 0);
    int vmi_fd = ioctl(vm_fd, KVM_CREATE_VMI);

Typical QEMU fd layout: fd 10 = kvm-vm, fd 11/13/15/17 = kvm-vcpu:0-3.

5. Ring-Based Event Delivery
=============================

Events are delivered via per-vCPU shared ring buffers. Each ring is a single
page shared between the kernel and the agent, with eventfd-based signaling
for synchronization.

5.1 Ring Setup
---------------

**KVM_VMI_SETUP_RING**

:Type: vmi_fd ioctl
:Parameters: ``struct kvm_vmi_setup_ring``
:Returns: 0 on success, <0 on error (``ring_fd`` set on success)

Sets up event delivery for one vCPU. The agent creates two eventfds and
passes them in. The kernel creates a ring page and returns a ``ring_fd``
for mmap.

::

    struct kvm_vmi_setup_ring {
        __u32 vcpu_id;    /* target vCPU */
        __u32 flags;      /* reserved, must be 0 */
        __s32 event_fd;   /* IN: kernel -> agent notification */
        __s32 ack_fd;     /* IN: agent -> kernel notification */
        __s32 ring_fd;    /* OUT: fd to mmap for the ring page */
        __s32 pad;
    };

The agent mmaps ``ring_fd`` at offset 0 for one page to access the ring::

    void *ring = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                      MAP_SHARED, ring_fd, 0);

One ring must be set up per vCPU that needs event delivery. Events only fire
on vCPUs with an active ring.

**KVM_VMI_TEARDOWN_RING**

:Type: vmi_fd ioctl
:Parameters: ``__u32 vcpu_id``
:Returns: 0 on success, <0 on error

Tears down the ring for one vCPU. Any pending event is cancelled and the
vCPU is woken.

5.2 Ring Layout
----------------

The ring page starts with a 64-byte header followed by event slots::

    +--------------------------------------------------+
    | Ring Header (64 bytes)                           |
    |   req_prod  (u32) - producer index (kernel)      |
    |   req_cons  (u32) - consumer index (agent)       |
    |   num_slots (u32) - number of event slots        |
    |   pad[13]   (u32) - reserved                     |
    +--------------------------------------------------+
    | Slot 0: struct kvm_vmi_ring_event                |
    +--------------------------------------------------+
    | Slot 1: struct kvm_vmi_ring_event                |
    +--------------------------------------------------+
    |   ...                                            |
    +--------------------------------------------------+
    | Slot N-1: struct kvm_vmi_ring_event              |
    +--------------------------------------------------+

::

    struct kvm_vmi_ring_header {
        __u32 req_prod;    /* producer index (kernel writes) */
        __u32 req_cons;    /* consumer index (agent writes) */
        __u32 num_slots;   /* number of event slots */
        __u32 pad[13];     /* pad to 64 bytes */
    };

The ring is a circular buffer. The current slot index is computed as
``index % num_slots``. The ring is full when
``req_prod - req_cons >= num_slots``.

5.3 Event Delivery Protocol
-----------------------------

The full event flow from guest trigger to guest resume:

1. Guest triggers an intercepted operation (e.g., MOV to CR3)
2. KVM intercepts in the VM-exit handler
3. Kernel writes the event to the ring slot at ``req_prod % num_slots``
4. Kernel snapshots registers into the slot (``struct kvm_vmi_regs``)
5. Kernel issues a write memory barrier (``smp_wmb``), then increments
   ``req_prod``
6. Kernel signals ``event_fd``
7. vCPU blocks inside ``KVM_RUN`` with ``vcpu->mutex`` released
8. Agent polls/reads ``event_fd``, reads slot at ``req_cons % num_slots``
9. Agent processes the event, optionally modifies registers and ``view_id``
10. Agent writes response flags to ``slot->response``
11. Agent increments ``req_cons``
12. Agent calls ``KVM_VMI_ACK_EVENT`` to wake the vCPU
13. Kernel reads response, applies actions (deny, set_regs, view switch,
    emulate, singlestep)
14. vCPU resumes guest execution

**KVM_VMI_ACK_EVENT**

:Type: vmi_fd ioctl
:Parameters: ``struct kvm_vmi_vcpu`` (``vcpu_id``)
:Returns: 0 on success, <0 on error

Signals that the agent has processed the event and written its response.
Wakes the blocked vCPU so it can read the response and resume.

5.4 Response Flags
-------------------

Response flags are written to ``slot->response`` as a bitmask before
calling ``KVM_VMI_ACK_EVENT``. Flags are combinable.

.. list-table::
   :header-rows: 1
   :widths: 35 10 55

   * - Flag
     - Value
     - Description
   * - ``KVM_VMI_RESPONSE_CONTINUE``
     - 0
     - Default. Proceed with normal handling of the intercepted operation.
   * - ``KVM_VMI_RESPONSE_DENY``
     - 1 << 0
     - Prevent the intercepted operation. For CR/MSR writes, the old value
       is preserved. For CPUID/descriptor/IO, the instruction is skipped
       (RIP advanced by ``insn_len``).
   * - ``KVM_VMI_RESPONSE_SET_REGS``
     - 1 << 1
     - Apply the agent's modified GP registers, RIP, and RFLAGS from the
       ring slot's register snapshot.
   * - ``KVM_VMI_RESPONSE_SWITCH_VIEW``
     - 1 << 2
     - Switch this vCPU to the view specified in ``slot->view_id`` on
       resume.
   * - ``KVM_VMI_RESPONSE_EMULATE``
     - 1 << 3
     - Emulate the faulting instruction. Applicable to mem_access, CPUID,
       and descriptor access events.
   * - ``KVM_VMI_RESPONSE_REINJECT``
     - 1 << 4
     - Re-inject the exception into the guest. For breakpoints (#BP),
       injects INT3. For debug (#DB), injects with RF flag set.
   * - ``KVM_VMI_RESPONSE_SINGLESTEP``
     - 1 << 5
     - Enable Monitor Trap Flag (MTF) for the next instruction. After the
       instruction executes, a ``KVM_VMI_EVENT_SINGLESTEP`` event fires.
   * - ``KVM_VMI_RESPONSE_SINGLESTEP_FAST``
     - 1 << 6
     - Atomic singlestep + view switch. Steps one instruction, then
       switches back to the ``restore_view`` saved at event time. Used for
       transparent breakpoint handling: step past the breakpoint in a clean
       view, then switch back to the instrumented view.

5.5 Register Snapshot
----------------------

Each ring event slot contains a full ``struct kvm_vmi_regs`` snapshot
written by the kernel:

**General-purpose registers**:
  ``rax``, ``rbx``, ``rcx``, ``rdx``, ``rsi``, ``rdi``, ``rbp``, ``rsp``,
  ``r8``-``r15``, ``rip``, ``rflags``

**Control registers**:
  ``cr0``, ``cr3``, ``cr4``, ``xcr0``

**Segment registers** (each with ``base``, ``limit``, ``selector``, ``ar``):
  ``cs``, ``ss``, ``ds``, ``es``, ``fs``, ``gs``

**Key MSRs**:
  ``sysenter_cs``, ``sysenter_esp``, ``sysenter_eip``, ``msr_efer``,
  ``msr_star``, ``msr_lstar``, ``msr_cstar``, ``msr_syscall_mask``,
  ``msr_kernel_gs_base``, ``msr_tsc_aux``

If the agent sets ``KVM_VMI_RESPONSE_SET_REGS``, the kernel restores the GP
registers, RIP, and RFLAGS from the agent's modified copy in the ring slot.
Control registers and MSRs are not restored via SET_REGS - they are managed
through their respective events (CR, MSR) or standard KVM ioctls.

For registers not in the snapshot (FPU, XSAVE, debug registers), the agent
can call standard KVM ioctls (``KVM_GET_FPU``, ``KVM_SET_FPU``,
``KVM_GET_XSAVE``, etc.) on a duplicated vCPU fd, since ``vcpu->mutex`` is
released while the vCPU is blocked waiting for the ring response.

6. Event Monitoring
====================

6.1 Controlling Events
-----------------------

**KVM_VMI_CONTROL_EVENT**

:Type: vmi_fd ioctl
:Parameters: ``struct kvm_vmi_control_event``
:Returns: 0 on success, <0 on error

Enables or disables event monitoring for the VM::

    struct kvm_vmi_control_event {
        __u32 event;   /* KVM_VMI_EVENT_* */
        __u32 enable;  /* 1 = enable, 0 = disable */
        union kvm_vmi_arch_control_data arch;
    };

Event monitoring is VM-wide: enabling an event causes it to be intercepted
on all vCPUs. However, events only fire on vCPUs that have a ring set up
(see section 5.1). The ``arch`` union carries event-specific parameters for
CR and MSR events.

When an event is enabled or disabled, all vCPUs are kicked to update their
VMCS intercept bits.

``KVM_VMI_EVENT_MEM_ACCESS`` does not use ``CONTROL_EVENT`` - it fires
automatically when a GFN in the current view has restricted access
permissions (see section 7.2).

6.2 Generic Events
-------------------

Generic events are architecture-independent. Their IDs occupy range 0 to 7.

KVM_VMI_EVENT_MEM_ACCESS (0)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:Trigger: EPT violation on a GFN with restricted permissions in the current
          view
:Data: ``struct kvm_vmi_event_mem_access``
:Valid responses: CONTINUE, EMULATE, SET_REGS, SWITCH_VIEW, SINGLESTEP,
                  SINGLESTEP_FAST

::

    struct kvm_vmi_event_mem_access {
        __u64 gpa;     /* faulting guest physical address */
        __u32 access;  /* access type that caused the violation */
        __u32 pad;
    };

This event does not require ``KVM_VMI_CONTROL_EVENT`` to enable. It fires
whenever a vCPU accesses a GFN whose permissions in the current view deny
that access type. Use ``KVM_VMI_SET_MEM_ACCESS`` (section 7.2) to configure
per-GFN permissions.

EMULATE tells KVM to emulate the faulting instruction, allowing it to
complete without modifying the EPT permissions. SINGLESTEP_FAST is commonly
used for transparent breakpoint handling: switch to a clean view, step one
instruction, then switch back.

KVM_VMI_EVENT_SINGLESTEP (1)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:Trigger: MTF (Monitor Trap Flag) VM-exit after executing one guest
          instruction
:Data: ``struct kvm_vmi_event_singlestep``
:Valid responses: CONTINUE, SET_REGS, SWITCH_VIEW, SINGLESTEP (to continue
                  stepping)

::

    struct kvm_vmi_event_singlestep {
        __u64 gpa;   /* guest physical address of the instruction */
    };

Singlestep events are triggered by a prior ``KVM_VMI_RESPONSE_SINGLESTEP``
or ``KVM_VMI_RESPONSE_SINGLESTEP_FAST`` response. They are not enabled via
``KVM_VMI_CONTROL_EVENT``.

To continue single-stepping, respond with ``KVM_VMI_RESPONSE_SINGLESTEP``
again. MTF is cleared after each singlestep event unless re-enabled.

KVM_VMI_EVENT_HYPERCALL (2)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:Trigger: Guest executes ``VMCALL`` (Intel) or ``VMMCALL`` (AMD)
:Data: ``struct kvm_vmi_event_hypercall``
:Valid responses: CONTINUE, SET_REGS

::

    struct kvm_vmi_event_hypercall {
        __u64 nr;    /* hypercall number (from RAX) */
        __u64 a0;    /* argument 0 (from RBX) */
        __u64 a1;    /* argument 1 (from RCX) */
        __u64 a2;    /* argument 2 (from RDX) */
    };

Allows the guest to communicate with the VMI agent via hypercalls.

6.3 x86 Architecture Events
-----------------------------

x86 event IDs start at ``KVM_VMI_EVENT_ARCH_BASE`` (8).

KVM_VMI_EVENT_CR (8)
~~~~~~~~~~~~~~~~~~~~~~

:Trigger: Guest writes to CR0, CR3, CR4, or XCR0
:Data: ``struct kvm_vmi_event_cr``
:Valid responses: CONTINUE, DENY, SET_REGS

::

    struct kvm_vmi_event_cr {
        __u32 index;       /* KVM_VMI_CR0/CR3/CR4/XCR0 */
        __u32 pad;
        __u64 old_value;   /* current value before write */
        __u64 new_value;   /* value the guest is writing */
    };

Control parameters (``arch.cr`` in ``struct kvm_vmi_control_event``):

- ``index``: Which CR to monitor (``KVM_VMI_CR0`` = 0, ``KVM_VMI_CR3`` = 3,
  ``KVM_VMI_CR4`` = 4, ``KVM_VMI_XCR0`` = 64)
- ``onchangeonly``: If set, only fire when the new value differs from the
  old value
- ``bitmask``: Only fire when bits in the bitmask change (0 = all bits)

Each CR index is enabled/disabled independently. The event fires **before**
the write is applied. CONTINUE allows the write. DENY skips the write and
advances RIP past the instruction.

KVM_VMI_EVENT_MSR (9)
~~~~~~~~~~~~~~~~~~~~~~~

:Trigger: Guest writes to a monitored MSR via ``WRMSR``
:Data: ``struct kvm_vmi_event_msr``
:Valid responses: CONTINUE, DENY, SET_REGS

::

    struct kvm_vmi_event_msr {
        __u32 index;       /* MSR index */
        __u32 pad;
        __u64 old_value;   /* current value before write */
        __u64 new_value;   /* value the guest is writing */
    };

Control parameters (``arch.msr`` in ``struct kvm_vmi_control_event``):

- ``msr``: MSR index to monitor
- ``onchangeonly``: If set, only fire when the new value differs

Each MSR is enabled/disabled independently. The event fires **before** the
write is applied. CONTINUE allows the write. DENY skips the write and
advances RIP.

KVM_VMI_EVENT_CPUID (10)
~~~~~~~~~~~~~~~~~~~~~~~~~~

:Trigger: Guest executes ``CPUID`` instruction
:Data: ``struct kvm_vmi_event_cpuid``
:Valid responses: EMULATE, DENY, SET_REGS

::

    struct kvm_vmi_event_cpuid {
        __u32 leaf;      /* EAX value (CPUID leaf) */
        __u32 subleaf;   /* ECX value (CPUID subleaf) */
    };

EMULATE executes CPUID normally and returns the result to the guest. DENY
skips the instruction (advances RIP). SET_REGS allows the agent to provide
custom CPUID results by modifying EAX/EBX/ECX/EDX in the register snapshot.

KVM_VMI_EVENT_BREAKPOINT (11)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:Trigger: Guest executes ``INT3`` (software breakpoint, opcode ``0xCC``)
:Data: ``struct kvm_vmi_event_breakpoint``
:Valid responses: REINJECT, SET_REGS, SINGLESTEP, SINGLESTEP_FAST,
                  SWITCH_VIEW

::

    struct kvm_vmi_event_breakpoint {
        __u64 gpa;        /* guest physical address of the INT3 */
        __u32 insn_len;   /* instruction length (always 1 for INT3) */
        __u32 pad;
    };

The default response (no flags, CONTINUE) silently consumes the breakpoint -
the guest never sees the exception. REINJECT delivers #BP (vector 3) to the
guest as if KVM did not intercept it.

Common workflow for transparent breakpoints:

1. Receive breakpoint event in instrumented view (INT3 at shadow page)
2. Respond with SINGLESTEP_FAST + SWITCH_VIEW to clean view
3. One instruction executes in the clean view (original code)
4. Singlestep event fires, vCPU automatically switches back to
   instrumented view

KVM_VMI_EVENT_DEBUG (12)
~~~~~~~~~~~~~~~~~~~~~~~~~

:Trigger: Debug exception (#DB) - hardware breakpoint hit, single-step trap
:Data: ``struct kvm_vmi_event_debug``
:Valid responses: REINJECT, SET_REGS

::

    struct kvm_vmi_event_debug {
        __u64 pending_dbg;   /* DR6-style pending debug exceptions */
        __u64 gpa;           /* guest physical address of RIP, or ~0 if
                                the instruction page is not mapped */
    };

``gpa`` is the guest physical address that the (linearized) RIP translates to,
resolved as an instruction fetch at the guest's current privilege level.  It is
``~0ULL`` (KVM_VMI_INVALID_GFN) if RIP is not mapped.

The default response (no flags) silently consumes the exception. REINJECT
delivers #DB (vector 1) to the guest with the RF flag set in RFLAGS to
prevent re-triggering on the same instruction.

KVM_VMI_EVENT_DESC_ACCESS (13)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:Trigger: Guest accesses a descriptor table register (``LGDT``, ``SGDT``,
          ``LIDT``, ``SIDT``, ``LLDT``, ``SLDT``, ``LTR``, ``STR``)
:Data: ``struct kvm_vmi_event_desc_access``
:Valid responses: EMULATE, DENY, SET_REGS

::

    struct kvm_vmi_event_desc_access {
        __u8 descriptor;   /* KVM_VMI_DESC_GDTR/IDTR/LDTR/TR */
        __u8 is_write;     /* 1 = write (LGDT/LIDT/LLDT/LTR), 0 = read */
        __u8 pad[6];
    };

Descriptor type constants:

- ``KVM_VMI_DESC_GDTR`` (0) - Global Descriptor Table Register
- ``KVM_VMI_DESC_IDTR`` (1) - Interrupt Descriptor Table Register
- ``KVM_VMI_DESC_LDTR`` (2) - Local Descriptor Table Register
- ``KVM_VMI_DESC_TR`` (3) - Task Register

EMULATE executes the instruction normally. DENY skips it (advances RIP).

KVM_VMI_EVENT_IO (14)
~~~~~~~~~~~~~~~~~~~~~~~

:Trigger: Guest executes ``IN``, ``OUT``, ``INS``, or ``OUTS`` instruction
:Data: ``struct kvm_vmi_event_io``
:Valid responses: CONTINUE, DENY, SET_REGS

::

    struct kvm_vmi_event_io {
        __u16 port;     /* I/O port number */
        __u8  bytes;    /* operand size (1, 2, or 4) */
        __u8  in;       /* 1 = IN/INS, 0 = OUT/OUTS */
        __u8  string;   /* 1 = string I/O (INS/OUTS) */
        __u8  pad[3];
    };

CONTINUE allows the I/O operation to proceed normally. DENY skips the
instruction (advances RIP).

7. Alternate Memory Views
==========================

Alternate memory views provide independent EPT (Extended Page Table) roots
with per-GFN access permissions and GFN remapping. Each view is a complete
alternate address space for the guest, lazily populated from the host EPT.

View 0 is the default host view and always exists. It cannot be created,
destroyed, or have its permissions or GFN mappings modified.

7.1 View Management
---------------------

**KVM_VMI_CREATE_VIEW**

:Type: vmi_fd ioctl
:Parameters: ``struct kvm_vmi_view``
:Returns: 0 on success (``view_id`` set), <0 on error

::

    struct kvm_vmi_view {
        __u32 view_id;         /* OUT: assigned by kernel */
        __u32 flags;           /* reserved, must be 0 */
        __u8  default_access;  /* default R/W/X for new entries */
        __u8  pad[7];
    };

Creates a new alternate EPT root. The view starts empty; entries are lazily
populated from the host EPT as the guest accesses memory. The
``default_access`` field sets the default R/W/X permissions for
lazily-populated entries (combination of ``KVM_VMI_ACCESS_R/W/X`` flags).

The kernel assigns a monotonically increasing ``view_id`` starting from 1.
View IDs are stable u32 values suitable for use as EPTP list indices (for
future VMFUNC support) when <= 511.

W without R is rejected (``-EINVAL``) since EPT cannot encode write-only
pages.

Views are allocated dynamically with no hardcoded limit.

**KVM_VMI_DESTROY_VIEW**

:Type: vmi_fd ioctl
:Parameters: ``struct kvm_vmi_view`` (``view_id`` IN)
:Returns: 0 on success, <0 on error

Destroys an alternate view and frees its EPT root. Fails with ``-EBUSY`` if
any vCPU is currently on this view. Cannot destroy view 0 (``-EINVAL``).

**KVM_VMI_SWITCH_VIEW**

:Type: vmi_fd ioctl
:Parameters: ``struct kvm_vmi_switch_view``
:Returns: 0 on success, <0 on error

::

    struct kvm_vmi_switch_view {
        __u32 view_id;
        __u32 pad;
    };

Switches all vCPUs to the specified view. For per-vCPU view switching, use
``KVM_VMI_RESPONSE_SWITCH_VIEW`` in a ring event response instead.

7.2 Memory Access Control
---------------------------

**KVM_VMI_SET_MEM_ACCESS**

:Type: vmi_fd ioctl
:Parameters: ``struct kvm_vmi_mem_access``
:Returns: 0 on success, <0 on error

::

    struct kvm_vmi_mem_access {
        __u32 view_id;
        __u32 nr;
        union {
            /* Single-GFN mode (nr <= 1) */
            struct {
                __u64 gfn;
                __u8  access;
                __u8  pad[7];
            };
            /* Batch mode (nr > 1) */
            struct {
                __u64 gfns_uaddr;      /* pointer to __u64[] */
                __u64 accesses_uaddr;  /* pointer to __u8[] */
            };
        };
    };

Sets per-GFN access permissions in an alternate view. Cannot modify view 0
(``-EINVAL``).

**Single-GFN mode** (``nr`` <= 1): Sets permissions for one GFN using the
inline ``gfn`` and ``access`` fields.

**Batch mode** (``nr`` > 1): Sets permissions for multiple GFNs.
``gfns_uaddr`` and ``accesses_uaddr`` point to userspace arrays of ``nr``
entries each.

Access flags:

.. list-table::
   :header-rows: 1
   :widths: 30 10 60

   * - Flag
     - Value
     - Description
   * - ``KVM_VMI_ACCESS_R``
     - 1 << 0
     - Allow read access
   * - ``KVM_VMI_ACCESS_W``
     - 1 << 1
     - Allow write access
   * - ``KVM_VMI_ACCESS_X``
     - 1 << 2
     - Allow execute access
   * - ``KVM_VMI_ACCESS_PW``
     - 1 << 3
     - Allow CPU paging-write access (A/D bit updates). Without this
       flag, CPU page-walk A/D updates on the GFN cause EPT violations.
       Requires ``KVM_CAP_VMI_EPT_PW``.
   * - ``KVM_VMI_ACCESS_DEFAULT``
     - 0xff
     - Reset to the view's default access permissions

Clearing a permission bit causes the corresponding access type to trigger a
``KVM_VMI_EVENT_MEM_ACCESS`` event.

**KVM_VMI_GET_MEM_ACCESS**

:Type: vmi_fd ioctl
:Parameters: ``struct kvm_vmi_mem_access``
:Returns: 0 on success, <0 on error

Queries the current access permissions for GFNs in a view. Supports both
single-GFN and batch modes, same as ``KVM_VMI_SET_MEM_ACCESS``.

7.3 GFN Remapping
-------------------

GFN remapping allows replacing a guest page's backing in an alternate view,
enabling transparent code patching without modifying the guest's original
memory.

**Shadow Page Workflow**

The typical workflow for transparent breakpoints:

1. Allocate a shadow page::

       struct kvm_vmi_alloc_gfn alloc = {};
       ioctl(vmi_fd, KVM_VMI_ALLOC_GFN, &alloc);
       /* alloc.gfn now contains the shadow GFN */

2. Map the shadow page and the original page via ``vmi_fd`` mmap, copy the
   original content, then patch it (e.g., write ``INT3`` at the target
   offset)

3. Remap the GFN in the alternate view::

       struct kvm_vmi_change_gfn change = {
           .view_id = my_view,
           .old_gfn = original_gfn,
           .new_gfn = alloc.gfn,
       };
       ioctl(vmi_fd, KVM_VMI_CHANGE_GFN, &change);

4. Guest executing in ``my_view`` now sees the patched shadow page at
   ``original_gfn``. In view 0 (or other views without the remap), the
   original unpatched page is visible.

**KVM_VMI_CHANGE_GFN**

:Type: vmi_fd ioctl
:Parameters: ``struct kvm_vmi_change_gfn``
:Returns: 0 on success, <0 on error

::

    struct kvm_vmi_change_gfn {
        __u32 view_id;   /* target view (must not be 0) */
        __u32 pad;
        __u64 old_gfn;   /* GFN whose mapping to override */
        __u64 new_gfn;   /* backing GFN (shadow or regular) */
    };

Remaps ``old_gfn`` to use ``new_gfn``'s backing page in the specified view.
Cannot remap in view 0 (``-EINVAL``). Set ``new_gfn`` to
``KVM_VMI_INVALID_GFN`` (~0ULL) to revert to the host mapping.

``new_gfn`` can be a shadow GFN (allocated via ``KVM_VMI_ALLOC_GFN``) or a
regular guest GFN (to alias one guest page to another).

**KVM_VMI_ALLOC_GFN**

:Type: vmi_fd ioctl
:Parameters: ``struct kvm_vmi_alloc_gfn``
:Returns: 0 on success (``gfn`` set), <0 on error

::

    struct kvm_vmi_alloc_gfn {
        __u64 gfn;   /* OUT: allocated shadow GFN */
    };

Allocates a kernel page and assigns it a shadow GFN. Shadow GFNs start at
``KVM_VMI_SHADOW_GFN_BASE`` (0xFFFFFE000000), well above any realistic
guest physical address space. The shadow page can be accessed via
``vmi_fd`` mmap (offset = shadow GFN << PAGE_SHIFT).

**KVM_VMI_FREE_GFN**

:Type: vmi_fd ioctl
:Parameters: ``struct kvm_vmi_free_gfn``
:Returns: 0 on success, <0 on error

::

    struct kvm_vmi_free_gfn {
        __u64 gfn;   /* IN: shadow GFN to free */
    };

Frees a shadow page. Fails with ``-EBUSY`` if any view still references
this shadow GFN via a ``KVM_VMI_CHANGE_GFN`` remap.

8. Guest Memory Access
=======================

Guest physical memory can be mapped into the agent process by calling
``mmap()`` on the ``vmi_fd``.

::

    /* Map 4KB at guest physical address 0x1000 */
    void *page = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                      MAP_SHARED, vmi_fd, 0x1000);

The mapping is fault-based: pages are resolved on first access by looking up
the GFN in the guest's address space and mapping the underlying host page.
No pages are pinned at mmap time.

Shadow GFNs (>= ``KVM_VMI_SHADOW_GFN_BASE``) are also accessible via this
mechanism, using ``shadow_gfn << PAGE_SHIFT`` as the mmap offset. This
allows the agent to write patched code into shadow pages.

The mapping uses ``VM_PFNMAP`` - mapped pages do not count toward the
agent's RSS.

Requires ``KVM_CAP_VMI_GUEST_MMAP``.

9. vCPU Pause
==============

The pause mechanism allows the agent to stop vCPU execution to safely
inspect or modify guest state.

**KVM_VMI_PAUSE_VM**

:Type: vmi_fd ioctl
:Parameters: none
:Returns: 0 on success, <0 on error

Pauses all vCPUs. Increments a per-vCPU ``pause_count``. Forces in-guest
vCPUs out of guest mode (``KVM_REQ_OUTSIDE_GUEST_MODE``) and wakes halted
vCPUs (``KVM_REQ_UNBLOCK``). After this ioctl returns, all vCPUs have
released ``vcpu->mutex``, allowing the agent to call ``KVM_GET_REGS`` and
other vCPU ioctls.

**KVM_VMI_UNPAUSE_VM**

:Type: vmi_fd ioctl
:Parameters: none
:Returns: 0 on success, <0 on error

Decrements ``pause_count`` on all vCPUs and wakes any that reach zero.

**KVM_VMI_PAUSE_VCPU**

:Type: vmi_fd ioctl
:Parameters: ``struct kvm_vmi_vcpu`` (``vcpu_id``)
:Returns: 0 on success, <0 on error

Pauses a single vCPU. Same semantics as ``KVM_VMI_PAUSE_VM`` but for one
vCPU.

**KVM_VMI_UNPAUSE_VCPU**

:Type: vmi_fd ioctl
:Parameters: ``struct kvm_vmi_vcpu`` (``vcpu_id``)
:Returns: 0 on success, <0 on error

Unpauses a single vCPU.

Pause is refcounted: multiple pause calls require matching unpause calls
before the vCPU resumes. This allows nested pause/unpause from different
parts of the agent without interference.

Requires ``KVM_CAP_VMI_PAUSE``.

10. Event Injection
====================

**KVM_VMI_INJECT_EVENT**

:Type: vmi_fd ioctl
:Parameters: ``struct kvm_vmi_inject_event``
:Returns: 0 on success, <0 on error

::

    struct kvm_vmi_inject_event {
        __u32 vcpu_id;      /* target vCPU */
        __u8  vector;       /* interrupt/exception vector (0-255) */
        __u8  type;         /* KVM_VMI_EVENT_TYPE_* */
        __u8  insn_len;     /* instruction length for SW_INT/SW_EXCEPT */
        __u8  pad;
        __u32 error_code;   /* exception error code */
        __u32 has_error;    /* 1 if error_code is valid */
        __u64 cr2;          /* CR2 value for #PF (vector 14) */
    };

Injects an exception, interrupt, or NMI into a guest vCPU. The ``type``
field uses VMCS VM-entry interruption type encoding (bits 10:8):

.. list-table::
   :header-rows: 1
   :widths: 35 10 55

   * - Type
     - Value
     - Description
   * - ``KVM_VMI_EVENT_TYPE_EXT_INT``
     - 0
     - External interrupt
   * - ``KVM_VMI_EVENT_TYPE_NMI``
     - 2
     - Non-maskable interrupt
   * - ``KVM_VMI_EVENT_TYPE_HW_EXCEPT``
     - 3
     - Hardware exception (e.g., #PF, #GP)
   * - ``KVM_VMI_EVENT_TYPE_SW_INT``
     - 4
     - Software interrupt (``INT nn``)
   * - ``KVM_VMI_EVENT_TYPE_PRIV_SW_INT``
     - 5
     - Privileged software interrupt
   * - ``KVM_VMI_EVENT_TYPE_SW_EXCEPT``
     - 6
     - Software exception (#BP, #OF)

``insn_len`` must be set (1-15) for ``SW_INT``, ``PRIV_SW_INT``, and
``SW_EXCEPT`` types, and must be 0 for all others. For ``#PF`` (vector 14),
set ``cr2`` to the faulting address and ``has_error`` to 1 with the
appropriate error code.

Requires ``KVM_CAP_VMI_INJECT``.
