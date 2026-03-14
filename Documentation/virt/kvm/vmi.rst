.. SPDX-License-Identifier: GPL-2.0

==============================================
KVM Virtual Machine Introspection (VMI) API
==============================================

.. contents:: :local:

1. Overview
===========

Virtual Machine Introspection (VMI) lets an external agent process observe and
control the execution of a KVM guest. The agent can intercept guest events
(register writes, breakpoints, memory accesses, hypercalls, ...), inspect and
modify guest state, and maintain alternate memory views with per-page access
control and guest-frame remapping.

KVM VMI follows the kernel's philosophy of providing mechanisms, not policy.
The kernel exposes generic capabilities - intercepting register writes, setting
per-view page permissions, remapping guest frames - and the agent decides what
to monitor and how to respond. There are no introspection-specific policies in
the uAPI.

VMI is implemented on **x86** (Intel VMX, using EPT for alternate views). The
control plane - the ``vmi_fd`` and all of its ioctls, the per-vCPU event ring,
guest-memory mmap, pause, and shadow-frame allocation - and the set of
interceptable events, the per-event data, the captured register snapshot, and
the event-injection model are documented below.

All VMI operations go through a ``vmi_fd`` obtained via ``KVM_CREATE_VMI`` on
the VM fd. Events are delivered through per-vCPU shared ring buffers with
eventfd signalling. When the ``vmi_fd`` is closed (including on agent crash),
all VMI state is cleaned up automatically.

2. Architecture
===============

Control plane vs execution plane
--------------------------------

VMI separates the control plane from the execution plane:

- **Control plane** (``vmi_fd``): all VMI configuration - ring setup, event
  control, view management, memory access, guest-memory mmap, pause, and event
  injection. No VMI ioctls are issued on the VM fd or vCPU fd (other than
  ``KVM_CREATE_VMI`` itself, which is a VM-fd ioctl).

- **Execution plane** (``vcpu_fd``): standard KVM vCPU operation. ``KVM_RUN``
  drives guest execution; an intercepted event causes the vCPU to block
  *inside* ``KVM_RUN`` with ``vcpu->mutex`` released, so the agent can call
  standard KVM vCPU ioctls (``KVM_GET_REGS``, ``KVM_GET_FPU``,
  ``KVM_GET_ONE_REG``, ...) on a duplicated vCPU fd without deadlocking.

External agent model
--------------------

The VMI agent is normally a separate process from the VMM (e.g. QEMU). No VMM
patching is required. The agent attaches to a running VM by:

1. Discovering the VMM process (e.g. via ``/proc``).
2. Duplicating the VMM's VM fd and vCPU fds via ``pidfd_getfd()`` or
   ``/proc/<pid>/fd``.
3. Issuing ``KVM_CREATE_VMI`` on the duplicated VM fd.
4. Setting up rings and enabling events through the returned ``vmi_fd``.

Two cross-process gates make this work (both only present when
``CONFIG_KVM_VMI=y``):

- ``KVM_CREATE_VMI`` is dispatched *before* the usual ``kvm->mm ==
  current->mm`` check that restricts VM-fd ioctls to the creating process, so
  the agent can create a session on a foreign VM. Every *other* VM-fd ioctl
  still requires the creating process's mm.
- While a VMI session is active, vCPU-fd ioctls from a foreign mm are
  permitted, so the agent can call ``KVM_GET_REGS`` / ``KVM_SET_REGS`` / etc. on
  duplicated vCPU fds while a vCPU is parked. Without an active session a
  foreign-mm vCPU ioctl returns ``-EIO`` as usual.

::

   Agent process                    VMM process
   +---------------------------+    +---------------------------+
   | vmi_fd (control plane)    |    | VM fd                     |
   |  - ring setup             |    | vCPU fds                  |
   |  - event control          |    | KVM_RUN loop              |
   |  - view management        |    |                           |
   |  - memory access          |    |                           |
   |  - guest-memory mmap      |    |                           |
   |                           |    |                           |
   | Duplicated vCPU fds       |    |                           |
   |  - KVM_GET_REGS, ...      |    |                           |
   +----------+----------------+    +----------+----------------+
              |                                |
              | ioctls                         | KVM_RUN
              v                                v
   +-------------------------------------------------------+
   |                     KVM kernel                         |
   |  - Event generation (VM-exit interception)             |
   |  - Ring-based event delivery (per-vCPU)                |
   |  - Alternate views (EPT)                               |
   |  - Guest-frame remapping (shadow pages)                |
   |  - Guest memory mapping (fault-based)                  |
   +-------------------------------------------------------+

Event delivery
--------------

There is no ``KVM_EXIT`` reason for VMI. ``KVM_RUN`` does not return to the
VMM's run loop for a VMI event; the vCPU thread blocks inside ``KVM_RUN`` and
the event is delivered to the agent through the per-vCPU ring buffer and
eventfd described in section 5.

3. Capabilities
===============

All capabilities are queried with ``KVM_CHECK_EXTENSION`` on the VM fd. They are
**advertise-only**: a capability reports whether the feature is supported, but
the ioctls do not re-check it at dispatch time. Each ``vmi_fd`` ioctl instead
validates its own preconditions - most return ``-EINVAL`` when no VMI session is
active (the ``vmi_fd`` normally exists only while a session does). Where a
feature is unsupported on the running platform the corresponding ioctl fails
with ``-EOPNOTSUPP`` (see the per-ioctl descriptions).

.. list-table::
   :header-rows: 1
   :widths: 32 8 60

   * - Capability
     - Value
     - Description
   * - ``KVM_CAP_VMI``
     - 500
     - VMI subsystem available. Requires ``CONFIG_KVM_VMI=y`` and EPT
       (``enable_ept``).
   * - ``KVM_CAP_VMI_RING``
     - 501
     - Ring-based event delivery (per-vCPU shared rings + eventfd).
   * - ``KVM_CAP_VMI_GUEST_MMAP``
     - 502
     - Guest physical memory mapping via ``vmi_fd`` mmap.
   * - ``KVM_CAP_VMI_PAUSE``
     - 503
     - VM-wide and per-vCPU pause support with refcounting.
   * - ``KVM_CAP_VMI_INJECT``
     - 504
     - Event injection (exception/interrupt/NMI).
   * - ``KVM_CAP_VMI_ALLOC_GFN``
     - 505
     - Shadow-frame allocation for guest-frame remapping workflows.

Configuration: ``CONFIG_KVM_VMI`` depends on ``KVM_INTEL && X86_64`` (no SVM/AMD
support).

4. Session lifecycle
====================

4.1 KVM_CREATE_VMI
------------------

:Capability: KVM_CAP_VMI
:Architectures: x86
:Type: vm ioctl (``_IO(KVMIO, 0xe9)``, no argument)
:Parameters: none
:Returns: a ``vmi_fd`` file descriptor on success, < 0 on error

Creates a VMI session for the VM and returns ``vmi_fd``, the single control
channel for all VMI operations. Only one VMI session may be active per VM; a
second call returns ``-EBUSY``. ``-ENOMEM`` is returned on allocation failure.

``KVM_CREATE_VMI`` may be issued from a process other than the one that created
the VM (see "External agent model" above).

4.2 Cross-process access
------------------------

The agent obtains the VMM's file descriptors via ``pidfd_getfd()``::

    int pidfd  = pidfd_open(vmm_pid, 0);
    int vm_fd  = pidfd_getfd(pidfd, vmm_vm_fd_num, 0);
    int vmi_fd = ioctl(vm_fd, KVM_CREATE_VMI);

vCPU fds are duplicated the same way and used directly with standard KVM vCPU
ioctls while a vCPU is parked (blocked on a ring event or paused).

4.3 Cleanup on close
--------------------

Closing the ``vmi_fd`` (explicitly or on agent exit) performs full teardown so
no VMI state leaks if the agent crashes. The teardown, in order:

1. All vCPUs are paused (parked with ``vcpu->mutex`` released).
2. Any guest CPU state masked by an in-flight single-step is restored.
3. VM-wide event monitoring is disabled and arch monitoring state is reset.
4. Every vCPU is switched back to view 0 (the host view).
5. In-flight EPT fault handlers are drained.
6. All shadow frames are freed.
7. All alternate views are destroyed (their EPT roots freed).
8. Per-vCPU rings are torn down; any vCPU blocked on a pending event is woken
   and resumes with the default action (CONTINUE).
9. Per-vCPU and VM-wide VMI state is detached and freed after an SRCU grace
   period.

5. Ring-based event delivery
============================

Events are delivered through per-vCPU shared ring buffers. Each ring is a single
page shared between the kernel and the agent, with eventfd-based signalling.

Delivery is a **synchronous, single-outstanding handshake**: when a vCPU hits an
intercepted event, the kernel publishes exactly one event into that vCPU's ring
and the vCPU thread blocks until the agent acknowledges it. A given vCPU never
has more than one event outstanding, and the producer never checks for a "full"
ring - it always blocks for the ack before it could produce another event.

5.1 Ring setup
--------------

**KVM_VMI_SETUP_RING** (``_IOWR(KVMIO, 0xea, struct kvm_vmi_setup_ring)``)

:Type: vmi_fd ioctl
:Parameters: ``struct kvm_vmi_setup_ring`` (IN/OUT)
:Returns: 0 on success (``ring_fd`` filled in), < 0 on error

Sets up event delivery for one vCPU. The agent creates two eventfds and passes
them in; the kernel allocates the ring page and returns a ``ring_fd`` to mmap.

::

    struct kvm_vmi_setup_ring {
        __u32 vcpu_id;    /* IN: target vCPU */
        __u32 flags;      /* IN: reserved, must be 0 */
        __s32 event_fd;   /* IN: eventfd, kernel -> agent notification */
        __s32 ack_fd;     /* IN: eventfd, agent -> kernel notification */
        __s32 ring_fd;    /* OUT: fd to mmap for the ring page */
        __s32 pad;
    };

The agent mmaps ``ring_fd`` at offset 0 for exactly one page::

    void *ring = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                      MAP_SHARED, ring_fd, 0);

One ring is set up per vCPU that needs event delivery; events only fire on
vCPUs that have an active ring. Errors: ``-EINVAL`` (``flags != 0``, unknown
``vcpu_id``, or vCPU without VMI state), ``-EEXIST`` (ring already set up),
``-ENOMEM``, or an eventfd error propagated from ``event_fd``/``ack_fd``.

The ``ring_fd`` is independent of the ring's lifetime: closing it does not free
the ring page (its ``release`` is a no-op). The ring page is owned by the
session and is freed by ``KVM_VMI_TEARDOWN_RING`` or ``vmi_fd`` close.

**KVM_VMI_TEARDOWN_RING** (``_IOW(KVMIO, 0xeb, __u32)``)

:Type: vmi_fd ioctl
:Parameters: ``__u32 vcpu_id`` (a bare u32, not a struct)
:Returns: 0 on success, < 0 on error

Tears down the ring for one vCPU. Internally the whole VM is paused, the ring is
freed, and the VM is unpaused. A vCPU blocked on a pending event is woken and
resumes with the default action (the pending event is cancelled, not answered).
Errors: ``-EINVAL`` (unknown ``vcpu_id``), ``-ENOENT`` (no ring set up).
Userspace must ``close(ring_fd)`` separately.

5.2 Ring layout
---------------

The ring page is a 16-byte header followed by ``num_slots`` event slots::

    +--------------------------------------------------+
    | struct kvm_vmi_ring_header (16 bytes)            |
    +--------------------------------------------------+
    | Slot 0: struct kvm_vmi_ring_event                |
    +--------------------------------------------------+
    | Slot 1: struct kvm_vmi_ring_event                |
    +--------------------------------------------------+
    |   ...                                            |
    +--------------------------------------------------+
    | Slot num_slots-1                                 |
    +--------------------------------------------------+

::

    struct kvm_vmi_ring_header {
        __u32 req_prod;    /* producer index (kernel) */
        __u32 req_cons;    /* consumer index */
        __u32 num_slots;   /* number of event slots */
        __u32 pad;
    };

``num_slots`` is computed by the kernel as
``(PAGE_SIZE - sizeof(struct kvm_vmi_ring_header)) /
sizeof(struct kvm_vmi_ring_event)`` (at least 1) and reported in the header. The
exact value depends on ``sizeof(struct kvm_vmi_ring_event)``, which embeds the
full register snapshot, so it is architecture dependent - read ``num_slots``
rather than assuming a constant. Slot ``i`` lives at index ``i % num_slots``.

Because delivery is synchronous (one event outstanding per vCPU), ``num_slots``
> 1 is not required for correctness; the indices are sized for generality.

5.3 Event delivery protocol
---------------------------

Producer (kernel), on an intercepted event:

1. Read ``prod = req_prod``; select slot ``prod % num_slots``.
2. Write the event header and event-specific payload into the slot.
3. Snapshot the vCPU registers into ``slot->regs`` (section 5.6).
4. Set ``slot->response = 0`` and ``slot->view_id = current view`` (so the
   agent can see which view the event fired in).
5. ``smp_wmb()``, then ``WRITE_ONCE(req_prod, prod + 1)``.
6. Signal ``event_fd``.
7. Release ``vcpu->mutex`` (and unload vCPU state) and block until the event is
   acknowledged.

Consumer (agent):

8. Wait on ``event_fd`` (read/poll); read the slot the kernel just published.
9. Process the event; optionally modify ``slot->regs`` and ``slot->view_id``.
10. Write the response bitmask to ``slot->response``.
11. Acknowledge (see 5.4).

On wake-up the kernel issues ``smp_rmb()``, reads ``slot->response``, applies the
response (section 5.5), and resumes the guest.

If the ring or session is torn down while a vCPU is blocked, the vCPU is woken
and resumes with the default action (CONTINUE).

5.4 Acknowledging an event
--------------------------

There are two acknowledgement paths, with different ownership of ``req_cons``:

**KVM_VMI_ACK_EVENT** (``_IOW(KVMIO, 0xec, struct kvm_vmi_vcpu)``) - the
standard path used by the in-tree selftests. The **kernel** advances
``req_cons`` and wakes the blocked vCPU::

    struct kvm_vmi_vcpu { __u32 vcpu_id; __u32 pad; };

The agent writes ``slot->response`` and then calls ``KVM_VMI_ACK_EVENT``; it
does **not** advance ``req_cons`` itself in this path. Errors: ``-EINVAL``
(unknown ``vcpu_id``, vCPU without VMI state, or ring already torn down).

**ack_fd signalling** - an optional lightweight path. The kernel registers a
wake-up callback on ``ack_fd`` at setup. Signalling ``ack_fd`` wakes the vCPU's
wait queue, but the callback does **not** advance ``req_cons``. The vCPU's
wake condition is ``req_cons > prod``, so a bare ``ack_fd`` signal alone does
not release the vCPU: to use this path the agent must itself advance
``req_cons`` in the mmapped ring (with a preceding ``smp_wmb()``) before
signalling ``ack_fd``.

In short: use ``KVM_VMI_ACK_EVENT`` (kernel owns ``req_cons``), *or* advance
``req_cons`` yourself and signal ``ack_fd`` - not a mix of both.

5.5 Response flags
------------------

The response is a bitmask written to ``slot->response`` before acknowledging.
Flags are combinable; unknown bits are ignored. Which flags are meaningful
depends on the event (and the architecture) - see the per-event sections.

.. list-table::
   :header-rows: 1
   :widths: 34 8 58

   * - Flag
     - Value
     - Description
   * - ``KVM_VMI_RESPONSE_CONTINUE``
     - 0
     - Default. Proceed with normal handling of the intercepted operation. For
       some events a bare CONTINUE is *not* a valid resolution and will
       re-fault - see the per-event notes.
   * - ``KVM_VMI_RESPONSE_DENY``
     - 1 << 0
     - Suppress the intercepted operation. For deferred-write events (CR/MSR)
       the write is simply never applied (the old value was never overwritten)
       and RIP is advanced past the instruction. For CPUID/descriptor/IO the
       instruction is skipped.
   * - ``KVM_VMI_RESPONSE_SET_REGS``
     - 1 << 1
     - Write back the agent's modified general-purpose registers, instruction
       pointer, and flags from ``slot->regs``. Only those are written back;
       control/segment/system registers in the snapshot are **not** (use
       ``KVM_SET_REGS``/``KVM_SET_SREGS``/``KVM_SET_ONE_REG`` for those). On a
       CR/MSR event, SET_REGS alone does *not* suppress the write - combine with
       DENY to both modify registers and suppress.
   * - ``KVM_VMI_RESPONSE_SWITCH_VIEW``
     - 1 << 2
     - Switch this vCPU to ``slot->view_id`` on resume.
   * - ``KVM_VMI_RESPONSE_EMULATE``
     - 1 << 3
     - Emulate the faulting instruction in software (applicable to
       ``MEM_ACCESS``, ``CPUID`` and ``DESC_ACCESS``).
   * - ``KVM_VMI_RESPONSE_REINJECT``
     - 1 << 4
     - Deliver the intercepted exception to the guest instead of consuming it:
       ``#BP`` for breakpoints, ``#DB`` (with the original DR6) for debug.
   * - ``KVM_VMI_RESPONSE_SINGLESTEP``
     - 1 << 5
     - Single-step the next instruction (MTF). One-shot. If
       ``KVM_VMI_EVENT_SINGLESTEP`` is enabled, a singlestep event fires after
       the instruction.
5.6 Register snapshot
---------------------

Every ring event embeds a full ``struct kvm_vmi_regs`` snapshot written by the
kernel. The structure is architecture specific.

For registers not in the snapshot (FPU, vector state, debug registers, ...) the
agent calls standard KVM ioctls on a duplicated vCPU fd while the vCPU is parked
(``vcpu->mutex`` is released).

**x86** ``struct kvm_vmi_regs``:

- GP registers: ``rax``, ``rbx``, ``rcx``, ``rdx``, ``rsi``, ``rdi``, ``rbp``,
  ``rsp``, ``r8``-``r15``, ``rip``, ``rflags``
- Control registers: ``cr0``, ``cr3``, ``cr4``, ``xcr0``
- Segment registers (``base``, ``limit``, ``selector``, ``ar`` each): ``cs``,
  ``ss``, ``ds``, ``es``, ``fs``, ``gs``
- MSRs: ``sysenter_cs/esp/eip``, ``msr_efer``, and on x86_64 ``msr_star``,
  ``msr_lstar``, ``msr_cstar``, ``msr_syscall_mask``, ``msr_kernel_gs_base``,
  ``msr_tsc_aux``

``SET_REGS`` on x86 writes back only the GP registers, ``rip`` and ``rflags``.

5.7 Ring event slot
-------------------

::

    struct kvm_vmi_ring_event {
        /* written by kernel */
        __u32 type;          /* KVM_VMI_EVENT_* (arch dependent, see section 6) */
        __u32 flags;
        __u32 vcpu_id;
        __u32 view_id;       /* view the event fired in; agent may overwrite */
        __u8  insn_len;      /* faulting instruction length (0 if N/A) */
        __u8  _pad[3];
        __u32 response;      /* KVM_VMI_RESPONSE_* (written by agent) */

        /* event-specific payload (written by kernel) */
        union {
            struct kvm_vmi_event_mem_access  mem_access;
            struct kvm_vmi_event_singlestep  singlestep;
            struct kvm_vmi_event_hypercall   hypercall;
            union  kvm_vmi_arch_event_data   arch;   /* arch-specific events */
        };

        struct kvm_vmi_regs regs;    /* written by kernel, may be modified */
    };

``insn_len`` carries the faulting instruction length where applicable. On x86 it
is set for CR/MSR/CPUID/BREAKPOINT/DESC_ACCESS/IO/HYPERCALL and is 0 for
MEM_ACCESS/SINGLESTEP/DEBUG.

6. Event monitoring
===================

6.1 Controlling events
----------------------

**KVM_VMI_CONTROL_EVENT** (``_IOW(KVMIO, 0xed, struct kvm_vmi_control_event)``)

:Type: vmi_fd ioctl
:Parameters: ``struct kvm_vmi_control_event``
:Returns: 0 on success, < 0 on error

::

    struct kvm_vmi_control_event {
        __u32 event;   /* KVM_VMI_EVENT_* */
        __u32 enable;  /* 1 = enable, 0 = disable */
        union kvm_vmi_arch_control_data arch;
    };

Enables or disables monitoring of an event VM-wide. Enabling causes the event to
be intercepted on all vCPUs, but events only fire on vCPUs that have a ring set
up. The ``arch`` union carries event-specific parameters (x86 CR/MSR). ``-EINVAL`` is returned for an out-of-range event id.

``KVM_VMI_EVENT_MEM_ACCESS`` is **not** controlled through this ioctl: it is
implicitly enabled and fires whenever a vCPU on an alternate view touches a
frame whose per-view permissions deny the access (section 7). Configure it with
``KVM_VMI_SET_MEM_ACCESS``.

6.2 Event IDs
-------------

Generic event IDs (0-2) are defined in ``<linux/kvm_vmi_events.h>``.
Architecture-specific event IDs start at ``KVM_VMI_EVENT_ARCH_BASE`` (8) and are
defined in ``<asm/kvm_vmi.h>``.

.. list-table::
   :header-rows: 1
   :widths: 12 28 60

   * - ID
     - Event
     - Notes
   * - 0
     - ``MEM_ACCESS``
     - generic (per-view access violation)
   * - 1
     - ``SINGLESTEP``
     - generic
   * - 8
     - ``CR``
     - control register write
   * - 9
     - ``MSR``
     - MSR write
   * - 10
     - ``CPUID``
     - CPUID instruction
   * - 11
     - ``BREAKPOINT`` (INT3)
     - software breakpoint
   * - 12
     - ``DEBUG``
     - debug exception
   * - 13
     - ``DESC_ACCESS``
     - descriptor-table access
   * - 14
     - ``IO``
     - I/O instruction

6.3 Generic events
------------------

KVM_VMI_EVENT_MEM_ACCESS (0)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:Trigger: a vCPU on an alternate view accesses a frame whose per-view
          permissions deny the access type (EPT violation)
:Data: ``struct kvm_vmi_event_mem_access``
:Enabled by: implicit (no ``CONTROL_EVENT``); fires whenever a ring exists and
             the vCPU is on an alternate view

::

    struct kvm_vmi_event_mem_access {
        __u64 gpa;     /* faulting guest physical address */
        __u32 access;  /* denied access bits: KVM_VMI_ACCESS_R/W/X */
        __u32 pad;
    };

``access`` is a bitmask of the attempted-but-denied access types; x86 may set
several bits at once (the EPT-violation read/write/instruction bits are OR-ed
together), so an agent should test bits rather than compare for equality.

Responses: ``SET_REGS``, ``SWITCH_VIEW``, ``SINGLESTEP``, ``SINGLESTEP_FAST``.
``EMULATE`` emulates the faulting instruction so it completes without relaxing
the view's permissions. A bare ``CONTINUE`` does not by itself resolve the fault
(the access is re-attempted); the agent must widen the permission, emulate, or
step past it (``SINGLESTEP_FAST``) to make progress.

KVM_VMI_EVENT_SINGLESTEP (1)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:Trigger: completion of a single instruction step armed by a prior
          ``SINGLESTEP`` response
:Data: ``struct kvm_vmi_event_singlestep``

::

    struct kvm_vmi_event_singlestep {
        __u64 gpa;   /* guest-physical of the instruction */
    };

A step is armed only by ``KVM_VMI_RESPONSE_SINGLESTEP`` /
``KVM_VMI_RESPONSE_SINGLESTEP_FAST``; there is no single-step ioctl. Delivery of
the event additionally requires ``KVM_VMI_EVENT_SINGLESTEP`` to be enabled via
``CONTROL_EVENT`` - if it is not, the step still occurs but no event is
delivered and the guest resumes. A ``SINGLESTEP_FAST`` step is consumed and its
event suppressed before this gate, so it never delivers a singlestep event.
Single-step is one-shot; respond ``SINGLESTEP`` again to keep stepping.
Responses: ``SET_REGS``, ``SWITCH_VIEW``, ``SINGLESTEP``.

6.4 x86 architecture events
---------------------------

x86 arch event parameters use ``union kvm_vmi_arch_control_data`` /
``union kvm_vmi_arch_event_data`` from ``<asm/kvm_vmi.h>``.

KVM_VMI_EVENT_CR (8)
~~~~~~~~~~~~~~~~~~~~~

:Trigger: guest write to CR0, CR3 or CR4 (before the write is applied)
:Data: ``struct kvm_vmi_event_cr``
:Responses: CONTINUE (allow), DENY (suppress + advance RIP), SET_REGS

::

    struct kvm_vmi_event_cr {
        __u32 index;       /* 0, 3 or 4 */
        __u32 pad;
        __u64 old_value;
        __u64 new_value;
    };

Control parameters (``arch.cr``): ``index`` (``KVM_VMI_CR0`` = 0,
``KVM_VMI_CR3`` = 3, ``KVM_VMI_CR4`` = 4), ``onchangeonly`` (skip writes that do
not change the value), ``bitmask`` (fire only if changed bits intersect the
mask). The ``bitmask`` filter is applied **only when** ``onchangeonly`` is also
set; with ``onchangeonly`` = 0 every write fires and ``bitmask`` is ignored.
Each CR is enabled/disabled independently.

.. note::
   ``KVM_VMI_XCR0`` (index 64) is accepted by ``CONTROL_EVENT`` but produces no
   event: the ``XSETBV`` path has no VMI hook. Do not rely on XCR0 monitoring.

DENY suppresses the write (the old value was never overwritten) and advances
RIP. ``SET_REGS`` *without* DENY writes back GP regs but still lets the original
CR write proceed - combine ``SET_REGS|DENY`` to both modify and suppress.

KVM_VMI_EVENT_MSR (9)
~~~~~~~~~~~~~~~~~~~~~~

:Trigger: guest ``WRMSR`` to a monitored MSR (before the write is applied)
:Data: ``struct kvm_vmi_event_msr``
:Responses: CONTINUE, DENY, SET_REGS

::

    struct kvm_vmi_event_msr {
        __u32 index;
        __u32 pad;
        __u64 old_value;
        __u64 new_value;
    };

Control parameters (``arch.msr``): ``msr`` (index) and ``onchangeonly``. Only
MSRs explicitly monitored generate events; monitoring an MSR enables its write
intercept. DENY/SET_REGS semantics match the CR event (DENY suppresses + skips;
SET_REGS alone still applies the write).

KVM_VMI_EVENT_CPUID (10)
~~~~~~~~~~~~~~~~~~~~~~~~~

:Trigger: guest ``CPUID``
:Data: ``struct kvm_vmi_event_cpuid``
:Responses: EMULATE, DENY, SET_REGS (a bare CONTINUE is invalid - see note)

::

    struct kvm_vmi_event_cpuid {
        __u32 leaf;      /* EAX */
        __u32 subleaf;   /* ECX */
    };

EMULATE runs KVM's normal CPUID and advances RIP. DENY skips the instruction
(CPUID becomes a NOP). SET_REGS lets the agent supply custom EAX/EBX/ECX/EDX via
the register snapshot.

.. note::
   When CPUID monitoring is enabled the kernel fully bypasses its own CPUID
   handling, so a bare ``CONTINUE`` neither advances RIP nor writes a result and
   the instruction re-faults. The agent must respond ``EMULATE``, ``DENY`` or
   ``SET_REGS``.

KVM_VMI_EVENT_BREAKPOINT (11)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:Trigger: guest ``INT3`` (software breakpoint, opcode 0xCC)
:Data: ``struct kvm_vmi_event_breakpoint``
:Responses: REINJECT, SET_REGS, SINGLESTEP, SINGLESTEP_FAST, SWITCH_VIEW

::

    struct kvm_vmi_event_breakpoint {
        __u64 gpa;        /* guest-physical of the INT3 (~0 if unmapped) */
    };

The INT3 length is in ``slot->insn_len``. By default (CONTINUE) the breakpoint
is consumed and the guest never sees ``#BP``; ``REINJECT`` delivers ``#BP``
(vector 3) to the guest. Typical transparent-breakpoint flow: receive the event
in an instrumented view, respond ``SINGLESTEP_FAST`` (+``SWITCH_VIEW`` to a
clean view) to step the original instruction, then auto-return to the
instrumented view.

KVM_VMI_EVENT_DEBUG (12)
~~~~~~~~~~~~~~~~~~~~~~~~~

:Trigger: ``#DB`` debug exception (hardware breakpoint, single-step trap)
:Data: ``struct kvm_vmi_event_debug``
:Responses: REINJECT, DENY, SET_REGS (+ generic SWITCH_VIEW/SINGLESTEP[_FAST])

::

    struct kvm_vmi_event_debug {
        __u64 pending_dbg;   /* DR6-style pending debug bits (exit qual) */
        __u64 gpa;           /* guest-physical of RIP, or ~0 if unmapped */
    };

By default the guest resumes with ``RFLAGS.RF`` set so the instruction does not
immediately re-trigger ``#DB``. ``DENY`` suppresses that (no RF set, no
reinject). ``REINJECT`` delivers ``#DB`` (vector 1) with the original DR6 so the
guest's handler runs.

KVM_VMI_EVENT_DESC_ACCESS (13)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:Trigger: descriptor-table access (``LGDT/SGDT/LIDT/SIDT/LLDT/SLDT/LTR/STR``)
:Data: ``struct kvm_vmi_event_desc_access``
:Responses: EMULATE, DENY, SET_REGS (a bare CONTINUE is invalid - see note)

::

    struct kvm_vmi_event_desc_access {
        __u8 descriptor;   /* KVM_VMI_DESC_GDTR/IDTR/LDTR/TR (0..3) */
        __u8 is_write;     /* 1 = load (LGDT/LIDT/LLDT/LTR), 0 = store */
        __u8 pad[6];
    };

EMULATE runs the instruction; DENY skips it.

.. note::
   Like CPUID, when descriptor monitoring is enabled the kernel bypasses its own
   emulation, so a bare ``CONTINUE`` re-faults; respond ``EMULATE``, ``DENY`` or
   ``SET_REGS``.

KVM_VMI_EVENT_IO (14)
~~~~~~~~~~~~~~~~~~~~~~

:Trigger: guest ``IN``/``OUT``/``INS``/``OUTS``
:Data: ``struct kvm_vmi_event_io``
:Responses: CONTINUE (allow), DENY (skip), SET_REGS

::

    struct kvm_vmi_event_io {
        __u16 port;
        __u8  bytes;    /* 1, 2 or 4 */
        __u8  in;       /* 1 = IN/INS, 0 = OUT/OUTS */
        __u8  string;   /* 1 = INS/OUTS */
        __u8  pad[3];
    };

7. Alternate memory views
=========================

An alternate view is an independent guest-physical address space with its own
per-frame access permissions and frame remapping. A view is a separate EPT root
(with an EPTP value). A view starts empty and is populated lazily from the host
mapping on first access.

View 0 is the default host view and always exists. It cannot be created,
destroyed, switched-from permanently, or have its permissions or frame mappings
modified.

7.1 View management
-------------------

**KVM_VMI_CREATE_VIEW** (``_IOWR(KVMIO, 0xf4, struct kvm_vmi_view)``)

:Type: vmi_fd ioctl
:Parameters: ``struct kvm_vmi_view`` (``view_id`` is OUT)
:Returns: 0 on success, < 0 on error

::

    struct kvm_vmi_view {
        __u32 view_id;         /* OUT on create, IN on destroy */
        __u32 flags;           /* reserved, set to 0 */
        __u8  default_access;  /* default R/W/X for lazily-populated entries */
        __u8  pad[7];
    };

``default_access`` is a combination of ``KVM_VMI_ACCESS_R/W/X`` (and, on x86
with hardware support, ``KVM_VMI_ACCESS_PW``). The kernel assigns a
monotonically increasing ``view_id`` starting at 1; ids are never reused within
a session. Views are allocated dynamically with no fixed limit.

Errors: ``-EINVAL`` (no session, or ``W`` without ``R`` - that combination
cannot be encoded), ``-EOPNOTSUPP`` (``PW`` requested without hardware support),
``-ENOMEM``.

.. note::
   View ids are stable u32 values intended to also serve as EPTP-list indices
   for a future VMFUNC fast-switch path when ``<= 511``. This is a forward
   convention only; nothing in the current code enforces a 511 limit or uses an
   EPTP list.

**KVM_VMI_DESTROY_VIEW** (``_IOW(KVMIO, 0xf5, struct kvm_vmi_view)``)

:Type: vmi_fd ioctl
:Parameters: ``struct kvm_vmi_view`` (``view_id`` IN)
:Returns: 0 on success, < 0 on error

Destroys a view and frees its EPT root. Errors: ``-EINVAL`` (no session,
or ``view_id`` 0), ``-ENOENT`` (unknown view), ``-EBUSY`` (a vCPU is currently
on the view).

**KVM_VMI_SWITCH_VIEW** (``_IOW(KVMIO, 0xf6, struct kvm_vmi_switch_view)``)

:Type: vmi_fd ioctl
:Parameters: ``struct kvm_vmi_switch_view``
:Returns: 0 on success, < 0 on error

::

    struct kvm_vmi_switch_view {
        __u32 view_id;
        __u32 pad;
    };

Switches **all** vCPUs to ``view_id`` (0 = host view). For per-vCPU switching,
use ``KVM_VMI_RESPONSE_SWITCH_VIEW`` in a ring response instead. Errors:
``-EINVAL`` (no session), ``-ENOENT`` (unknown non-zero view).

7.2 Memory access control
-------------------------

**KVM_VMI_SET_MEM_ACCESS** (``_IOW(KVMIO, 0xf8, struct kvm_vmi_mem_access)``)

:Type: vmi_fd ioctl
:Parameters: ``struct kvm_vmi_mem_access``
:Returns: 0 on success, < 0 on error

::

    struct kvm_vmi_mem_access {
        __u32 view_id;
        __u32 nr;
        union {
            /* single-GFN mode (nr <= 1) */
            struct {
                __u64 gfn;
                __u8  access;
                __u8  pad;
                __u16 autostep_mask;   /* must be 0 on x86 */
                __u8  pad2[4];
            };
            /* batch mode (nr > 1) */
            struct {
                __u64 gfns_uaddr;      /* __u64[nr] of GFNs */
                __u64 accesses_uaddr;  /* __u8[nr] of access bytes */
            };
        };
    };

Sets per-frame access permissions in an alternate view. Cannot modify view 0
(``-EINVAL``). Single-GFN mode (``nr`` <= 1) uses the inline ``gfn``/``access``;
batch mode (``nr`` > 1) reads ``nr`` entries from the two user arrays. A clear
permission bit makes the corresponding access fault, delivering a
``KVM_VMI_EVENT_MEM_ACCESS`` event.

Access flags:

.. list-table::
   :header-rows: 1
   :widths: 30 8 62

   * - Flag
     - Value
     - Description
   * - ``KVM_VMI_ACCESS_R``
     - 1 << 0
     - Allow read
   * - ``KVM_VMI_ACCESS_W``
     - 1 << 1
     - Allow write (requires R)
   * - ``KVM_VMI_ACCESS_X``
     - 1 << 2
     - Allow execute

Convenience combinations ``KVM_VMI_ACCESS_RW/RX/WX/RWX`` are also defined.

.. note::
   ``KVM_VMI_ACCESS_DEFAULT`` (0xff) is defined in the uAPI but is **not**
   interpreted specially by the current implementation: it is stored verbatim
   as the access value (and, containing the ``PW`` bit, is rejected with
   ``-EOPNOTSUPP`` unless EPT paging-write hardware is present). There is no
   per-frame "revert to the view default" operation.

``autostep_mask`` (single-GFN mode) must be 0 on x86; a non-zero value returns
``-EOPNOTSUPP`` (x86 has no auto-step support). Batch mode never sets a mask.

Errors: ``-EINVAL`` (no session, view 0, or W-without-R), ``-ENOENT`` (unknown
view), ``-EOPNOTSUPP`` (PW without hardware, or non-zero ``autostep_mask``),
``-EFAULT`` (NULL batch pointers or copy failure), ``-ENOMEM``.

**KVM_VMI_GET_MEM_ACCESS** (``_IOWR(KVMIO, 0xf7, struct kvm_vmi_mem_access)``)

:Type: vmi_fd ioctl
:Parameters: ``struct kvm_vmi_mem_access``
:Returns: 0 on success, < 0 on error

Queries permissions, in single-GFN or batch mode. Unlike SET, view 0 is
accepted and reports ``KVM_VMI_ACCESS_RWX`` for every frame. For a non-zero view
each frame reports its override if set, else the view's ``default_access``.
Errors: ``-EINVAL`` (no session), ``-ENOENT`` (unknown non-zero view),
``-EFAULT`` (NULL batch pointers or copy failure), ``-ENOMEM`` (batch
allocation failure).

7.3 Guest-frame remapping
-------------------------

Remapping replaces a guest frame's backing in one view, enabling transparent
code patching without touching the guest's original memory. The typical shadow
workflow:

1. Allocate a shadow frame::

       struct kvm_vmi_alloc_gfn alloc = {};
       ioctl(vmi_fd, KVM_VMI_ALLOC_GFN, &alloc);   /* alloc.gfn = shadow GFN */

2. mmap the shadow frame and the original frame via ``vmi_fd`` (section 8), copy
   the original content, and patch the shadow (e.g. write ``INT3``).

3. Remap in the alternate view::

       struct kvm_vmi_change_gfn change = {
           .view_id = my_view,
           .old_gfn = original_gfn,
           .new_gfn = alloc.gfn,
       };
       ioctl(vmi_fd, KVM_VMI_CHANGE_GFN, &change);

4. A vCPU on ``my_view`` now sees the patched shadow at ``original_gfn``; other
   views (including view 0) still see the original page.

**KVM_VMI_CHANGE_GFN** (``_IOW(KVMIO, 0xfb, struct kvm_vmi_change_gfn)``)

:Type: vmi_fd ioctl
:Parameters: ``struct kvm_vmi_change_gfn``
:Returns: 0 on success, < 0 on error

::

    struct kvm_vmi_change_gfn {
        __u32 view_id;   /* must not be 0 */
        __u32 pad;
        __u64 old_gfn;   /* frame whose mapping to override */
        __u64 new_gfn;   /* backing frame (shadow or regular) */
    };

Remaps ``old_gfn`` to ``new_gfn``'s backing page in the view. ``new_gfn`` may be
a shadow GFN (``>= KVM_VMI_SHADOW_GFN_BASE``) or a regular guest GFN (aliasing
one guest page onto another). Setting ``new_gfn`` to ``KVM_VMI_INVALID_GFN``
(``~0ULL``) reverts to the host mapping. Errors: ``-EINVAL`` (no session, view
0), ``-ENOENT`` (unknown view, or unallocated shadow target), ``-EFAULT`` (no
memslot / fault-in failure for a regular ``new_gfn``), ``-ENOMEM`` (pinning a
regular ``new_gfn``).

**KVM_VMI_ALLOC_GFN** (``_IOWR(KVMIO, 0xf9, struct kvm_vmi_alloc_gfn)``)

:Type: vmi_fd ioctl
:Parameters: ``struct kvm_vmi_alloc_gfn`` (``gfn`` OUT)
:Returns: 0 on success, < 0 on error

::

    struct kvm_vmi_alloc_gfn {
        __u64 gfn;   /* OUT: allocated shadow GFN */
    };

Allocates a zeroed kernel page and assigns it a shadow GFN from a counter
starting at ``KVM_VMI_SHADOW_GFN_BASE`` (``0xFFFFFE000000``), well above any
realistic guest physical address. The shadow page is accessible via ``vmi_fd``
mmap at offset ``gfn << PAGE_SHIFT``. Errors: ``-EINVAL`` (no session),
``-ENOMEM``.

**KVM_VMI_FREE_GFN** (``_IOW(KVMIO, 0xfa, struct kvm_vmi_free_gfn)``)

:Type: vmi_fd ioctl
:Parameters: ``struct kvm_vmi_free_gfn`` (``gfn`` IN)
:Returns: 0 on success, < 0 on error

::

    struct kvm_vmi_free_gfn {
        __u64 gfn;   /* IN: shadow GFN to free */
    };

Frees a shadow page (and force-unmaps it from any agent mapping). Errors:
``-EINVAL`` (no session, or ``gfn < KVM_VMI_SHADOW_GFN_BASE``), ``-ENOENT``
(not allocated), ``-EBUSY`` (still referenced by a ``CHANGE_GFN`` remap).

8. Guest memory access
======================

Guest physical memory is mapped into the agent by calling ``mmap()`` on the
``vmi_fd`` with the offset equal to the guest physical address::

    /* map 4 KiB at guest physical address 0x1000 */
    void *page = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                      MAP_SHARED, vmi_fd, 0x1000);

The mapping is fault-based: a page is resolved on first access (no pages are
pinned at mmap time). For a normal GFN the kernel resolves the host page through
the VM owner's address space; for an unbacked or invalid GFN the access faults
with ``SIGBUS``. Shadow frames (``>= KVM_VMI_SHADOW_GFN_BASE``) are accessible
through the same mmap at offset ``shadow_gfn << PAGE_SHIFT``, letting the agent
write patched code into them.

The mapping uses ``VM_PFNMAP``, so mapped pages do not count toward the agent's
RSS. ``mmap`` requires an active session (else ``-EINVAL``). Requires
``KVM_CAP_VMI_GUEST_MMAP``.

**KVM_VMI_GET_MEM_INFO** (``_IOR(KVMIO, 0xee, struct kvm_vmi_mem_info)``)

:Type: vmi_fd ioctl
:Parameters: ``struct kvm_vmi_mem_info`` (OUT)
:Returns: 0 on success, < 0 on error

::

    struct kvm_vmi_mem_info {
        __u64 max_gfn;   /* exclusive upper-bound GFN of guest RAM */
        __u64 pad;
    };

Reports the guest RAM extent so the agent can avoid faulting unbacked frames.
``max_gfn`` is the **exclusive** upper bound, computed as the maximum of
``base_gfn + npages`` over all memslots; frames at or above ``max_gfn`` are not
backed by guest RAM. KVM has no memslot-enumeration ioctl, so this is the
agent's way to learn the layout the VMM programmed.

9. vCPU pause
=============

Pause stops vCPU execution so the agent can safely inspect or modify guest
state. It is refcounted per vCPU (an atomic ``pause_count``): a vCPU stays
parked while its count is non-zero, so nested pause/unpause from different parts
of the agent compose correctly. A parked vCPU releases ``vcpu->mutex`` inside
the run loop, so the agent's ``KVM_GET_REGS`` (etc.) on the vCPU fd serializes
naturally on that mutex. Requires ``KVM_CAP_VMI_PAUSE``.

**KVM_VMI_PAUSE_VM** (``_IO(KVMIO, 0xef)``) / **KVM_VMI_UNPAUSE_VM**
(``_IO(KVMIO, 0xf0)``)

:Type: vmi_fd ioctl
:Parameters: none
:Returns: 0

``PAUSE_VM`` increments ``pause_count`` on every vCPU that has VMI state, forces
in-guest vCPUs out synchronously (``KVM_REQ_OUTSIDE_GUEST_MODE``) and wakes
halted/sleeping ones
(``KVM_REQ_UNBLOCK``). It returns immediately without itself taking
``vcpu->mutex``; a subsequent agent vCPU ioctl blocks on that mutex until the
vCPU has parked. ``UNPAUSE_VM`` decrements each ``pause_count`` (never below 0)
and wakes any vCPU reaching 0.

**KVM_VMI_PAUSE_VCPU** (``_IOW(KVMIO, 0xf1, struct kvm_vmi_vcpu)``) /
**KVM_VMI_UNPAUSE_VCPU** (``_IOW(KVMIO, 0xf2, struct kvm_vmi_vcpu)``)

:Type: vmi_fd ioctl
:Parameters: ``struct kvm_vmi_vcpu`` (``vcpu_id``)
:Returns: 0 on success, < 0 on error

Pause/unpause a single vCPU with the same refcount semantics. Errors:
``-EINVAL`` (unknown ``vcpu_id`` or vCPU without VMI state).

10. Event injection
===================

**KVM_VMI_INJECT_EVENT** (``_IOW(KVMIO, 0xf3, struct kvm_vmi_inject_event)``)

:Type: vmi_fd ioctl
:Parameters: ``struct kvm_vmi_inject_event`` (architecture specific)
:Returns: 0 on success, < 0 on error

Injects an event into a guest vCPU. The ioctl resolves the target by
``vcpu_id`` (``-EINVAL`` if unknown or without VMI state). Requires
``KVM_CAP_VMI_INJECT``.

::

    struct kvm_vmi_inject_event {
        __u32 vcpu_id;
        __u8  vector;       /* interrupt/exception vector */
        __u8  type;         /* KVM_VMI_EVENT_TYPE_* (VMCS interruption type) */
        __u8  insn_len;     /* instruction length for SW_INT/SW_EXCEPT */
        __u8  pad;          /* must be 0 */
        __u32 error_code;
        __u32 has_error;
        __u64 cr2;          /* for #PF (vector 14) */
    };

``type`` matches the VMCS VM-entry interruption-type encoding:

.. list-table::
   :header-rows: 1
   :widths: 34 8 58

   * - Type
     - Value
     - Description / constraints
   * - ``KVM_VMI_EVENT_TYPE_EXT_INT``
     - 0
     - External interrupt. Requires ``RFLAGS.IF`` = 1 (else ``-EBUSY``);
       ``insn_len`` must be 0.
   * - ``KVM_VMI_EVENT_TYPE_NMI``
     - 2
     - NMI; ``insn_len`` must be 0.
   * - ``KVM_VMI_EVENT_TYPE_HW_EXCEPT``
     - 3
     - Hardware exception; ``vector`` <= 31; ``insn_len`` must be 0;
       ``has_error`` must match whether the vector takes an error code (DF, TS,
       NP, SS, GP, PF, AC). For ``#PF`` set ``cr2``.
   * - ``KVM_VMI_EVENT_TYPE_SW_INT``
     - 4
     - Software interrupt (``INT n``); ``insn_len`` 1-15.
   * - ``KVM_VMI_EVENT_TYPE_PRIV_SW_INT``
     - 5
     - **Not supported on x86** - returns ``-EOPNOTSUPP``.
   * - ``KVM_VMI_EVENT_TYPE_SW_EXCEPT``
     - 6
     - Software exception; ``vector`` must be 3 (``#BP``) or 4 (``#OF``);
       ``insn_len`` 1-15; ``has_error`` must be 0.

A non-zero ``pad`` or an out-of-range type/vector/insn_len/has_error returns
``-EINVAL``.
