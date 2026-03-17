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

