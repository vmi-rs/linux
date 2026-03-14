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

