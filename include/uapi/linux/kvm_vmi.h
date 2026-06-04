/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * KVM Virtual Machine Introspection (VMI) uAPI
 *
 * Provides userspace interfaces for virtual machine introspection,
 * including event monitoring and alternate memory views.
 *
 * Events are delivered via per-vCPU ring buffers.
 * A vmi_fd (from KVM_CREATE_VMI) serves as the control plane.
 *
 * Generic event IDs occupy range 0 to KVM_VMI_EVENT_ARCH_BASE-1.
 * Arch-specific event IDs start at KVM_VMI_EVENT_ARCH_BASE and
 * are defined in <asm/kvm_vmi.h>.
 */
#ifndef _UAPI_LINUX_KVM_VMI_H
#define _UAPI_LINUX_KVM_VMI_H

#include <linux/types.h>
#include <linux/kvm_vmi_events.h>
#include <asm/kvm_vmi.h>

/*
 * Memory Access Flags
 *
 * Used in kvm_vmi_mem_access.access to specify which access types
 * are permitted for a GFN in a given view.  A cleared bit means
 * that access type will cause a KVM_VMI_EVENT_MEM_ACCESS exit.
 */
#define KVM_VMI_ACCESS_R		(1 << 0)
#define KVM_VMI_ACCESS_W		(1 << 1)
#define KVM_VMI_ACCESS_X		(1 << 2)
#define KVM_VMI_ACCESS_PW		(1 << 3)  /* Allow CPU paging-write (A/D updates) */
#define KVM_VMI_ACCESS_RW		(KVM_VMI_ACCESS_R | KVM_VMI_ACCESS_W)
#define KVM_VMI_ACCESS_RX		(KVM_VMI_ACCESS_R | KVM_VMI_ACCESS_X)
#define KVM_VMI_ACCESS_WX		(KVM_VMI_ACCESS_W | KVM_VMI_ACCESS_X)
#define KVM_VMI_ACCESS_RWX		(KVM_VMI_ACCESS_R | KVM_VMI_ACCESS_W | \
					 KVM_VMI_ACCESS_X)
#define KVM_VMI_ACCESS_DEFAULT		0xff  /* Use view's default access */

/*
 * Special GFN value indicating "revert to host mapping"
 */
#define KVM_VMI_INVALID_GFN		(~(__u64)0)

/*
 * Base GFN for VMI-allocated shadow pages. Shadow GFNs live in a
 * reserved range above guest physical memory and are backed by
 * kernel-allocated pages rather than guest memslots.
 */
#define KVM_VMI_SHADOW_GFN_BASE		(0xFFFFFE000000ULL)

/* Ioctls on vmi_fd (returned by KVM_CREATE_VMI) */
#define KVM_VMI_SETUP_RING        _IOWR(KVMIO, 0xea, struct kvm_vmi_setup_ring)
#define KVM_VMI_TEARDOWN_RING     _IOW(KVMIO,  0xeb, __u32)
#define KVM_VMI_ACK_EVENT         _IOW(KVMIO,  0xec, struct kvm_vmi_vcpu)
#define KVM_VMI_CONTROL_EVENT     _IOW(KVMIO,  0xed, struct kvm_vmi_control_event)
#define KVM_VMI_PAUSE_VM          _IO(KVMIO,   0xee)
#define KVM_VMI_UNPAUSE_VM        _IO(KVMIO,   0xef)
#define KVM_VMI_PAUSE_VCPU        _IOW(KVMIO,  0xf0, struct kvm_vmi_vcpu)
#define KVM_VMI_UNPAUSE_VCPU      _IOW(KVMIO,  0xf1, struct kvm_vmi_vcpu)
#define KVM_VMI_INJECT_EVENT      _IOW(KVMIO,  0xf2, struct kvm_vmi_inject_event)
#define KVM_VMI_CREATE_VIEW       _IOWR(KVMIO, 0xf3, struct kvm_vmi_view)
#define KVM_VMI_DESTROY_VIEW      _IOW(KVMIO,  0xf4, struct kvm_vmi_view)
#define KVM_VMI_SWITCH_VIEW       _IOW(KVMIO,  0xf5, struct kvm_vmi_switch_view)
#define KVM_VMI_GET_MEM_ACCESS    _IOWR(KVMIO, 0xf6, struct kvm_vmi_mem_access)
#define KVM_VMI_SET_MEM_ACCESS    _IOW(KVMIO,  0xf7, struct kvm_vmi_mem_access)
#define KVM_VMI_ALLOC_GFN         _IOWR(KVMIO, 0xf8, struct kvm_vmi_alloc_gfn)
#define KVM_VMI_FREE_GFN          _IOW(KVMIO,  0xf9, struct kvm_vmi_free_gfn)
#define KVM_VMI_CHANGE_GFN        _IOW(KVMIO,  0xfa, struct kvm_vmi_change_gfn)

/* Ring event response flags (bitmask, combinable) */
#define KVM_VMI_RESPONSE_CONTINUE          (0)  /* Default: proceed with normal handling */
#define KVM_VMI_RESPONSE_DENY              (1 << 0)
#define KVM_VMI_RESPONSE_SET_REGS          (1 << 1)
#define KVM_VMI_RESPONSE_SWITCH_VIEW       (1 << 2)
#define KVM_VMI_RESPONSE_EMULATE           (1 << 3)
#define KVM_VMI_RESPONSE_REINJECT          (1 << 4)
#define KVM_VMI_RESPONSE_SINGLESTEP        (1 << 5)
#define KVM_VMI_RESPONSE_SINGLESTEP_FAST   (1 << 6)
#define KVM_VMI_RESPONSE_MASK \
	(KVM_VMI_RESPONSE_DENY | KVM_VMI_RESPONSE_SET_REGS | \
	 KVM_VMI_RESPONSE_SWITCH_VIEW | KVM_VMI_RESPONSE_EMULATE | \
	 KVM_VMI_RESPONSE_REINJECT | KVM_VMI_RESPONSE_SINGLESTEP | \
	 KVM_VMI_RESPONSE_SINGLESTEP_FAST)

/*
 * VMI ioctl structures
 */

/**
 * struct kvm_vmi_setup_ring - Ring setup parameters
 * @vcpu_id: Target vCPU
 * @flags: Reserved, must be 0
 * @event_fd: IN: eventfd for kernel -> agent event notification
 * @ack_fd: IN: eventfd for agent -> kernel response notification
 * @ring_fd: OUT: fd to mmap for the ring page (created by kernel)
 * @pad: Reserved padding
 */
struct kvm_vmi_setup_ring {
	__u32 vcpu_id;
	__u32 flags;
	__s32 event_fd;
	__s32 ack_fd;
	__s32 ring_fd;
	__s32 pad;
};

/**
 * struct kvm_vmi_control_event - VM-wide event monitoring control
 * @event: Event type (KVM_VMI_EVENT_*)
 * @enable: 1 to enable, 0 to disable
 * @arch: Architecture-specific event parameters
 */
struct kvm_vmi_control_event {
	__u32 event;
	__u32 enable;
	union kvm_vmi_arch_control_data arch;
};

/**
 * struct kvm_vmi_vcpu - Generic vCPU identifier for vmi_fd ioctls
 */
struct kvm_vmi_vcpu {
	__u32 vcpu_id;
	__u32 pad;
};

/**
 * struct kvm_vmi_view - Alternate memory view descriptor
 * @view_id: View identifier. OUT on create (assigned by kernel), IN on destroy.
 *           View 0 is always the default (host) view and cannot be created/destroyed.
 * @flags: Reserved, must be zero.
 * @default_access: Default R/W/X permissions for lazily-populated entries.
 *                  Combination of KVM_VMI_ACCESS_R/W/X flags.
 * @pad: Reserved padding, must be zero.
 */
struct kvm_vmi_view {
	__u32 view_id;
	__u32 flags;
	__u8  default_access;
	__u8  pad[7];
};

/**
 * struct kvm_vmi_switch_view - Switch all vCPUs to a view via vmi_fd
 *
 * Switches every vCPU in the VM to the specified view atomically.
 * For per-vCPU view switching, use the KVM_VMI_RESPONSE_SWITCH_VIEW
 * flag in the ring event response.
 */
struct kvm_vmi_switch_view {
	__u32 view_id;
	__u32 pad;
};

/**
 * struct kvm_vmi_mem_access - Memory access permissions for a view
 * @view_id: Target view.
 * @nr: Number of GFNs (0 or 1 for single-GFN, >1 for batch).
 *
 * Single-GFN mode (nr <= 1):
 *   @gfn: The guest frame number.
 *   @access: Combination of KVM_VMI_ACCESS_R/W/X flags.
 *
 * Batch mode (nr > 1):
 *   @gfns_uaddr: Userspace pointer to __u64 array of GFNs.
 *   @accesses_uaddr: Userspace pointer to __u8 array of access flags.
 */
struct kvm_vmi_mem_access {
	__u32 view_id;
	__u32 nr;
	union {
		struct {
			__u64 gfn;
			__u8  access;
			__u8  pad;
			/*
			 * Sub-page auto-step mask (single-GFN mode). Bit i set means
			 * the 4K sub-page at offset i*4K within @gfn's host page is
			 * single-stepped in the kernel on a denied data access instead
			 * of delivering a KVM_VMI_EVENT_MEM_ACCESS. Used on hosts whose
			 * page size exceeds the guest granule (e.g. 16K host / 4K
			 * guest), where one stage-2 leaf fuses several guest pages: it
			 * lets a breakpoint's neighbor pages be handled in-kernel while
			 * the breakpoint's own sub-page still delivers. 0 = deliver all
			 * (default). 16 bits cover up to a 64K host page. Requires arch
			 * auto-step support (KVM_VMI_SET_MEM_ACCESS returns -EOPNOTSUPP
			 * otherwise).
			 */
			__u16 autostep_mask;
			__u8  pad2[4];
		};
		struct {
			__u64 gfns_uaddr;
			__u64 accesses_uaddr;
		};
	};
};

struct kvm_vmi_alloc_gfn {
	__u64 gfn;	/* out: allocated shadow GFN */
};

struct kvm_vmi_free_gfn {
	__u64 gfn;	/* in: shadow GFN to free */
};

/**
 * struct kvm_vmi_change_gfn - Remap a GFN in an alternate view
 * @view_id: Target view (must not be 0).
 * @pad: Reserved padding, must be zero.
 * @old_gfn: The GFN whose mapping to override.
 * @new_gfn: The GFN whose backing page should be used instead.
 *           Set to KVM_VMI_INVALID_GFN to revert to host mapping.
 */
struct kvm_vmi_change_gfn {
	__u32 view_id;
	__u32 pad;
	__u64 old_gfn;
	__u64 new_gfn;
};

/*
 * Ring-based event delivery
 */

/*
 * Generic event data structs (arch-independent)
 */
struct kvm_vmi_event_mem_access {
	__u64 gpa;
	__u32 access;
	__u32 pad;
};

struct kvm_vmi_event_singlestep {
	__u64 gpa;
};

/*
 * KVM_VMI_EVENT_HYPERCALL event data.
 *
 * @imm: the trapped hypercall instruction's immediate (HVC #imm on arm64).
 *
 * Hypercall arguments are not duplicated here: they ride along in the
 * captured GP registers (x0..x7 on arm64; rax/rbx/... on x86).
 * Zero on architectures whose hypercall instruction carries no immediate.
 */
struct kvm_vmi_event_hypercall {
	__u32 imm;
	__u32 pad;
};

/**
 * struct kvm_vmi_ring_header - Ring page header
 * @req_prod: Producer index (kernel increments after writing event)
 * @req_cons: Consumer index (agent increments after reading event)
 * @num_slots: Number of event slots in this ring
 * @pad: Reserved padding
 */
struct kvm_vmi_ring_header {
	__u32 req_prod;
	__u32 req_cons;
	__u32 num_slots;
	__u32 pad;
};

/**
 * struct kvm_vmi_ring_event - Ring event slot
 *
 * Written by kernel (header + event data + regs), response area
 * written by agent before signaling ack_fd.
 *
 * Generic events (mem_access, singlestep) are direct union members.
 * Arch-specific events are grouped under the 'arch' union member.
 */
struct kvm_vmi_ring_event {
	/* Header: written by kernel */
	__u32 type;          /* KVM_VMI_EVENT_* */
	__u32 flags;
	__u32 vcpu_id;
	__u32 view_id;
	__u8  insn_len;      /* VM-exit instruction length (0 = not applicable) */
	__u8  _pad[3];
	__u32 response;      /* KVM_VMI_RESPONSE_* flags (written by agent) */

	/* Event-specific data: written by kernel */
	union {
		struct kvm_vmi_event_mem_access mem_access;
		struct kvm_vmi_event_singlestep singlestep;
		struct kvm_vmi_event_hypercall hypercall;
		union kvm_vmi_arch_event_data arch;
	};

	/* Registers: written by kernel, optionally modified by agent */
	struct kvm_vmi_regs regs;
};

_Static_assert(sizeof(struct kvm_vmi_ring_event) <= 4096,
	       "ring event must fit in a page");

#endif /* _UAPI_LINUX_KVM_VMI_H */
