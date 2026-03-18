/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * KVM VMI - x86-specific uAPI types
 *
 * Contains register definitions, x86 event IDs, event data structs,
 * and injection types that are specific to the x86 architecture.
 */
#ifndef _UAPI_ASM_X86_KVM_VMI_H
#define _UAPI_ASM_X86_KVM_VMI_H

#include <linux/types.h>
#include <linux/kvm_vmi_events.h>

/*
 * x86 VMI Event Types
 */
#define KVM_VMI_EVENT_CR		KVM_VMI_ARCH_EVENT(0)  /* Control register write */
#define KVM_VMI_EVENT_MSR		KVM_VMI_ARCH_EVENT(1)  /* MSR write */
#define KVM_VMI_EVENT_CPUID		KVM_VMI_ARCH_EVENT(2)  /* CPUID instruction */
#define KVM_VMI_EVENT_BREAKPOINT	KVM_VMI_ARCH_EVENT(3)  /* INT3 software breakpoint */
#define KVM_VMI_EVENT_DEBUG		KVM_VMI_ARCH_EVENT(4)  /* Debug exception (DR access) */
#define KVM_VMI_EVENT_DESC_ACCESS	KVM_VMI_ARCH_EVENT(5)  /* Descriptor table register access */
#define KVM_VMI_NUM_EVENTS		KVM_VMI_ARCH_EVENT(6)

/*
 * x86 CR Indices (for kvm_vmi_control_event.cr.index)
 */
#define KVM_VMI_CR0			0
#define KVM_VMI_CR3			3
#define KVM_VMI_CR4			4
#define KVM_VMI_XCR0			64

/*
 * x86 Descriptor Types (for KVM_VMI_EVENT_DESC_ACCESS)
 */
#define KVM_VMI_DESC_GDTR		0
#define KVM_VMI_DESC_IDTR		1
#define KVM_VMI_DESC_LDTR		2
#define KVM_VMI_DESC_TR			3

/*
 * Event injection types (match VMCS VM-entry interruption type, bits 10:8)
 */
#define KVM_VMI_EVENT_TYPE_EXT_INT     0
#define KVM_VMI_EVENT_TYPE_NMI         2
#define KVM_VMI_EVENT_TYPE_HW_EXCEPT   3
#define KVM_VMI_EVENT_TYPE_SW_INT      4
#define KVM_VMI_EVENT_TYPE_PRIV_SW_INT 5
#define KVM_VMI_EVENT_TYPE_SW_EXCEPT   6

/**
 * struct kvm_vmi_inject_event - Inject exception/interrupt/NMI
 * @vcpu_id: Target vCPU
 * @vector: Interrupt/exception vector (0-255)
 * @type: KVM_VMI_EVENT_TYPE_* (matches VMCS interruption type encoding)
 * @insn_len: Instruction length (1-15) for SW_INT/SW_EXCEPT; must be 0 otherwise
 * @pad: Must be 0
 * @error_code: Exception error code (if has_error is set)
 * @has_error: Whether error_code is valid
 * @cr2: CR2 value for #PF (vector 14)
 */
struct kvm_vmi_inject_event {
	__u32 vcpu_id;
	__u8  vector;
	__u8  type;
	__u8  insn_len;
	__u8  pad;
	__u32 error_code;
	__u32 has_error;
	__u64 cr2;
};

/**
 * struct kvm_vmi_regs - x86 register snapshot embedded in ring events
 *
 * Contains the most commonly needed registers for VMI. For exotic
 * registers (FPU, XSAVE, debug regs), the agent can call standard
 * KVM ioctls (KVM_GET_FPU, etc.) since vcpu->mutex is released.
 */
struct kvm_vmi_regs {
	/* GP registers */
	__u64 rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp;
	__u64 r8, r9, r10, r11, r12, r13, r14, r15;
	__u64 rip, rflags;

	/* Control registers */
	__u64 cr0, cr3, cr4, xcr0;

	/* Segment registers (6 segments x 16 bytes = 96 bytes) */
	struct {
		__u64 base;
		__u32 limit;
		__u16 selector;
		__u16 ar;
	} cs, ss, ds, es, fs, gs;

	/* Key MSRs */
	__u64 sysenter_cs, sysenter_esp, sysenter_eip;
	__u64 msr_efer;
	__u64 msr_star, msr_lstar, msr_cstar, msr_syscall_mask;
	__u64 msr_kernel_gs_base;
	__u64 msr_tsc_aux;
};

/*
 * x86 event data structs (sub-unions of kvm_vmi_arch_event_data)
 */
struct kvm_vmi_event_cr {
	__u32 index;
	__u32 pad;
	__u64 old_value;
	__u64 new_value;
};

struct kvm_vmi_event_msr {
	__u32 index;
	__u32 pad;
	__u64 old_value;
	__u64 new_value;
};

struct kvm_vmi_event_cpuid {
	__u32 leaf;
	__u32 subleaf;
};

struct kvm_vmi_event_breakpoint {
	__u64 gpa;
};

struct kvm_vmi_event_debug {
	__u64 pending_dbg;
};

struct kvm_vmi_event_desc_access {
	__u8 descriptor;
	__u8 is_write;
	__u8 pad[6];
};

/**
 * union kvm_vmi_arch_control_data - x86-specific control_event parameters
 * @cr: CR event parameters
 * @msr: MSR event parameters
 */
union kvm_vmi_arch_control_data {
	struct {
		__u8  index;
		__u8  onchangeonly;
		__u8  pad[6];
		__u64 bitmask;
	} cr;
	struct {
		__u32 msr;
		__u8  onchangeonly;
		__u8  pad[3];
	} msr;
};

/**
 * union kvm_vmi_arch_event_data - x86-specific event data in ring events
 */
union kvm_vmi_arch_event_data {
	struct kvm_vmi_event_cr cr;
	struct kvm_vmi_event_msr msr;
	struct kvm_vmi_event_cpuid cpuid;
	struct kvm_vmi_event_breakpoint breakpoint;
	struct kvm_vmi_event_debug debug;
	struct kvm_vmi_event_desc_access desc_access;
};

#endif /* _UAPI_ASM_X86_KVM_VMI_H */
