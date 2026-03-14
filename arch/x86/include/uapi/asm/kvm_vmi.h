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

#define KVM_VMI_NUM_EVENTS		KVM_VMI_ARCH_EVENT(0)

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

/**
 * union kvm_vmi_arch_event_data - x86-specific event data in ring events
 */
union kvm_vmi_arch_event_data {
};

#endif /* _UAPI_ASM_X86_KVM_VMI_H */
