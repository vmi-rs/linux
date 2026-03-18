/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_KVM_VMI_H
#define _ASM_X86_KVM_VMI_H

#include <linux/types.h>
#include <linux/xarray.h>
#include <linux/kvm_types.h>
#include <uapi/asm/kvm_vmi.h>

struct kvm;
struct kvm_vcpu;
struct kvm_mmu_page;
struct kvm_page_fault;
struct kvm_vmi_view_data;
struct kvm_vmi_control_event;
struct kvm_vmi_inject_event;

/**
 * struct kvm_arch_vmi_view - x86-specific alternate view data
 * @tdp_root: TDP MMU root page (kvm_mmu_page) for this view's EPT.
 * @eptp: Full 64-bit EPTP value (memory type + page walk len + AD + root_hpa).
 *        Stored complete for VMFUNC-readiness.
 */
struct kvm_arch_vmi_view {
	struct kvm_mmu_page *tdp_root;
	u64 eptp;
};

/* cr_monitor[] array indices */
#define KVM_VMI_CR_IDX_CR0	0
#define KVM_VMI_CR_IDX_CR3	1
#define KVM_VMI_CR_IDX_CR4	2
#define KVM_VMI_CR_IDX_XCR0	3
#define KVM_VMI_NR_CR_MONITORS	4

/**
 * struct kvm_arch_vmi - x86-specific VM-level VMI monitoring config
 * @cr_monitor: Per-CR monitoring configuration (VM-wide).
 */
struct kvm_arch_vmi {
	struct {
		bool enabled;
		u8 onchangeonly;
		u64 bitmask;
	} cr_monitor[KVM_VMI_NR_CR_MONITORS];
};

/**
 * struct kvm_arch_vcpu_vmi - x86-specific per-vCPU VMI state
 * @emul_gpa: Faulting GPA saved for ACTION_EMULATE.
 * @cr_event_type: Last CR event type for response handling.
 * @cr_event_cr_num: Actual CR number (0/3/4) for DENY.
 * @cr_event_old_val: Old CR value saved for DENY.
 * @cr_event_new_val: New CR value saved for CONTINUE.
 */
struct kvm_arch_vcpu_vmi {
	gpa_t emul_gpa;
	u32 cr_event_type;
	int cr_event_cr_num;
	u64 cr_event_old_val;
	u64 cr_event_new_val;
};

#ifdef CONFIG_KVM_VMI

/*
 * Map uAPI CR number to cr_monitor[] array index.
 * Returns -EINVAL for invalid/unsupported CR numbers.
 */
static inline int vmi_cr_index(u8 cr)
{
	switch (cr) {
	case KVM_VMI_CR0:	return KVM_VMI_CR_IDX_CR0;
	case KVM_VMI_CR3:	return KVM_VMI_CR_IDX_CR3;
	case KVM_VMI_CR4:	return KVM_VMI_CR_IDX_CR4;
	case KVM_VMI_XCR0:	return KVM_VMI_CR_IDX_XCR0;
	default:		return -EINVAL;
	}
}

/* VMCS intercept queries (called from vmx.c to build VMCS state) */
bool kvm_vmi_cr3_intercept(struct kvm *kvm);

/* Event handlers - VM-exit intercepts (arch/x86/kvm/vmi.c) */
int kvm_vmi_cr_write(struct kvm_vcpu *vcpu, int cr_num, u64 old_val,
		     u64 new_val);

/* Memory access (TDP MMU integration) */
int kvm_vmi_check_mem_access(struct kvm_vcpu *vcpu, gpa_t gpa,
			     unsigned long exit_qual);
void kvm_vmi_setup_page_fault(struct kvm_vcpu *vcpu,
			      struct kvm_page_fault *fault);

#else /* !CONFIG_KVM_VMI */

static inline bool kvm_vmi_cr3_intercept(struct kvm *kvm) { return false; }

#endif /* CONFIG_KVM_VMI */

#endif /* _ASM_X86_KVM_VMI_H */
