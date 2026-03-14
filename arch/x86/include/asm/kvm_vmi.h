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

/**
 * struct kvm_arch_vmi - x86-specific VM-level VMI monitoring config
 */
struct kvm_arch_vmi {
};

/**
 * struct kvm_arch_vcpu_vmi - x86-specific per-vCPU VMI state
 * @emul_gpa: Faulting GPA saved for ACTION_EMULATE.
 */
struct kvm_arch_vcpu_vmi {
	gpa_t emul_gpa;
};

#ifdef CONFIG_KVM_VMI

/* Memory access (TDP MMU integration) */
int kvm_vmi_check_mem_access(struct kvm_vcpu *vcpu, gpa_t gpa,
			     unsigned long exit_qual);
void kvm_vmi_setup_page_fault(struct kvm_vcpu *vcpu,
			      struct kvm_page_fault *fault);

#endif /* CONFIG_KVM_VMI */

#endif /* _ASM_X86_KVM_VMI_H */
