/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * KVM Virtual Machine Introspection - arm64 internal header
 */
#ifndef __ARM64_KVM_VMI_H
#define __ARM64_KVM_VMI_H

#include <linux/types.h>
#include <linux/kvm_types.h>
#include <uapi/asm/kvm_vmi.h>

struct kvm;
struct kvm_vcpu;
struct kvm_vmi_view_data;

/**
 * struct kvm_arch_vmi_view - arm64-specific alternate view data
 *
 * A view is backed by its own stage-2 translation (a private
 * struct kvm_s2_mmu with a per-view VMID). Populated in the alternate
 * memory views commit; empty until then.
 */
struct kvm_arch_vmi_view {
};

/**
 * struct kvm_arch_vmi - arm64-specific VM-level VMI monitoring config
 *
 * Holds which system registers are monitored and related trap state.
 * Populated by the system-register monitoring commit; empty until then.
 */
struct kvm_arch_vmi {
};

/**
 * struct kvm_arch_vcpu_vmi - arm64-specific per-vCPU VMI state
 *
 * Saved single-step state and pending-event scratch. Populated by the
 * single-step / breakpoint commits; empty until then.
 */
struct kvm_arch_vcpu_vmi {
};

#ifdef CONFIG_KVM_VMI

/*
 * Re-apply VMI hardware state (HCR_EL2/MDCR_EL2/VTTBR_EL2 trap and
 * stage-2 control) on a vCPU. Driven by KVM_REQ_VMI_UPDATE from the run
 * loop. A no-op until trap/view features land; the single sync point
 * later commits extend.
 */
void kvm_vmi_apply_state(struct kvm_vcpu *vcpu);
int kvm_vmi_hypercall(struct kvm_vcpu *vcpu);

#else /* !CONFIG_KVM_VMI */

static inline void kvm_vmi_apply_state(struct kvm_vcpu *vcpu) {}
static inline int kvm_vmi_hypercall(struct kvm_vcpu *vcpu) { return 0; }

#endif /* CONFIG_KVM_VMI */

#endif /* __ARM64_KVM_VMI_H */
