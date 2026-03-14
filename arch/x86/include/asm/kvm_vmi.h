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
struct kvm_vmi_control_event;
struct kvm_vmi_inject_event;

/**
 * struct kvm_arch_vmi - x86-specific VM-level VMI monitoring config
 */
struct kvm_arch_vmi {
};

/**
 * struct kvm_arch_vcpu_vmi - x86-specific per-vCPU VMI state
 */
struct kvm_arch_vcpu_vmi {
};

#endif /* _ASM_X86_KVM_VMI_H */
