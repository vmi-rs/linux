// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM Virtual Machine Introspection (VMI) - x86-specific code
 *
 * Contains x86/VMX-specific event hooks and arch integration.
 */

#include <linux/kvm_host.h>
#include <linux/kvm_vmi.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <asm/kvm_host.h>
#include <asm/vmx.h>
#include <asm/msr-index.h>
#include "kvm_cache_regs.h"
#include "mmu.h"
#include "mmu/mmu_internal.h"

#include <trace/events/kvm_vmi.h>


bool kvm_arch_vmi_supported(void)
{
	return kvm_x86_call(vmi_has_cap)();
}

void kvm_arch_vmi_session_init(struct kvm_vmi *vmi)
{
}

void kvm_arch_vmi_session_cleanup(struct kvm_vmi *vmi)
{
}

/**
 * kvm_arch_vmi_session_reset - Reset arch-specific session state
 * @vmi: The VMI session being reset.
 *
 * Called from kvm_vmi_release() to clear arch-specific monitoring
 * configuration. Each event commit extends this function to clean
 * up its own state (CR monitor array, MSR xarray, etc.).
 */
void kvm_arch_vmi_session_reset(struct kvm_vmi *vmi)
{
}

/*
 * Reset arch-specific per-vCPU VMI state during session teardown.
 *
 * Called from the release path (not the vCPU thread), so this must NOT
 * touch VMCS state directly. Only clears in-memory flags; the vCPU
 * thread will pick up the changes via KVM_REQ_VMI_UPDATE on its
 * next entry (if it runs again).
 */
void kvm_arch_vmi_reset_vcpu_state(struct kvm_vcpu *vcpu)
{
}

/**
 * kvm_arch_vmi_control_event - Handle arch-specific event control
 * @kvm: The VM.
 * @ctrl: Event control parameters.
 *
 * Called from generic kvm_vmi_control_event() for events with
 * KVM_VMI_EVENT_ARCH_BASE or higher IDs. Returns -EOPNOTSUPP
 * for events this function doesn't handle, causing the caller
 * to fall through to generic bit-toggle handling.
 *
 * Return: 0 on success, -EOPNOTSUPP if not handled, negative errno on error.
 */
int kvm_arch_vmi_control_event(struct kvm *kvm,
			       struct kvm_vmi_control_event *ctrl)
{
	switch (ctrl->event) {
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * kvm_arch_vmi_update - Kick all vCPUs to sync VMI state into VMCS
 * @kvm: The VM to update.
 *
 * Makes a KVM_REQ_VMI_UPDATE request on all vCPUs and kicks them
 * so they pick up changes to event monitoring config on next entry.
 */
void kvm_arch_vmi_update(struct kvm *kvm)
{
	unsigned long i;
	struct kvm_vcpu *vcpu;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		kvm_make_request(KVM_REQ_VMI_UPDATE, vcpu);
		kvm_vcpu_kick(vcpu);
	}
}
