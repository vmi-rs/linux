// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM Virtual Machine Introspection (VMI) - arm64-specific code
 *
 * Supplies the arch contract the generic VMI core (virt/kvm/vmi/vmi.c)
 * reaches through plain extern functions. arm64 KVM is monolithic, so
 * the contract is implemented directly here with no kvm_x86_ops-style
 * vtable. Some hooks are no-ops because arm64 differs from x86 (e.g. no
 * SRCU to shed before blocking, no paging-write tracking).
 */

#include <linux/kvm_host.h>
#include <linux/kvm_vmi.h>
#include <linux/bitops.h>
#include <linux/slab.h>

#include <asm/kvm_vmi.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_mmu.h>
#include <asm/esr.h>
#include <asm/insn.h>
#include <asm/cpufeature.h>
#include <asm/virt.h>

#include <trace/events/kvm_vmi.h>

/**
 * kvm_arch_vmi_supported - Report whether VMI works on this host
 *
 * VMI introspects a guest through host-managed stage-2 translation
 * (alternate views, per-GFN permissions, remaps). Under protected KVM
 * the host does not own the guest's stage-2, so introspection is not
 * possible. Any non-protected KVM has a usable stage-2.
 *
 * Return: true if VMI is supported.
 */
bool kvm_arch_vmi_supported(void)
{
	return !is_protected_kvm_enabled();
}

/*
 * arm64 has no analog of x86 EPT paging-write monitoring (A/D-bit
 * write tracking). The generic core uses this to gate KVM_VMI_ACCESS_PW
 * handling; report unsupported.
 */
bool kvm_arch_vmi_has_paging_write(void)
{
	return false;
}

bool kvm_arch_vmi_has_auto_step(void)
{
	return false;
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
 * configuration. Each event commit extends this to clean up its own
 * state (monitored-sysreg set, etc.).
 */
void kvm_arch_vmi_session_reset(struct kvm_vmi *vmi)
{
}

/*
 * Reset arch-specific per-vCPU VMI state during session teardown.
 *
 * Called from the release path (not the vCPU thread), so it must not
 * touch live CPU state; it only clears in-memory flags. The vCPU picks
 * up the change via KVM_REQ_VMI_UPDATE on its next entry.
 */
void kvm_arch_vmi_reset_vcpu_state(struct kvm_vcpu *vcpu)
{
}

/**
 * kvm_arch_vmi_control_event - Handle arch-specific event control
 * @kvm: The VM.
 * @ctrl: Event control parameters.
 *
 * Called from generic kvm_vmi_control_event() for events at
 * KVM_VMI_EVENT_ARCH_BASE or higher. Returns -EOPNOTSUPP for events
 * this function does not handle, so the caller falls through to the
 * generic enabled-bit toggle.
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
 * kvm_arch_vmi_update - Kick all vCPUs to re-sync VMI hardware state
 * @kvm: The VM to update.
 *
 * Requests KVM_REQ_VMI_UPDATE on every vCPU and kicks them so they
 * re-apply VMI trap/stage-2 control (HCR_EL2/MDCR_EL2/VTTBR_EL2) on
 * their next entry. The application itself happens in
 * kvm_vmi_apply_state().
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

void kvm_arch_vmi_set_singlestep(struct kvm_vcpu *vcpu, bool enable)
{
}

/*
 * arm64's run loop holds no per-vCPU SRCU read lock at the VMI delivery
 * point (it takes kvm->srcu only in narrow scopes such as the MMU fault
 * path), so there is nothing to shed before blocking.
 */
void kvm_arch_vmi_block_begin(struct kvm_vcpu *vcpu)
{
}

void kvm_arch_vmi_block_end(struct kvm_vcpu *vcpu)
{
}

void kvm_vmi_apply_state(struct kvm_vcpu *vcpu)
{
}

int kvm_arch_vmi_create_view(struct kvm *kvm, struct kvm_vmi_view_data *view)
{
	return -EOPNOTSUPP;
}

void kvm_arch_vmi_destroy_view(struct kvm *kvm, struct kvm_vmi_view_data *view)
{
}

void kvm_arch_vmi_switch_view(struct kvm_vcpu *vcpu,
			      struct kvm_vmi_view_data *view)
{
}

void kvm_arch_vmi_reset_view(struct kvm_vcpu *vcpu)
{
}

bool kvm_arch_vmi_view_has_root(struct kvm_vmi_view_data *view)
{
	return false;
}

void kvm_arch_vmi_invalidate_gfn(struct kvm *kvm,
				 struct kvm_vmi_view_data *view, gfn_t gfn)
{
}

void kvm_arch_vmi_invalidate_gfn_locked(struct kvm *kvm,
					struct kvm_vmi_view_data *view,
					gfn_t gfn)
{
}

void kvm_arch_vmi_invalidate_gfn_revert(struct kvm *kvm,
					struct kvm_vmi_view_data *view,
					gfn_t gfn)
{
}

void kvm_vmi_capture_regs(struct kvm_vcpu *vcpu, struct kvm_vmi_regs *regs)
{
}

void kvm_vmi_restore_regs(struct kvm_vcpu *vcpu, struct kvm_vmi_regs *regs)
{
}

void kvm_vmi_handle_event_response(struct kvm_vcpu *vcpu, u32 event_type,
				   u32 resp)
{
}

int kvm_vmi_inject_event(struct kvm_vcpu *vcpu,
			 struct kvm_vmi_inject_event *inject)
{
	return -EOPNOTSUPP;
}

void kvm_arch_vmi_restore_singlestep(struct kvm_vcpu *vcpu)
{
}
