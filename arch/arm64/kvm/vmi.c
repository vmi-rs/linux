// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM Virtual Machine Introspection (VMI) - arm64-specific code
 *
 * Implements the arch contract the generic VMI core
 * (virt/kvm/vmi/vmi.c) reaches through plain extern functions. arm64
 * KVM is monolithic, so the contract is implemented directly here with
 * no kvm_x86_ops-style vtable.
 *
 * This commit stands up session lifecycle with a no-op backend: the
 * functions the create/destroy path needs are real, and the remainder
 * (register capture, views, memory access, single-step, injection) are
 * compiling stubs filled in by later commits.
 */

#include <linux/kvm_host.h>
#include <linux/kvm_vmi.h>
#include <linux/bitops.h>
#include <linux/slab.h>

#include <asm/kvm_vmi.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_mmu.h>
#include <asm/esr.h>
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
	struct kvm_vcpu_vmi *vcpu_vmi = vcpu->vmi;
	struct kvm_s2_mmu *mmu = &vcpu->kvm->arch.mmu;

	/*
	 * Materialize the active memory view into the hardware stage-2. This
	 * is the authoritative sync point, driven by KVM_REQ_VMI_UPDATE: the
	 * VM-wide KVM_VMI_SWITCH_VIEW ioctl only updates the generic
	 * current_view and kicks, so we derive the target mmu from current_view
	 * here (mirroring x86's apply, which reads current_view to program the
	 * EPTP). arm64 loads stage-2 only at vcpu_load, not per guest entry, so
	 * we must reprogram VTTBR_EL2/VTCR_EL2 now, before the next entry.
	 * Update the view's VMID first (kvm_get_vttbr reads mmu->vmid.id);
	 * distinct per-view VMIDs mean no TLB flush is needed on switch.
	 */
	if (vcpu_vmi && vcpu_vmi->current_view_id != 0) {
		struct kvm_vmi_view_data *view = READ_ONCE(vcpu_vmi->current_view);

		if (view && view->arch.mmu)
			mmu = view->arch.mmu;
	}

	vcpu->arch.hw_mmu = mmu;
	kvm_arm_vmid_update(&mmu->vmid);
	__load_stage2(mmu, mmu->arch);
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

void kvm_arch_vmi_set_singlestep(struct kvm_vcpu *vcpu, bool enable)
{
}

int kvm_arch_vmi_create_view(struct kvm *kvm, struct kvm_vmi_view_data *view)
{
	int ret;

	view->arch.mmu = kzalloc(sizeof(*view->arch.mmu), GFP_KERNEL_ACCOUNT);
	if (!view->arch.mmu)
		return -ENOMEM;

	ret = kvm_init_stage2_mmu(kvm, view->arch.mmu, kvm_get_pa_bits(kvm));
	if (ret) {
		kfree(view->arch.mmu);
		view->arch.mmu = NULL;
	}

	return ret;
}

void kvm_arch_vmi_destroy_view(struct kvm *kvm, struct kvm_vmi_view_data *view)
{
	kvm_free_stage2_pgd(view->arch.mmu);
	kfree(view->arch.mmu);
	view->arch.mmu = NULL;
}

void kvm_arch_vmi_switch_view(struct kvm_vcpu *vcpu,
			      struct kvm_vmi_view_data *view)
{
	/* view == NULL means the host view (view 0). */
	vcpu->arch.hw_mmu = view ? view->arch.mmu : &vcpu->kvm->arch.mmu;
	kvm_make_request(KVM_REQ_VMI_UPDATE, vcpu);
}

void kvm_arch_vmi_reset_view(struct kvm_vcpu *vcpu)
{
	vcpu->arch.hw_mmu = &vcpu->kvm->arch.mmu;
	kvm_make_request(KVM_REQ_VMI_UPDATE, vcpu);
}

bool kvm_arch_vmi_view_has_root(struct kvm_vmi_view_data *view)
{
	return view->arch.mmu && view->arch.mmu->pgt;
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

/*
 * kvm_vmi_event_enabled - true if @event_type can be delivered on @vcpu.
 *
 * Requires session VMI state, the event enabled in the session bitmap,
 * and a ring set up on this vCPU. Mirrors the x86 helper; all fields are
 * generic.
 */
static bool kvm_vmi_event_enabled(struct kvm_vcpu *vcpu, u32 event_type)
{
	struct kvm_vmi *vmi = kvm_vmi_get(vcpu->kvm);

	return vmi && (vmi->enabled_events & BIT_ULL(event_type)) &&
	       vcpu->vmi && vcpu->vmi->ring;
}

/**
 * kvm_vmi_hypercall - Deliver a HYPERCALL event for a trapped guest HVC.
 * @vcpu: The vCPU that executed HVC.
 *
 * Captures the register snapshot (x0..x7 carry the SMCCC function id and
 * arguments) plus the HVC immediate, delivers via the ring, and blocks
 * until the agent acks. Uses the deferred pattern: return 0 so the caller
 * runs the normal SMCCC dispatch, unless the agent responded DENY or
 * SET_REGS, in which case return 1 so the caller skips dispatch.
 *
 * The HVC exception return address is already past the instruction, so no
 * PC advance is needed on any response.
 *
 * Return: 1 if the caller should skip SMCCC dispatch, 0 otherwise.
 */
int kvm_vmi_hypercall(struct kvm_vcpu *vcpu)
{
	struct kvm_vmi_ring_event ring_event = {};
	int ret;

	if (!kvm_vmi_event_enabled(vcpu, KVM_VMI_EVENT_HYPERCALL))
		return 0;

	ring_event.type = KVM_VMI_EVENT_HYPERCALL;
	ring_event.vcpu_id = vcpu->vcpu_id;
	ring_event.insn_len = 4;	/* HVC is a 4-byte instruction */
	ring_event.hypercall.imm = kvm_vcpu_hvc_get_imm(vcpu);

	trace_kvm_vmi_event_deliver(vcpu->vcpu_id, KVM_VMI_EVENT_HYPERCALL, 0);
	ret = kvm_vmi_deliver_via_ring(vcpu, &ring_event);

	return (ret > 0 && (ret & (KVM_VMI_RESPONSE_DENY |
				   KVM_VMI_RESPONSE_SET_REGS))) ? 1 : 0;
}

/**
 * kvm_vmi_capture_regs - Copy vCPU register state into a ring event
 * @vcpu: The vCPU whose registers to capture.
 * @regs: Destination register snapshot in the ring event.
 *
 * Provides the agent with a full register capture without needing vCPU
 * ioctls (which require the vcpu mutex held by the blocked vCPU). System
 * registers are read with vcpu_read_sys_reg() rather than the raw
 * __vcpu_sys_reg()/ctxt_sys_reg() because under VHE/NV they may be live
 * on-CPU or VNCR-backed.
 */
void kvm_vmi_capture_regs(struct kvm_vcpu *vcpu, struct kvm_vmi_regs *regs)
{
	int i;

	/* GP registers, stack, PC, processor state */
	for (i = 0; i < 31; i++)
		regs->regs[i] = vcpu_gp_regs(vcpu)->regs[i];
	regs->sp_el0 = vcpu_gp_regs(vcpu)->sp;
	regs->pc = *vcpu_pc(vcpu);
	regs->pstate = *vcpu_cpsr(vcpu);

	/*
	 * System registers - vcpu_read_sys_reg(), not the raw
	 * __vcpu_sys_reg()/ctxt_sys_reg(): under VHE/NV these may be live
	 * on-CPU or VNCR-backed, and the raw accessor would read stale memory.
	 */
	regs->sp_el1        = vcpu_read_sys_reg(vcpu, SP_EL1);
	regs->ttbr0_el1     = vcpu_read_sys_reg(vcpu, TTBR0_EL1);
	regs->ttbr1_el1     = vcpu_read_sys_reg(vcpu, TTBR1_EL1);
	regs->tcr_el1       = vcpu_read_sys_reg(vcpu, TCR_EL1);
	regs->sctlr_el1     = vcpu_read_sys_reg(vcpu, SCTLR_EL1);
	regs->mair_el1      = vcpu_read_sys_reg(vcpu, MAIR_EL1);
	regs->vbar_el1      = vcpu_read_sys_reg(vcpu, VBAR_EL1);
	regs->contextidr_el1 = vcpu_read_sys_reg(vcpu, CONTEXTIDR_EL1);
	regs->elr_el1       = vcpu_read_sys_reg(vcpu, ELR_EL1);
	regs->spsr_el1      = vcpu_read_sys_reg(vcpu, SPSR_EL1);
	regs->esr_el1       = vcpu_read_sys_reg(vcpu, ESR_EL1);
	regs->far_el1       = vcpu_read_sys_reg(vcpu, FAR_EL1);
	regs->tpidr_el0     = vcpu_read_sys_reg(vcpu, TPIDR_EL0);
	regs->tpidr_el1     = vcpu_read_sys_reg(vcpu, TPIDR_EL1);
	regs->tpidrro_el0   = vcpu_read_sys_reg(vcpu, TPIDRRO_EL0);
}

/**
 * kvm_vmi_restore_regs - Copy registers from a ring event back to the vCPU
 * @vcpu: The vCPU whose registers to update.
 * @regs: Source register snapshot from the ring event.
 *
 * Only general-purpose registers, SP_EL0, PC, and PSTATE are restored.
 * System registers (translation, exception, thread regs) are deliberately
 * not written back here: modifying them without validation could crash the
 * host. The agent uses KVM_SET_ONE_REG for those if needed.
 */
void kvm_vmi_restore_regs(struct kvm_vcpu *vcpu, struct kvm_vmi_regs *regs)
{
	int i;

	for (i = 0; i < 31; i++)
		vcpu_gp_regs(vcpu)->regs[i] = regs->regs[i];
	vcpu_gp_regs(vcpu)->sp = regs->sp_el0;
	*vcpu_pc(vcpu) = regs->pc;
	*vcpu_cpsr(vcpu) = regs->pstate;
}

void kvm_vmi_handle_event_response(struct kvm_vcpu *vcpu, u32 event_type,
				   u32 resp)
{
}

/* kvm_inject_* return 1 when an exception was pended; normalize to 0. */
static int vmi_inject_normalize(int r)
{
	return r < 0 ? r : 0;
}

/* Accept only fault FSCs a guest abort handler can sensibly process. */
static bool vmi_inject_fsc_ok(u8 fsc)
{
	fsc &= ESR_ELx_FSC;

	return esr_fsc_is_translation_fault(fsc) ||
	       esr_fsc_is_permission_fault(fsc) ||
	       esr_fsc_is_access_flag_fault(fsc) ||
	       fsc == ESR_ELx_FSC_EXTABT ||
	       esr_fsc_is_sea_ttw(fsc);
}

int kvm_vmi_inject_event(struct kvm_vcpu *vcpu,
			 struct kvm_vmi_inject_event *inject)
{
	if (inject->pad[0] || inject->pad[1] || inject->pad[2] || inject->pad[3])
		return -EINVAL;

	switch (inject->type) {
	case KVM_VMI_INJECT_SERROR:
		/* SError carries no abort fields. */
		if (inject->iabt || inject->fsc || inject->write || inject->addr)
			return -EINVAL;
		if (inject->has_esr) {
			/* Mirror __kvm_arm_vcpu_set_events RAS gating. */
			if (!cpus_have_final_cap(ARM64_HAS_RAS_EXTN))
				return -EINVAL;
			if (inject->esr & ~ESR_ELx_ISS_MASK)
				return -EINVAL;
			return vmi_inject_normalize(
				kvm_inject_serror_esr(vcpu, inject->esr));
		}
		return vmi_inject_normalize(kvm_inject_serror(vcpu));

	case KVM_VMI_INJECT_ABORT:
		if (inject->has_esr || inject->esr)
			return -EINVAL;
		if (inject->iabt && inject->write)	/* WnR is data-abort only */
			return -EINVAL;
		if (!vmi_inject_fsc_ok(inject->fsc))
			return -EINVAL;
		return vmi_inject_normalize(
			kvm_inject_dabt_with_fsc(vcpu, inject->iabt,
						 inject->addr, inject->fsc,
						 inject->write));
	default:
		return -EINVAL;
	}
}
