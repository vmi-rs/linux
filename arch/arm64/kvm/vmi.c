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
	memset(vmi->arch.sysreg_monitor, 0, sizeof(vmi->arch.sysreg_monitor));
	vmi->arch.sysreg_monitor_count = 0;
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
	case KVM_VMI_EVENT_SYSREG: {
		struct kvm_vmi *vmi = kvm_vmi_get(kvm);
		__u8 reg = ctrl->arch.sysreg.reg;

		if (reg >= KVM_VMI_NR_SYSREG_MONITORS)
			return -EINVAL;

		if (ctrl->enable) {
			if (!vmi->arch.sysreg_monitor[reg].enabled)
				vmi->arch.sysreg_monitor_count++;
			vmi->arch.sysreg_monitor[reg].enabled = true;
			vmi->arch.sysreg_monitor[reg].onchangeonly =
				ctrl->arch.sysreg.onchangeonly;
			vmi->arch.sysreg_monitor[reg].bitmask =
				ctrl->arch.sysreg.bitmask;
			vmi->enabled_events |= BIT_ULL(KVM_VMI_EVENT_SYSREG);
		} else {
			if (vmi->arch.sysreg_monitor[reg].enabled)
				vmi->arch.sysreg_monitor_count--;
			vmi->arch.sysreg_monitor[reg].enabled = false;
			vmi->arch.sysreg_monitor[reg].onchangeonly = 0;
			vmi->arch.sysreg_monitor[reg].bitmask = 0;
			if (vmi->arch.sysreg_monitor_count == 0)
				vmi->enabled_events &=
					~BIT_ULL(KVM_VMI_EVENT_SYSREG);
		}

		kvm_arch_vmi_update(kvm);
		return 0;
	}
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
	struct kvm_vcpu_vmi *vcpu_vmi = vcpu->vmi;
	struct kvm_s2_mmu *mmu = &vcpu->kvm->arch.mmu;

	/*
	 * Materialize the active memory view into the hardware stage-2, the
	 * authoritative sync point driven by KVM_REQ_VMI_UPDATE. The VM-wide
	 * KVM_VMI_SWITCH_VIEW ioctl only updates the generic current_view and
	 * kicks, so derive the target mmu from current_view here (as x86's
	 * apply reads current_view to program the EPTP). arm64 loads stage-2
	 * only at vcpu_load, not per guest entry, so reprogram
	 * VTTBR_EL2/VTCR_EL2 now. Update the view's VMID first (kvm_get_vttbr
	 * reads mmu->vmid.id); distinct per-view VMIDs avoid a switch TLB
	 * flush.
	 *
	 * Hold the per-vCPU view_lock: a VM-wide switch takes the same lock to
	 * drop this view's vcpu_count and NULL current_view, so holding it
	 * keeps the current_view read and __load_stage2 atomic against that
	 * switch.
	 * Otherwise kvm_vmi_destroy_view() could kfree the view in between and
	 * we would load a freed stage-2 root (random guest reset). Under the
	 * lock we either load the view while vcpu_count is still raised (a
	 * concurrent destroy returns -EBUSY) or observe current_view_id == 0.
	 */
	if (vcpu_vmi)
		spin_lock(&vcpu_vmi->view_lock);

	if (vcpu_vmi && vcpu_vmi->current_view_id != 0) {
		/* Read under view_lock (held above), not kvm->srcu. */
		struct kvm_vmi_view_data *view =
			rcu_dereference_protected(vcpu_vmi->current_view,
				lockdep_is_held(&vcpu_vmi->view_lock));

		if (view && view->arch.mmu)
			mmu = view->arch.mmu;
	}

	vcpu->arch.hw_mmu = mmu;
	kvm_arm_vmid_update(&mmu->vmid);
	__load_stage2(mmu, mmu->arch);

	if (vcpu_vmi)
		spin_unlock(&vcpu_vmi->view_lock);

	/*
	 * VMI sysreg monitoring keeps the VM-register write trap on. This is
	 * the apply-on-re-entry point (KVM_REQ_VMI_UPDATE), mirroring x86's
	 * vmx_vmi_apply_vmcs_state asserting its intercepts: assert TVM when
	 * monitoring is active (it was force-kept across kvm_toggle_cache), and
	 * restore the default (cleared once caches are on) when it is not.
	 */
	if (kvm_vmi_sysreg_monitoring(vcpu->kvm))
		*vcpu_hcr(vcpu) |= HCR_TVM;
	else if (vcpu_has_cache_enabled(vcpu))
		*vcpu_hcr(vcpu) &= ~HCR_TVM;

	/* VMI breakpoint monitoring keeps the debug-exception trap (TDE) on. */
	if (kvm_vmi_bp_monitoring(vcpu->kvm))
		vcpu->arch.mdcr_el2 |= MDCR_EL2_TDE;
	else if (!vcpu->guest_debug)
		vcpu->arch.mdcr_el2 &= ~MDCR_EL2_TDE;

	if (has_vhe()) {
		preempt_disable();
		write_sysreg(vcpu->arch.mdcr_el2, mdcr_el2);
		preempt_enable();
	}
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
	/*
	 * Drain users of this view's hardware root before freeing it. The
	 * generic caller has already erased the view from vmi->views (no
	 * vCPU can switch to it now) and verified vcpu_count == 0 (every vCPU
	 * has switched away in software). But arm64 loads the stage-2 into
	 * VTTBR_EL2 lazily in kvm_vmi_apply_state() via KVM_REQ_VMI_UPDATE, so
	 * a kicked vCPU may still be running on its old hardware VTTBR, and an
	 * in-flight stage-2 abort walker may still hold this view's tables
	 * under mmu_lock. Freeing now would let the guest run on a freed
	 * stage-2 (a silent firmware reset) or fault the walker. So force every
	 * vCPU out of guest mode, then cycle mmu_lock to drain any in-flight
	 * fault. x86 omits the force-out (it reloads EPTP eagerly); the
	 * mmu_lock cycle mirrors x86's vmx_vmi_destroy_view().
	 */
	kvm_make_all_cpus_request(kvm, KVM_REQ_OUTSIDE_GUEST_MODE);
	write_lock(&kvm->mmu_lock);
	write_unlock(&kvm->mmu_lock);

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

/*
 * Drop the leaf stage-2 mapping for @gfn in a view's private stage-2, so the
 * next access re-faults and is re-installed with the view's current per-GFN
 * permissions. kvm_stage2_unmap_range() asserts the mmu write lock is held and
 * does not self-lock, so @locked tells us whether the caller already holds it
 * (only the mmu_notifier path does).
 */
static void kvm_vmi_zap_view_gfn(struct kvm *kvm,
				 struct kvm_vmi_view_data *view, gfn_t gfn,
				 bool locked)
{
	struct kvm_s2_mmu *mmu = view->arch.mmu;

	if (!mmu || !mmu->pgt)
		return;
	trace_kvm_vmi_zap_view_gfn(view->id, gfn);
	if (!locked)
		write_lock(&kvm->mmu_lock);
	kvm_stage2_unmap_range(mmu, gfn_to_gpa(gfn), PAGE_SIZE, false);
	if (!locked)
		write_unlock(&kvm->mmu_lock);
}

void kvm_arch_vmi_invalidate_gfn(struct kvm *kvm,
				 struct kvm_vmi_view_data *view, gfn_t gfn)
{
	kvm_vmi_zap_view_gfn(kvm, view, gfn, false);
}

void kvm_arch_vmi_invalidate_gfn_locked(struct kvm *kvm,
					struct kvm_vmi_view_data *view,
					gfn_t gfn)
{
	kvm_vmi_zap_view_gfn(kvm, view, gfn, true);
}

void kvm_arch_vmi_invalidate_gfn_revert(struct kvm *kvm,
					struct kvm_vmi_view_data *view,
					gfn_t gfn)
{
	kvm_vmi_zap_view_gfn(kvm, view, gfn, false);
}

/*
 * Resolve a view's effective per-GFN access. The generic core stores
 * per-GFN overrides as xa_mk_value(access) in @access_overrides; absent an
 * override the view's default applies. The generic resolver is static, so
 * mirror it here (matching x86).
 */
static u8 kvm_vmi_view_gfn_access(struct kvm_vmi_view_data *view, gfn_t gfn)
{
	void *entry;

	if (!view)
		return KVM_VMI_ACCESS_RWX;
	entry = xa_load(&view->access_overrides, gfn);
	if (entry)
		return (u8)xa_to_value(entry);
	return view->default_access;
}

/*
 * Clamp the stage-2 leaf permissions about to be installed for @gfn down to
 * what the vCPU's active view allows. Called from the fault path with the
 * finalized prot; only ever narrows, never widens. View 0 (NULL current_view)
 * is the unrestricted host view.
 */
void kvm_vmi_clamp_view_prot(struct kvm_vcpu *vcpu, gfn_t gfn,
			     enum kvm_pgtable_prot *prot)
{
	struct kvm_vcpu_vmi *vcpu_vmi = vcpu->vmi;
	struct kvm_vmi_view_data *view;
	u8 access;

	if (!vcpu_vmi)
		return;
	/* Fault path: the abort handler holds kvm->srcu (mmu.c). */
	view = srcu_dereference(vcpu_vmi->current_view, &vcpu->kvm->srcu);
	if (!view)
		return;
	access = kvm_vmi_view_gfn_access(view, gfn);
	if (!(access & KVM_VMI_ACCESS_R))
		*prot &= ~KVM_PGTABLE_PROT_R;
	if (!(access & KVM_VMI_ACCESS_W))
		*prot &= ~KVM_PGTABLE_PROT_W;
	if (!(access & KVM_VMI_ACCESS_X))
		*prot &= ~KVM_PGTABLE_PROT_X;
}

/*
 * True if the active alt view has per-GFN access overrides, so the fault
 * path must map at PTE granularity - otherwise a hugepage leaf would apply
 * one gfn's access to the whole block and defeat per-GFN control. Views with
 * only a uniform default_access (no overrides) can keep block mappings.
 */
bool kvm_vmi_view_force_pte(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_vmi *vcpu_vmi = vcpu->vmi;
	struct kvm_vmi_view_data *view;

	if (!vcpu_vmi)
		return false;
	/* Fault path: the abort handler holds kvm->srcu (mmu.c). */
	view = srcu_dereference(vcpu_vmi->current_view, &vcpu->kvm->srcu);
	return view && !xa_empty(&view->access_overrides);
}

/*
 * Report whether the vCPU's active view denies @attempted (R/W/X bits) for
 * @gfn. Used by the abort handler to distinguish a real VMI access violation
 * from an ordinary stage-2 fault. View 0 never denies.
 */
bool kvm_vmi_view_denies(struct kvm_vcpu *vcpu, gfn_t gfn, u8 attempted)
{
	struct kvm_vcpu_vmi *vcpu_vmi = vcpu->vmi;
	struct kvm_vmi_view_data *view;

	if (!vcpu_vmi)
		return false;
	/* Fault path: the abort handler holds kvm->srcu (mmu.c). */
	view = srcu_dereference(vcpu_vmi->current_view, &vcpu->kvm->srcu);
	if (!view)
		return false;
	return (kvm_vmi_view_gfn_access(view, gfn) & attempted) != attempted;
}

/*
 * Resolve a per-GFN remap (change_gfn) for the vCPU's active view. The generic
 * core stores gfn_overrides[gfn] as the raw target HPA cast to a pointer; the
 * fault path maps that HPA instead of the host PFN. View 0 (NULL current_view)
 * never remaps.
 *
 * Return: true and *hpa set if @gfn is remapped in the active view.
 */
bool kvm_vmi_view_remap(struct kvm_vcpu *vcpu, gfn_t gfn, hpa_t *hpa)
{
	struct kvm_vcpu_vmi *vcpu_vmi = vcpu->vmi;
	struct kvm_vmi_view_data *view;
	void *entry;

	if (!vcpu_vmi)
		return false;
	/* Fault path: the abort handler holds kvm->srcu (mmu.c). */
	view = srcu_dereference(vcpu_vmi->current_view, &vcpu->kvm->srcu);
	if (!view)
		return false;
	entry = xa_load(&view->gfn_overrides, gfn);
	if (!entry)
		return false;
	*hpa = (hpa_t)(unsigned long)entry;
	return true;
}

/*
 * Stage-2 block size in host pages. At the 16K granule PMD_SIZE is 32 MB
 * (PMD_SHIFT == 25), so a block spans PMD_SIZE >> PAGE_SHIFT host pages. Always
 * derive from PMD_SIZE; never hardcode.
 */
#define VMI_BLOCK_PAGES		(PMD_SIZE >> PAGE_SHIFT)

/*
 * True if the fault for @gfn must be mapped at PTE (page) granularity in the
 * active view. Two reasons: (1) the view has per-GFN access overrides
 * (preserved via kvm_vmi_view_force_pte); or (2) @gfn is itself
 * remapped, or a remapped GFN shares its 32 MB PMD block - a block leaf would
 * otherwise map the remapped GFN with the original (non-override) HPA.
 */
bool kvm_vmi_view_force_pte_gfn(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	struct kvm_vcpu_vmi *vcpu_vmi = vcpu->vmi;
	struct kvm_vmi_view_data *view;
	gfn_t block_start, block_end;
	unsigned long idx;
	void *entry;

	if (kvm_vmi_view_force_pte(vcpu))	/* access overrides */
		return true;
	if (!vcpu_vmi)
		return false;
	/* Fault path: the abort handler holds kvm->srcu (mmu.c). */
	view = srcu_dereference(vcpu_vmi->current_view, &vcpu->kvm->srcu);
	if (!view)
		return false;
	if (xa_load(&view->gfn_overrides, gfn))
		return true;
	block_start = ALIGN_DOWN(gfn, VMI_BLOCK_PAGES);
	block_end = block_start + VMI_BLOCK_PAGES;
	xa_for_each_range(&view->gfn_overrides, idx, entry,
			  block_start, block_end - 1)
		return true;
	return false;
}

/*
 * Deliver a KVM_VMI_EVENT_MEM_ACCESS event for a view access violation and
 * block until the agent acks. mem_access is implicitly enabled (it is not
 * gated on enabled_events), but with no ring attached there is no agent to
 * consult, so return 0 (CONTINUE) and let the clamped leaf stand.
 *
 * Return: the agent's response flags (>= 0), or 0 (CONTINUE) if no ring.
 */
int kvm_vmi_mem_access(struct kvm_vcpu *vcpu, gpa_t gpa, u8 attempted)
{
	struct kvm_vmi_ring_event ring_event = {};
	struct kvm_vmi_view_data *view;
	u8 trace_access;
	int ret, srcu_idx;

	if (!vcpu->vmi || !READ_ONCE(vcpu->vmi->ring))
		return 0;

	ring_event.type = KVM_VMI_EVENT_MEM_ACCESS;
	ring_event.vcpu_id = vcpu->vcpu_id;
	ring_event.insn_len = 0;
	ring_event.mem_access.gpa = gpa;
	ring_event.mem_access.access = attempted;

	/*
	 * The abort path has already dropped kvm->srcu before this blocking
	 * delivery, so take a brief local SRCU section to deref current_view
	 * for the tracepoint, then unlock before blocking on the ring (holding
	 * srcu across the wait would stall synchronize_srcu()).
	 */
	srcu_idx = srcu_read_lock(&vcpu->kvm->srcu);
	view = srcu_dereference(vcpu->vmi->current_view, &vcpu->kvm->srcu);
	trace_access = kvm_vmi_view_gfn_access(view, gpa_to_gfn(gpa));
	srcu_read_unlock(&vcpu->kvm->srcu, srcu_idx);

	trace_kvm_vmi_mem_violation(vcpu->vcpu_id, gpa, attempted, trace_access);
	ret = kvm_vmi_deliver_via_ring(vcpu, &ring_event);

	return ret;
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
	struct kvm_vmi *vmi;
	bool enabled;
	int srcu_idx;

	/* Run-loop fast path; arm64 holds no kvm->srcu here (unlike x86 whose run loop holds it across guest execution). */
	srcu_idx = srcu_read_lock(&vcpu->kvm->srcu);
	vmi = kvm_vmi_get(vcpu->kvm);
	enabled = vmi && (vmi->enabled_events & BIT_ULL(event_type)) &&
		  vcpu->vmi && vcpu->vmi->ring;
	srcu_read_unlock(&vcpu->kvm->srcu, srcu_idx);

	return enabled;
}

/*
 * Map an enum vcpu_sysreg (as seen in sys_reg_desc.reg / access_vm_reg) to its
 * stable KVM_VMI_SYSREG_* index, or -1 if the register is not in the monitorable
 * set. Confirmed 1:1 against the SYS_DESC entries that use access_vm_reg.
 */
int kvm_vmi_sysreg_index(int reg)
{
	switch (reg) {
	case SCTLR_EL1:		return KVM_VMI_SYSREG_SCTLR_EL1;
	case TTBR0_EL1:		return KVM_VMI_SYSREG_TTBR0_EL1;
	case TTBR1_EL1:		return KVM_VMI_SYSREG_TTBR1_EL1;
	case TCR_EL1:		return KVM_VMI_SYSREG_TCR_EL1;
	case CONTEXTIDR_EL1:	return KVM_VMI_SYSREG_CONTEXTIDR_EL1;
	case MAIR_EL1:		return KVM_VMI_SYSREG_MAIR_EL1;
	default:		return -1;
	}
}

/*
 * True if any system register is currently monitored on @kvm. Read from the
 * trap-keep fast paths; cheap (one count read, no array scan).
 */
bool kvm_vmi_sysreg_monitoring(struct kvm *kvm)
{
	struct kvm_vmi *vmi;
	bool active;
	int srcu_idx;

	/* Run-loop fast path; arm64 does not hold kvm->srcu on the TVM sysreg trap path (unlike the stage-2 abort path), so take a brief SRCU read lock around the kvm_vmi_get() dereference. */
	srcu_idx = srcu_read_lock(&kvm->srcu);
	vmi = kvm_vmi_get(kvm);
	active = vmi && vmi->arch.sysreg_monitor_count > 0;
	srcu_read_unlock(&kvm->srcu, srcu_idx);

	return active;
}

/*
 * True if guest BRK (software breakpoint) monitoring is active on @kvm. Read
 * from the debug fast paths (kvm_arm_setup_mdcr_el2, kvm_vcpu_load_debug,
 * kvm_vmi_apply_state) to decide whether to force-keep MDCR_EL2.TDE and
 * host-owned debug.
 */
bool kvm_vmi_bp_monitoring(struct kvm *kvm)
{
	struct kvm_vmi *vmi;
	bool active;
	int srcu_idx;

	/*
	 * Called from the arm64 debug fast paths (vcpu_load / exit handling),
	 * which on arm64 hold neither kvm->srcu nor kvm->lock -- unlike x86,
	 * whose run loop keeps kvm->srcu across guest execution. kvm_vmi_get()
	 * requires one of them, so take srcu around the deref + read here.
	 */
	srcu_idx = srcu_read_lock(&kvm->srcu);
	vmi = kvm_vmi_get(kvm);
	active = vmi && (vmi->enabled_events & BIT_ULL(KVM_VMI_EVENT_BREAKPOINT));
	srcu_read_unlock(&kvm->srcu, srcu_idx);

	return active;
}

/**
 * kvm_vmi_sysreg_write - Deliver a SYSREG event for a monitored VM-reg write.
 * @vcpu:    The vCPU performing the write (trapped in access_vm_reg).
 * @idx:     KVM_VMI_SYSREG_* index of the register (from kvm_vmi_sysreg_index).
 * @old_val: Current register value (before the write).
 * @new_val: Value the guest is writing.
 *
 * Applies onchangeonly/bitmask filtering, builds the ring event, and blocks
 * until the agent acks. Deferred-write pattern: return false so the caller
 * applies the write (CONTINUE / filtered / no agent), true so the caller skips
 * it (DENY, or the not-yet-implemented SET_REGS, treated as DENY).
 */
bool kvm_vmi_sysreg_write(struct kvm_vcpu *vcpu, int idx, u64 old_val,
			  u64 new_val)
{
	struct kvm_vmi_ring_event ring_event = {};
	struct kvm_vmi *vmi;
	bool onchangeonly;
	u64 bitmask;
	u64 changed;
	bool denied;
	int ret, srcu_idx;

	if (!kvm_vmi_event_enabled(vcpu, KVM_VMI_EVENT_SYSREG))
		return false;

	/*
	 * Bracket the kvm_vmi_get() + monitor deref in a brief SRCU section and
	 * snapshot the filter fields. Do not hold kvm->srcu across the blocking
	 * ring delivery below (that would wedge synchronize_srcu() in
	 * kvm_vmi_release()), so unlock first, then block.
	 */
	srcu_idx = srcu_read_lock(&vcpu->kvm->srcu);
	vmi = kvm_vmi_get(vcpu->kvm);
	if (!vmi || !vmi->arch.sysreg_monitor[idx].enabled) {
		srcu_read_unlock(&vcpu->kvm->srcu, srcu_idx);
		return false;
	}
	onchangeonly = vmi->arch.sysreg_monitor[idx].onchangeonly;
	bitmask = vmi->arch.sysreg_monitor[idx].bitmask;
	srcu_read_unlock(&vcpu->kvm->srcu, srcu_idx);

	changed = old_val ^ new_val;
	if (onchangeonly && !changed)
		return false;
	if (bitmask && !(changed & bitmask))
		return false;

	ring_event.type = KVM_VMI_EVENT_SYSREG;
	ring_event.vcpu_id = vcpu->vcpu_id;
	ring_event.insn_len = 4;	/* MSR is a 4-byte instruction */
	ring_event.arch.sysreg.reg = idx;
	ring_event.arch.sysreg.old_value = old_val;
	ring_event.arch.sysreg.new_value = new_val;

	ret = kvm_vmi_deliver_via_ring(vcpu, &ring_event);

	/* DENY (and, until SET_REGS is implemented, SET_REGS) -> skip write. */
	denied = (ret > 0 && (ret & (KVM_VMI_RESPONSE_DENY |
				     KVM_VMI_RESPONSE_SET_REGS)));
	trace_kvm_vmi_sysreg_write(idx, old_val, new_val, denied);
	return denied;
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

/*
 * Translate the guest PC (EL1&0 stage-1 VA) to an IPA via AT S1E1R, the arm64
 * analog of x86's kvm_mmu_gva_to_gpa_fetch. __kvm_at_s1e01 writes PAR_EL1 as a
 * side effect, so save and restore the guest's PAR_EL1. View-independent
 * (stage-1 only). Returns INVALID_GPA on translation fault.
 */
static gpa_t kvm_vmi_pc_to_ipa(struct kvm_vcpu *vcpu, u64 pc)
{
	u64 saved_par = vcpu_read_sys_reg(vcpu, PAR_EL1);
	gpa_t ipa = INVALID_GPA;
	u64 par;

	__kvm_at_s1e01(vcpu, OP_AT_S1E1R, pc);
	par = vcpu_read_sys_reg(vcpu, PAR_EL1);
	if (!(par & SYS_PAR_EL1_F))
		/*
		 * PAR_EL1.PA is a 4K-granular field (bits[51:12]); the output
		 * address's low 12 bits equal the input VA's bits[11:0],
		 * regardless of the host (16K) or guest translation granule.
		 * Use a fixed 12-bit offset, NOT the host PAGE_MASK.
		 */
		ipa = (par & SYS_PAR_EL1_PA) | (pc & GENMASK_ULL(11, 0));

	vcpu_write_sys_reg(vcpu, saved_par, PAR_EL1);
	return ipa;
}

/*
 * Guest BRK trapped to EL2 (MDCR_EL2.TDE). Deliver a BREAKPOINT event with the
 * BRK's IPA + comment, then apply the agent's response. The kernel NEVER
 * advances PC: CONTINUE re-enters on the BRK (re-traps), SET_REGS lets the
 * agent advance PC (applied generically), REINJECT delivers the BRK to the
 * guest EL1. Always returns 1 (re-enter the guest).
 */
int kvm_vmi_breakpoint(struct kvm_vcpu *vcpu)
{
	struct kvm_vmi_ring_event ring_event = {};
	u64 esr = kvm_vcpu_get_esr(vcpu);
	u64 pc = *vcpu_pc(vcpu);
	gpa_t ipa;
	int ret;

	if (!kvm_vmi_event_enabled(vcpu, KVM_VMI_EVENT_BREAKPOINT))
		return 1;

	ipa = kvm_vmi_pc_to_ipa(vcpu, pc);

	ring_event.type = KVM_VMI_EVENT_BREAKPOINT;
	ring_event.vcpu_id = vcpu->vcpu_id;
	ring_event.insn_len = 4;
	ring_event.arch.breakpoint.ipa = ipa;
	ring_event.arch.breakpoint.imm = esr_brk_comment(esr);

	trace_kvm_vmi_event_deliver(vcpu->vcpu_id, KVM_VMI_EVENT_BREAKPOINT, ipa);
	ret = kvm_vmi_deliver_via_ring(vcpu, &ring_event);

	/*
	 * REINJECT handled here (esr is in scope and is the BRK's). SET_REGS
	 * GPR/PC restore is applied generically by the core. CONTINUE: no PC
	 * change -> the BRK re-traps. The kernel never advances PC itself.
	 */
	if (ret > 0 && (ret & KVM_VMI_RESPONSE_REINJECT))
		kvm_inject_brk64(vcpu, esr_brk_comment(esr));

	return 1;
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
	switch (event_type) {
	case KVM_VMI_EVENT_SYSREG:
		/*
		 * The deferred-write verdict (CONTINUE vs DENY) is applied at
		 * the access_vm_reg() callsite via the kvm_vmi_sysreg_write()
		 * return value, and the sysreg path's automatic PC increment
		 * already consumes the instruction. SET_REGS for sysreg writes
		 * is not yet implemented; the generic core's GPR restore on
		 * SET_REGS has already run, so there is nothing to do here.
		 */
		break;
	default:
		break;
	}
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

void kvm_arch_vmi_restore_singlestep(struct kvm_vcpu *vcpu)
{
}
