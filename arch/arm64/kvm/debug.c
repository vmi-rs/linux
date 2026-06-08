// SPDX-License-Identifier: GPL-2.0-only
/*
 * Debug and Guest Debug support
 *
 * Copyright (C) 2015 - Linaro Ltd
 * Authors: Alex Bennée <alex.bennee@linaro.org>
 * 	    Oliver Upton <oliver.upton@linux.dev>
 */

#include <linux/kvm_host.h>
#include <linux/hw_breakpoint.h>

#include <asm/debug-monitors.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_emulate.h>

static int cpu_has_spe(u64 dfr0)
{
	return cpuid_feature_extract_unsigned_field(dfr0, ID_AA64DFR0_EL1_PMSVer_SHIFT) &&
	       !(read_sysreg_s(SYS_PMBIDR_EL1) & PMBIDR_EL1_P);
}

/**
 * kvm_arm_setup_mdcr_el2 - configure vcpu mdcr_el2 value
 *
 * @vcpu:	the vcpu pointer
 *
 * This ensures we will trap access to:
 *  - Performance monitors (MDCR_EL2_TPM/MDCR_EL2_TPMCR)
 *  - Debug ROM Address (MDCR_EL2_TDRA)
 *  - OS related registers (MDCR_EL2_TDOSA)
 *  - Statistical profiler (MDCR_EL2_TPMS/MDCR_EL2_E2PB)
 *  - Self-hosted Trace Filter controls (MDCR_EL2_TTRF)
 *  - Self-hosted Trace (MDCR_EL2_TTRF/MDCR_EL2_E2TB)
 */
static void kvm_arm_setup_mdcr_el2(struct kvm_vcpu *vcpu)
{
	preempt_disable();

	/*
	 * This also clears MDCR_EL2_E2PB_MASK and MDCR_EL2_E2TB_MASK
	 * to disable guest access to the profiling and trace buffers
	 */
	vcpu->arch.mdcr_el2 = FIELD_PREP(MDCR_EL2_HPMN,
					 *host_data_ptr(nr_event_counters));
	vcpu->arch.mdcr_el2 |= (MDCR_EL2_TPM |
				MDCR_EL2_TPMS |
				MDCR_EL2_TTRF |
				MDCR_EL2_TPMCR |
				MDCR_EL2_TDRA |
				MDCR_EL2_TDOSA);

	/*
	 * Route software debug exceptions to EL2 for userspace debug, VMI BRK,
	 * or VMI single-step.
	 */
	if (vcpu->guest_debug || kvm_vmi_bp_monitoring(vcpu->kvm) ||
	    kvm_vmi_singlestep_active(vcpu))
		vcpu->arch.mdcr_el2 |= MDCR_EL2_TDE;

	/*
	 * Trap debug registers if the guest doesn't have ownership of them.
	 */
	if (!kvm_guest_owns_debug_regs(vcpu))
		vcpu->arch.mdcr_el2 |= MDCR_EL2_TDA;

	if (vcpu_has_nv(vcpu))
		kvm_nested_setup_mdcr_el2(vcpu);

	/* Write MDCR_EL2 directly if we're already at EL2 */
	if (has_vhe())
		write_sysreg(vcpu->arch.mdcr_el2, mdcr_el2);

	preempt_enable();
}

void kvm_init_host_debug_data(void)
{
	u64 dfr0 = read_sysreg(id_aa64dfr0_el1);

	if (cpuid_feature_extract_signed_field(dfr0, ID_AA64DFR0_EL1_PMUVer_SHIFT) > 0)
		*host_data_ptr(nr_event_counters) = FIELD_GET(ARMV8_PMU_PMCR_N,
							      read_sysreg(pmcr_el0));

	*host_data_ptr(debug_brps) = SYS_FIELD_GET(ID_AA64DFR0_EL1, BRPs, dfr0);
	*host_data_ptr(debug_wrps) = SYS_FIELD_GET(ID_AA64DFR0_EL1, WRPs, dfr0);

	if (cpu_has_spe(dfr0))
		host_data_set_flag(HAS_SPE);

	if (has_vhe())
		return;

	/* Check if we have BRBE implemented and available at the host */
	if (cpuid_feature_extract_unsigned_field(dfr0, ID_AA64DFR0_EL1_BRBE_SHIFT))
		host_data_set_flag(HAS_BRBE);

	if (cpuid_feature_extract_unsigned_field(dfr0, ID_AA64DFR0_EL1_TraceFilt_SHIFT)) {
		/* Force disable trace in protected mode in case of no TRBE */
		if (is_protected_kvm_enabled())
			host_data_set_flag(EL1_TRACING_CONFIGURED);

		if (cpuid_feature_extract_unsigned_field(dfr0, ID_AA64DFR0_EL1_TraceBuffer_SHIFT) &&
		    !(read_sysreg_s(SYS_TRBIDR_EL1) & TRBIDR_EL1_P))
			host_data_set_flag(HAS_TRBE);
	}
}

void kvm_debug_init_vhe(void)
{
	/* Clear PMSCR_EL1.E{0,1}SPE which reset to UNKNOWN values. */
	if (host_data_test_flag(HAS_SPE))
		write_sysreg_el1(0, SYS_PMSCR);
}

/*
 * True when a real hardware software-step (PSTATE.SS) is wanted. A VMI atomic
 * step shares singlestep_active for its host-owned-debug / MDCR_EL2.TDE plumbing
 * but must NOT arm PSTATE.SS: a step exception inside an LDXR..STXR sequence
 * clears the local exclusive monitor, so the atomic could never complete. The
 * atomic step uses a region-end HW breakpoint (MDSCR_EL1.MDE) instead.
 */
static bool kvm_vmi_hw_singlestep(struct kvm_vcpu *vcpu)
{
	return kvm_vmi_singlestep_active(vcpu) && !kvm_vmi_atomic_step_active(vcpu);
}

/*
 * Configures the 'external' MDSCR_EL1 value for the guest, i.e. when the host
 * has taken over MDSCR_EL1.
 *
 *  - Userspace is single-stepping the guest, and MDSCR_EL1.SS is forced to 1.
 *
 *  - Userspace is using the breakpoint/watchpoint registers to debug the
 *    guest, and MDSCR_EL1.MDE is forced to 1.
 *
 *  - The guest has enabled the OS Lock, and KVM is forcing MDSCR_EL1.MDE to 0,
 *    masking all debug exceptions affected by the OS Lock.
 */
static void setup_external_mdscr(struct kvm_vcpu *vcpu)
{
	/*
	 * Use the guest's MDSCR_EL1 as a starting point, since there are
	 * several other features controlled by MDSCR_EL1 that are not relevant
	 * to the host.
	 *
	 * Clear the bits that KVM may use which also satisfies emulation of
	 * the OS Lock as MDSCR_EL1.MDE is cleared.
	 */
	u64 mdscr = vcpu_read_sys_reg(vcpu, MDSCR_EL1) & ~(MDSCR_EL1_SS |
							   MDSCR_EL1_MDE |
							   MDSCR_EL1_KDE);

	if ((vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP) ||
	    kvm_vmi_hw_singlestep(vcpu))
		mdscr |= MDSCR_EL1_SS;

	/*
	 * Enable breakpoint/watchpoint debug events for userspace HW debug and
	 * for the VMI atomic-step region-end breakpoint.
	 */
	if ((vcpu->guest_debug & KVM_GUESTDBG_USE_HW) ||
	    kvm_vmi_atomic_step_active(vcpu))
		mdscr |= MDSCR_EL1_MDE | MDSCR_EL1_KDE;

	vcpu->arch.external_mdscr_el1 = mdscr;
}

void kvm_vcpu_load_debug(struct kvm_vcpu *vcpu)
{
	u64 mdscr;

	/* Must be called before kvm_vcpu_load_vhe() */
	KVM_BUG_ON(vcpu_get_flag(vcpu, SYSREGS_ON_CPU), vcpu->kvm);

	if (has_vhe()) {
		*host_data_ptr(host_debug_state.mdcr_el2) = read_sysreg(mdcr_el2);
		/*
		 * Snapshot the genuine host MDSCR_EL1 before any VMI single-step
		 * setup can write the live, VHE-shared register. Restored
		 * unconditionally in kvm_vcpu_put_debug() so the host never
		 * resumes EL0 with a leaked MDSCR_EL1.SS.
		 */
		*host_data_ptr(host_debug_state.mdscr_el1) = read_sysreg(mdscr_el1);
	}

	/*
	 * Determine which of the possible debug states we're in:
	 *
	 *  - VCPU_DEBUG_HOST_OWNED: KVM has taken ownership of the guest's
	 *    breakpoint/watchpoint registers, or needs to use MDSCR_EL1 to do
	 *    software step or emulate the effects of the OS Lock being enabled.
	 *
	 *  - VCPU_DEBUG_GUEST_OWNED: The guest has debug exceptions enabled, and
	 *    the breakpoint/watchpoint registers need to be loaded eagerly.
	 *
	 *  - VCPU_DEBUG_FREE: Neither of the above apply, no breakpoint/watchpoint
	 *    context needs to be loaded on the CPU.
	 */
	if (vcpu->guest_debug || kvm_vcpu_os_lock_enabled(vcpu) ||
	    kvm_vmi_bp_monitoring(vcpu->kvm) || kvm_vmi_singlestep_active(vcpu)) {
		vcpu->arch.debug_owner = VCPU_DEBUG_HOST_OWNED;
		setup_external_mdscr(vcpu);

		/*
		 * Steal the guest's single-step state machine if userspace wants
		 * single-step the guest.
		 */
		if ((vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP) ||
		    kvm_vmi_hw_singlestep(vcpu)) {
			if (*vcpu_cpsr(vcpu) & DBG_SPSR_SS)
				vcpu_clear_flag(vcpu, GUEST_SS_ACTIVE_PENDING);
			else
				vcpu_set_flag(vcpu, GUEST_SS_ACTIVE_PENDING);

			if (!vcpu_get_flag(vcpu, HOST_SS_ACTIVE_PENDING))
				*vcpu_cpsr(vcpu) |= DBG_SPSR_SS;
			else
				*vcpu_cpsr(vcpu) &= ~DBG_SPSR_SS;
		}
	} else {
		mdscr = vcpu_read_sys_reg(vcpu, MDSCR_EL1);

		if (mdscr & (MDSCR_EL1_KDE | MDSCR_EL1_MDE))
			vcpu->arch.debug_owner = VCPU_DEBUG_GUEST_OWNED;
		else
			vcpu->arch.debug_owner = VCPU_DEBUG_FREE;
	}

	kvm_arm_setup_mdcr_el2(vcpu);
}

void kvm_vcpu_put_debug(struct kvm_vcpu *vcpu)
{
	if (has_vhe()) {
		write_sysreg(*host_data_ptr(host_debug_state.mdcr_el2), mdcr_el2);
		/*
		 * VMI single-step may have written MDSCR_EL1.SS into the live,
		 * VHE-shared register (kvm_vmi_apply_singlestep()). Restore the
		 * genuine host value before the early return below: the
		 * plain-singlestep ring-block path disarms
		 * kvm_vmi_singlestep_active() before this runs, so the early
		 * return would otherwise skip the restore and leave the host
		 * resuming EL0 with single-step armed.
		 */
		write_sysreg(*host_data_ptr(host_debug_state.mdscr_el1), mdscr_el1);
	}

	if (likely(!(vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP) &&
		   !kvm_vmi_hw_singlestep(vcpu)))
		return;

	/*
	 * Save the host's software step state and restore the guest's before
	 * potentially returning to userspace.
	 */
	if (!(*vcpu_cpsr(vcpu) & DBG_SPSR_SS))
		vcpu_set_flag(vcpu, HOST_SS_ACTIVE_PENDING);
	else
		vcpu_clear_flag(vcpu, HOST_SS_ACTIVE_PENDING);

	if (vcpu_get_flag(vcpu, GUEST_SS_ACTIVE_PENDING))
		*vcpu_cpsr(vcpu) &= ~DBG_SPSR_SS;
	else
		*vcpu_cpsr(vcpu) |= DBG_SPSR_SS;
}

#ifdef CONFIG_KVM_VMI
/*
 * Asynchronous exceptions (SError/IRQ/FIQ) the VMI single-step masks in the
 * guest's PSTATE for the duration of the one-instruction step window. PSTATE.D
 * is deliberately left untouched: the step is routed to EL2 via MDCR_EL2.TDE,
 * so a lower-EL debug mask cannot gate it, and masking it would only risk
 * suppressing the step we are trying to take.
 */
#define VMI_SS_DAIF_MASK	(PSR_A_BIT | PSR_I_BIT | PSR_F_BIT)

/*
 * Mask the guest's asynchronous exceptions for a VMI single-step window.
 *
 * VMI steps a LIVE, preemptible guest that is not party to the software-step
 * protocol (unlike the in-tree stepper, whose exception entry/exit hooks clear
 * and restore MDSCR_EL1.SS per stepped thread). Were an interrupt taken between
 * arming PSTATE.SS and the step trapping to EL2, the guest would enter its own
 * handler with the step bit pending and hardware would have already saved
 * SPSR_EL1.SS=1 into the interrupted thread's context in guest RAM, beyond KVM's
 * reach; that thread later takes a spurious software-step exception (observed in
 * a Windows guest as a stray STATUS_SINGLE_STEP at an arbitrary instruction).
 *
 * Masking SError/IRQ/FIQ makes the step atomic: exactly one instruction
 * executes and traps to EL2, with no preemption to leak SS. This mirrors the
 * in-tree invariant that a software step runs only with interrupts disabled
 * (kernel_enable_single_step()'s WARN_ON(!irqs_disabled())). The masked
 * interrupts are not lost -- they stay pending in the vGIC and are taken once
 * the guest's real DAIF is restored at disarm.
 */
static void kvm_vmi_mask_singlestep_daif(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_vmi *vcpu_vmi = vcpu->vmi;

	if (!vcpu_vmi || vcpu_vmi->arch.daif_masked)
		return;

	vcpu_vmi->arch.saved_daif = *vcpu_cpsr(vcpu) & VMI_SS_DAIF_MASK;
	*vcpu_cpsr(vcpu) |= VMI_SS_DAIF_MASK;
	vcpu_vmi->arch.daif_masked = true;
}

/* Restore the guest's pre-step DAIF, undoing kvm_vmi_mask_singlestep_daif(). */
static void kvm_vmi_unmask_singlestep_daif(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_vmi *vcpu_vmi = vcpu->vmi;

	if (!vcpu_vmi || !vcpu_vmi->arch.daif_masked)
		return;

	*vcpu_cpsr(vcpu) &= ~VMI_SS_DAIF_MASK;
	*vcpu_cpsr(vcpu) |= vcpu_vmi->arch.saved_daif;
	vcpu_vmi->arch.daif_masked = false;
}

/*
 * Arm or disarm VMI hardware single-step on @vcpu, materialized LIVE because
 * under VHE MDSCR_EL1 is loaded only at vcpu_load. Called from
 * kvm_vmi_apply_state() on KVM_REQ_VMI_UPDATE. Models VMI single-step as a
 * host-side stepper: it shares MDSCR_EL1.SS / PSTATE.SS and the guest-SS
 * save/restore (kvm_vcpu_load_debug/put_debug) with userspace
 * KVM_GUESTDBG_SINGLESTEP, so the two coexist without corruption.
 */
void kvm_vmi_apply_singlestep(struct kvm_vcpu *vcpu)
{
	bool want = kvm_vmi_singlestep_active(vcpu);

	/*
	 * Restore any guest DAIF masked for a step window BEFORE the
	 * host-ownership early-return below. A VMI session teardown
	 * (kvm_vmi_release) clears bp-monitoring and the step, so the next
	 * kvm_vcpu_load_debug() drops debug ownership; keying the skip off
	 * ownership would then leave a vCPU torn down mid-step resuming with
	 * A/I/F masked -> interrupts disabled -> silent spin/hang. This runs on
	 * the vCPU's own thread with vcpu->vmi still valid (the SRCU teardown
	 * defers the free past this KVM_REQ_VMI_UPDATE), and is idempotent
	 * (guarded by daif_masked), so a normal disarm restores it exactly once.
	 */
	if (!want)
		kvm_vmi_unmask_singlestep_daif(vcpu);

	/*
	 * Skip only when nothing host-side needs managing: not arming now and
	 * not already host-owned. Keying the skip off host-ownership (not
	 * guest_debug) is essential for DISARM: a step armed by a prior
	 * apply_state left the vCPU host-owned, so a later CONTINUE (want==false,
	 * no guest_debug) MUST fall through here to clear MDSCR_EL1.SS, else the
	 * guest keeps stepping into SOFTSTP_LOW exceptions singlestep_active no
	 * longer claims.
	 */
	if (!want && !kvm_host_owns_debug_regs(vcpu))
		return;

	if (want)
		vcpu->arch.debug_owner = VCPU_DEBUG_HOST_OWNED;

	setup_external_mdscr(vcpu);	/* SS for a real step, MDE for an atomic step */

	if (kvm_vmi_hw_singlestep(vcpu)) {
		*vcpu_cpsr(vcpu) |= DBG_SPSR_SS;
		kvm_vmi_mask_singlestep_daif(vcpu);
	} else if (!(vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP)) {
		/*
		 * Not a real single-step (disarm, or an atomic step which uses a
		 * region-end HW breakpoint instead): ensure PSTATE.SS is clear. The
		 * atomic step's breakpoint lives in external_debug_state, armed by
		 * kvm_vmi_arm_atomic_step_bp() and loaded by the hyp debug switch.
		 */
		*vcpu_cpsr(vcpu) &= ~DBG_SPSR_SS;
	}

	if (has_vhe()) {
		preempt_disable();
		write_sysreg(vcpu->arch.external_mdscr_el1, mdscr_el1);
		preempt_enable();
	}
}

/*
 * Teardown-time restore of a guest DAIF masked for an in-flight VMI single-step.
 *
 * The normal disarm restores DAIF from a later kvm_vmi_apply_singlestep(), but a
 * session teardown NULLs and frees vcpu->vmi (where saved_daif lives) before that
 * apply can run, stranding the masked guest with interrupts disabled (a silent
 * hang). kvm_vmi_release() calls this from the agent thread with vcpu->mutex held
 * and the vCPU parked, while vcpu->vmi is still valid, so the saved value is
 * restored exactly once (the unmask is idempotent, guarded by daif_masked). The
 * hardware single-step bits are cleared by the post-teardown apply, which does
 * not need vcpu->vmi, so only DAIF needs restoring here.
 */
void kvm_arch_vmi_restore_singlestep(struct kvm_vcpu *vcpu)
{
	kvm_vmi_unmask_singlestep_daif(vcpu);
	/* Disarm any in-flight atomic-step region-end breakpoint too. */
	kvm_vmi_disarm_atomic_step_bp(vcpu);
}

/*
 * One-shot internal HW breakpoint for the VMI atomic step. It regains control at
 * the end of an LDXR..STXR sequence run on the default view, so the exclusive
 * completes atomically (no step exception clears the monitor). The breakpoint
 * lives in external_debug_state[BRP 0], loaded by the hyp debug switch when VMI
 * owns debug (singlestep_active keeps it host-owned); the guest's own breakpoint
 * registers live in vcpu_debug_state and are not loaded then, and the atomic
 * step is gated off when userspace owns HW debug (KVM_GUESTDBG_USE_HW), so BRP 0
 * is free. DBGBCR selects an unlinked instruction-address match over guest
 * EL1&EL0 (BAS=0b1111, type/BT=0, HMC=0, SSC=0); MDCR_EL2.TDE routes the
 * exception to EL2 and MDSCR_EL1.MDE (setup_external_mdscr) enables it.
 */
#define VMI_ATOMIC_STEP_BRP	0
#define VMI_ATOMIC_STEP_DBGBCR	((0xfUL << 5) | (0x3UL << 1) | 0x1UL)

void kvm_vmi_arm_atomic_step_bp(struct kvm_vcpu *vcpu, u64 end_va)
{
	vcpu->arch.external_debug_state.dbg_bvr[VMI_ATOMIC_STEP_BRP] = end_va;
	vcpu->arch.external_debug_state.dbg_bcr[VMI_ATOMIC_STEP_BRP] =
		VMI_ATOMIC_STEP_DBGBCR;
}

void kvm_vmi_disarm_atomic_step_bp(struct kvm_vcpu *vcpu)
{
	vcpu->arch.external_debug_state.dbg_bcr[VMI_ATOMIC_STEP_BRP] = 0;
	vcpu->arch.external_debug_state.dbg_bvr[VMI_ATOMIC_STEP_BRP] = 0;
}
#endif /* CONFIG_KVM_VMI */

/*
 * Updates ownership of the debug registers after a trapped guest access to a
 * breakpoint/watchpoint register. Host ownership of the debug registers is of
 * strictly higher priority, and it is the responsibility of the VMM to emulate
 * guest debug exceptions in this configuration.
 */
void kvm_debug_set_guest_ownership(struct kvm_vcpu *vcpu)
{
	if (kvm_host_owns_debug_regs(vcpu))
		return;

	vcpu->arch.debug_owner = VCPU_DEBUG_GUEST_OWNED;
	kvm_arm_setup_mdcr_el2(vcpu);
}

void kvm_debug_handle_oslar(struct kvm_vcpu *vcpu, u64 val)
{
	if (val & OSLAR_EL1_OSLK)
		__vcpu_rmw_sys_reg(vcpu, OSLSR_EL1, |=, OSLSR_EL1_OSLK);
	else
		__vcpu_rmw_sys_reg(vcpu, OSLSR_EL1, &=, ~OSLSR_EL1_OSLK);

	preempt_disable();
	kvm_arch_vcpu_put(vcpu);
	kvm_arch_vcpu_load(vcpu, smp_processor_id());
	preempt_enable();
}

static bool skip_trbe_access(bool skip_condition)
{
	return (WARN_ON_ONCE(preemptible()) || skip_condition ||
		is_protected_kvm_enabled() || !is_kvm_arm_initialised());
}

void kvm_enable_trbe(void)
{
	if (!skip_trbe_access(has_vhe()))
		host_data_set_flag(TRBE_ENABLED);
}
EXPORT_SYMBOL_GPL(kvm_enable_trbe);

void kvm_disable_trbe(void)
{
	if (!skip_trbe_access(has_vhe()))
		host_data_clear_flag(TRBE_ENABLED);
}
EXPORT_SYMBOL_GPL(kvm_disable_trbe);

void kvm_tracing_set_el1_configuration(u64 trfcr_while_in_guest)
{
	if (skip_trbe_access(false))
		return;

	if (has_vhe()) {
		write_sysreg_s(trfcr_while_in_guest, SYS_TRFCR_EL12);
		return;
	}

	*host_data_ptr(trfcr_while_in_guest) = trfcr_while_in_guest;
	if (read_sysreg_s(SYS_TRFCR_EL1) != trfcr_while_in_guest)
		host_data_set_flag(EL1_TRACING_CONFIGURED);
	else
		host_data_clear_flag(EL1_TRACING_CONFIGURED);
}
EXPORT_SYMBOL_GPL(kvm_tracing_set_el1_configuration);
