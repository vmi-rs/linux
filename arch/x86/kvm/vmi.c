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

/*
 * Convert a kvm_segment's attribute fields into VMX-format access rights.
 * The encoding follows the VMX VMCS Guest Segment Access Rights format
 * (SDM Vol. 3C, 24.4.1): type[3:0], S[4], DPL[6:5], P[7], AVL[12],
 * L[13], D/B[14], G[15].
 */
static u16 kvm_vmi_segment_ar(struct kvm_segment *seg)
{
	u16 ar = seg->type & 0xf;

	ar |= (seg->s & 1) << 4;
	ar |= (seg->dpl & 3) << 5;
	ar |= (seg->present & 1) << 7;
	ar |= (seg->avl & 1) << 12;
	ar |= (seg->l & 1) << 13;
	ar |= (seg->db & 1) << 14;
	ar |= (seg->g & 1) << 15;
	return ar;
}

#define CAPTURE_SEGMENT(vcpu, regs, name, sreg) do {		\
	struct kvm_segment __seg;				\
	kvm_get_segment(vcpu, &__seg, sreg);			\
	(regs)->name.base = __seg.base;				\
	(regs)->name.limit = __seg.limit;			\
	(regs)->name.selector = __seg.selector;			\
	(regs)->name.ar = kvm_vmi_segment_ar(&__seg);		\
} while (0)

/**
 * kvm_vmi_capture_regs - Copy vCPU register state into ring event regs
 * @vcpu: The vCPU whose registers to capture.
 * @regs: Destination register struct in the ring event.
 *
 * Called during ring-based event delivery to provide the agent with a
 * full register capture without needing to call KVM_GET_REGS ioctls
 * (which would require the vCPU mutex that's held by the blocked vCPU).
 */
void kvm_vmi_capture_regs(struct kvm_vcpu *vcpu, struct kvm_vmi_regs *regs)
{
	u64 msr_val;

	/* GP registers */
	regs->rax = kvm_rax_read(vcpu);
	regs->rbx = kvm_rbx_read(vcpu);
	regs->rcx = kvm_rcx_read(vcpu);
	regs->rdx = kvm_rdx_read(vcpu);
	regs->rsi = kvm_rsi_read(vcpu);
	regs->rdi = kvm_rdi_read(vcpu);
	regs->rbp = kvm_rbp_read(vcpu);
	regs->rsp = kvm_rsp_read(vcpu);
#ifdef CONFIG_X86_64
	regs->r8 = kvm_r8_read(vcpu);
	regs->r9 = kvm_r9_read(vcpu);
	regs->r10 = kvm_r10_read(vcpu);
	regs->r11 = kvm_r11_read(vcpu);
	regs->r12 = kvm_r12_read(vcpu);
	regs->r13 = kvm_r13_read(vcpu);
	regs->r14 = kvm_r14_read(vcpu);
	regs->r15 = kvm_r15_read(vcpu);
#endif
	regs->rip = kvm_rip_read(vcpu);
	regs->rflags = kvm_get_rflags(vcpu);

	/* Control registers */
	regs->cr0 = kvm_read_cr0(vcpu);
	regs->cr3 = kvm_read_cr3(vcpu);
	regs->cr4 = kvm_read_cr4(vcpu);
	regs->xcr0 = vcpu->arch.xcr0;

	/* Segment registers */
	CAPTURE_SEGMENT(vcpu, regs, cs, VCPU_SREG_CS);
	CAPTURE_SEGMENT(vcpu, regs, ss, VCPU_SREG_SS);
	CAPTURE_SEGMENT(vcpu, regs, ds, VCPU_SREG_DS);
	CAPTURE_SEGMENT(vcpu, regs, es, VCPU_SREG_ES);
	CAPTURE_SEGMENT(vcpu, regs, fs, VCPU_SREG_FS);
	CAPTURE_SEGMENT(vcpu, regs, gs, VCPU_SREG_GS);

	/* MSRs - use kvm_msr_read() which dispatches to the correct backend */
	if (!kvm_msr_read(vcpu, MSR_IA32_SYSENTER_CS, &msr_val))
		regs->sysenter_cs = msr_val;
	if (!kvm_msr_read(vcpu, MSR_IA32_SYSENTER_ESP, &msr_val))
		regs->sysenter_esp = msr_val;
	if (!kvm_msr_read(vcpu, MSR_IA32_SYSENTER_EIP, &msr_val))
		regs->sysenter_eip = msr_val;

	regs->msr_efer = vcpu->arch.efer;

#ifdef CONFIG_X86_64
	if (!kvm_msr_read(vcpu, MSR_STAR, &msr_val))
		regs->msr_star = msr_val;
	if (!kvm_msr_read(vcpu, MSR_LSTAR, &msr_val))
		regs->msr_lstar = msr_val;
	if (!kvm_msr_read(vcpu, MSR_CSTAR, &msr_val))
		regs->msr_cstar = msr_val;
	if (!kvm_msr_read(vcpu, MSR_SYSCALL_MASK, &msr_val))
		regs->msr_syscall_mask = msr_val;
	if (!kvm_msr_read(vcpu, MSR_KERNEL_GS_BASE, &msr_val))
		regs->msr_kernel_gs_base = msr_val;
	if (!kvm_msr_read(vcpu, MSR_TSC_AUX, &msr_val))
		regs->msr_tsc_aux = msr_val;
#endif
}

/**
 * kvm_vmi_restore_regs - Copy registers from ring event back to vCPU
 * @vcpu: The vCPU whose registers to update.
 * @regs: Source register struct from the ring event.
 *
 * Only restores GP registers, RIP, and RFLAGS. Control registers,
 * segments, and MSRs are not restored here - modifying those without
 * proper validation could crash the host. The agent should use
 * KVM_SET_SREGS/KVM_SET_MSRS for those if needed.
 */
void kvm_vmi_restore_regs(struct kvm_vcpu *vcpu, struct kvm_vmi_regs *regs)
{
	kvm_rax_write(vcpu, regs->rax);
	kvm_rbx_write(vcpu, regs->rbx);
	kvm_rcx_write(vcpu, regs->rcx);
	kvm_rdx_write(vcpu, regs->rdx);
	kvm_rsi_write(vcpu, regs->rsi);
	kvm_rdi_write(vcpu, regs->rdi);
	kvm_rbp_write(vcpu, regs->rbp);
	kvm_rsp_write(vcpu, regs->rsp);
#ifdef CONFIG_X86_64
	kvm_r8_write(vcpu, regs->r8);
	kvm_r9_write(vcpu, regs->r9);
	kvm_r10_write(vcpu, regs->r10);
	kvm_r11_write(vcpu, regs->r11);
	kvm_r12_write(vcpu, regs->r12);
	kvm_r13_write(vcpu, regs->r13);
	kvm_r14_write(vcpu, regs->r14);
	kvm_r15_write(vcpu, regs->r15);
#endif
	kvm_rip_write(vcpu, regs->rip);
	kvm_set_rflags(vcpu, regs->rflags);
}

/**
 * kvm_vmi_handle_event_response - Dispatch event response to the right handler
 * @vcpu: The vCPU that delivered the event.
 * @event_type: The KVM_VMI_EVENT_* type of the original event.
 * @resp: KVM_VMI_RESPONSE_* bitmask from the agent.
 *
 * Called from the common VMI ring processing code after the agent writes
 * its response. Routes to the appropriate x86-specific handler based on
 * event type.
 */
void kvm_vmi_handle_event_response(struct kvm_vcpu *vcpu, u32 event_type,
				   u32 resp)
{
	switch (event_type) {
	default:
		break;
	}
}

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
