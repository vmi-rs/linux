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

/*
 * vmi_emulate_insn - Emulate the intercepted instruction, preserving
 * any exception/interrupt injected by the agent during the ring wait.
 *
 * kvm_emulate_instruction() calls kvm_clear_exception_queue() as part
 * of its setup, which would wipe any exception the agent injected via
 * KVM_VMI_INJECT_EVENT. Save and restore the exception/interrupt state
 * around the emulation.
 */
static void vmi_emulate_insn(struct kvm_vcpu *vcpu)
{
	struct kvm_queued_exception saved_exception = vcpu->arch.exception;
	struct kvm_queued_interrupt saved_interrupt = vcpu->arch.interrupt;
	bool had_exception = vcpu->arch.exception.pending;
	bool had_interrupt = vcpu->arch.interrupt.injected;

	kvm_emulate_instruction(vcpu, 0);

	if (had_exception && !vcpu->arch.exception.pending) {
		vcpu->arch.exception = saved_exception;
		kvm_make_request(KVM_REQ_EVENT, vcpu);
	}
	if (had_interrupt && !vcpu->arch.interrupt.injected) {
		vcpu->arch.interrupt = saved_interrupt;
		kvm_make_request(KVM_REQ_EVENT, vcpu);
	}
}

/**
 * handle_cr_response - Handle CR event response
 * @vcpu: The vCPU re-entering after a CR event.
 * @resp: KVM_VMI_RESPONSE_* flags from the agent.
 *
 * CR uses Xen's deferred-write pattern:
 * CONTINUE (0): Write proceeds (caller applies it). Default.
 * DENY: Advance RIP without applying the write.
 * SET_REGS: Agent controls everything.
 */
static void handle_cr_response(struct kvm_vcpu *vcpu, u32 resp)
{
	if (resp & KVM_VMI_RESPONSE_SET_REGS)
		return;

	if (resp & KVM_VMI_RESPONSE_DENY)
		kvm_skip_emulated_instruction(vcpu);
}

/**
 * handle_msr_response - Handle MSR event response
 * @vcpu: The vCPU re-entering after an MSR event.
 * @resp: KVM_VMI_RESPONSE_* flags from the agent.
 *
 * MSR uses Xen's deferred-write pattern:
 * CONTINUE (0): Write proceeds (caller applies it). Default.
 * DENY: Advance RIP without applying the write.
 * SET_REGS: Agent controls everything.
 */
static void handle_msr_response(struct kvm_vcpu *vcpu, u32 resp)
{
	if (resp & KVM_VMI_RESPONSE_SET_REGS)
		return;

	if (resp & KVM_VMI_RESPONSE_DENY)
		kvm_skip_emulated_instruction(vcpu);
}

/**
 * handle_cpuid_response - Handle CPUID event response
 * @vcpu: The vCPU re-entering after a CPUID event.
 * @resp: KVM_VMI_RESPONSE_* bitmask from userspace.
 *
 * EMULATE: Emulate CPUID instruction (write results + advance RIP).
 * DENY: Advance RIP without emulating (CPUID appears as NOP).
 * SET_REGS: Agent controls everything.
 */
static void handle_cpuid_response(struct kvm_vcpu *vcpu, u32 resp)
{
	if (resp & KVM_VMI_RESPONSE_SET_REGS)
		return;

	if (resp & KVM_VMI_RESPONSE_EMULATE)
		vmi_emulate_insn(vcpu);
	else if (resp & KVM_VMI_RESPONSE_DENY)
		kvm_skip_emulated_instruction(vcpu);
}

/**
 * handle_bp_response - Handle breakpoint event response
 * @vcpu: The vCPU re-entering after a breakpoint event.
 * @resp: KVM_VMI_RESPONSE_* bitmask from userspace.
 *
 * If REINJECT: Inject #BP into the guest so its IDT handler fires.
 * Otherwise: Do nothing. The agent is responsible for advancing RIP
 *   past the INT3 via SET_REGS when it wants to consume the breakpoint.
 */
static void handle_bp_response(struct kvm_vcpu *vcpu, u32 resp)
{
	struct kvm_vcpu_vmi *vcpu_vmi = vcpu->vmi;

	if (resp & KVM_VMI_RESPONSE_REINJECT) {
		vcpu->arch.event_exit_inst_len = vcpu_vmi->arch.bp_insn_length;
		kvm_queue_exception(vcpu, BP_VECTOR);
	}
}

/**
 * handle_debug_response - Handle debug exception event response
 * @vcpu: The vCPU re-entering after a debug exception event.
 * @resp: KVM_VMI_RESPONSE_* bitmask from userspace.
 *
 * If REINJECT: Inject #DB into the guest with the original DR6 value
 * so its IDT handler fires.
 * If CONTINUE: Set the Resume Flag (RF) in guest RFLAGS so the CPU
 * skips code breakpoints for one instruction, allowing the faulting
 * instruction to execute without re-triggering #DB. The CPU clears
 * RF automatically after one instruction.
 *
 * Return: 0 on success.
 */
static void handle_debug_response(struct kvm_vcpu *vcpu, u32 resp)
{
	if (resp & KVM_VMI_RESPONSE_REINJECT) {
		struct kvm_vcpu_vmi *vcpu_vmi = vcpu->vmi;

		kvm_queue_exception_p(vcpu, DB_VECTOR, vcpu_vmi->arch.dbg_dr6);
		return;
	}

	if (!(resp & KVM_VMI_RESPONSE_DENY))
		kvm_set_rflags(vcpu, kvm_get_rflags(vcpu) | X86_EFLAGS_RF);
}

/**
 * handle_desc_response - Handle descriptor access event response
 * @vcpu: The vCPU re-entering after a descriptor access event.
 * @resp: KVM_VMI_RESPONSE_* bitmask from userspace.
 *
 * EMULATE: Emulate descriptor instruction (apply + advance RIP).
 * DENY: Advance RIP without emulating.
 * SET_REGS: Agent controls everything.
 */
static void handle_desc_response(struct kvm_vcpu *vcpu, u32 resp)
{
	if (resp & KVM_VMI_RESPONSE_SET_REGS)
		return;

	if (resp & KVM_VMI_RESPONSE_EMULATE)
		vmi_emulate_insn(vcpu);
	else if (resp & KVM_VMI_RESPONSE_DENY)
		kvm_skip_emulated_instruction(vcpu);
}

/**
 * handle_io_response - Handle I/O event response
 * @vcpu: The vCPU re-entering after an I/O event.
 * @resp: KVM_VMI_RESPONSE_* bitmask from userspace.
 *
 * IO uses deferred-write pattern (like CR/MSR):
 * CONTINUE (0): IO proceeds (caller handles it). Default.
 * DENY: Advance RIP without emulating (I/O suppressed).
 * SET_REGS: Agent controls everything.
 */
static void handle_io_response(struct kvm_vcpu *vcpu, u32 resp)
{
	if (resp & KVM_VMI_RESPONSE_SET_REGS)
		return;

	if (resp & KVM_VMI_RESPONSE_DENY)
		kvm_skip_emulated_instruction(vcpu);
}

/**
 * handle_emulate - Emulate faulting instruction for ACTION_EMULATE
 * @vcpu: The vCPU that received ACTION_EMULATE response.
 *
 * Called when userspace returns ACTION_EMULATE after a mem_access event.
 * The emulator executes the instruction that triggered the EPT violation
 * using KVM's software emulation, reading/writing guest memory through the
 * host mapping (bypassing the alternate view's EPT restrictions).
 *
 * On failure, sets vcpu->run->exit_reason to KVM_EXIT_INTERNAL_ERROR
 * so KVM exits to userspace.
 */
static void handle_emulate(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_vmi *vcpu_vmi = vcpu->vmi;
	int r;

	r = x86_emulate_instruction(vcpu, vcpu_vmi->arch.emul_gpa,
				    EMULTYPE_PF | EMULTYPE_ALLOW_RETRY_PF,
				    NULL, 0);
	if (r >= 0)
		return; /* Success or needs userspace (kvm_run already set) */

	/* Emulation failed */
	vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
	vcpu->run->internal.suberror = KVM_INTERNAL_ERROR_EMULATION;
	vcpu->run->internal.ndata = 0;
}

/**
 * handle_hypercall_response - Handle hypercall event response
 * @vcpu: The vCPU re-entering after a hypercall event.
 * @resp: KVM_VMI_RESPONSE_* bitmask from userspace.
 *
 * Deferred pattern: CONTINUE/EMULATE let the normal hypercall handler run
 * (handled by kvm_vmi_hypercall returning 0). DENY advances RIP past the
 * VMCALL/VMMCALL instruction. SET_REGS means the agent controls everything.
 */
static void handle_hypercall_response(struct kvm_vcpu *vcpu, u32 resp)
{
	if (resp & KVM_VMI_RESPONSE_SET_REGS)
		return;

	if (resp & KVM_VMI_RESPONSE_DENY)
		kvm_skip_emulated_instruction(vcpu);
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
	case KVM_VMI_EVENT_MEM_ACCESS:
		if (resp & KVM_VMI_RESPONSE_EMULATE)
			handle_emulate(vcpu);
		break;
	case KVM_VMI_EVENT_SINGLESTEP:
		/* No special response handling for singlestep */
		break;
	case KVM_VMI_EVENT_HYPERCALL:
		handle_hypercall_response(vcpu, resp);
		break;
	case KVM_VMI_EVENT_CR:
		handle_cr_response(vcpu, resp);
		break;
	case KVM_VMI_EVENT_MSR:
		handle_msr_response(vcpu, resp);
		break;
	case KVM_VMI_EVENT_CPUID:
		handle_cpuid_response(vcpu, resp);
		break;
	case KVM_VMI_EVENT_BREAKPOINT:
		handle_bp_response(vcpu, resp);
		break;
	case KVM_VMI_EVENT_DEBUG:
		handle_debug_response(vcpu, resp);
		break;
	case KVM_VMI_EVENT_DESC_ACCESS:
		handle_desc_response(vcpu, resp);
		break;
	case KVM_VMI_EVENT_IO:
		handle_io_response(vcpu, resp);
		break;
	default:
		break;
	}
}

/**
 * kvm_vmi_inject_event - Inject an exception, interrupt, or NMI
 * @vcpu: The target vCPU.
 * @inject: Injection parameters from userspace.
 *
 * Type values match the VMCS VM-entry interruption-information field encoding.
 * Uses KVM's standard injection helpers to queue the event.
 *
 * Return: 0 on success, -EINVAL for invalid parameters.
 */
int kvm_vmi_inject_event(struct kvm_vcpu *vcpu,
			 struct kvm_vmi_inject_event *inject)
{
	if (inject->pad)
		return -EINVAL;

	switch (inject->type) {
	case KVM_VMI_EVENT_TYPE_HW_EXCEPT:
		if (inject->vector > 31)
			return -EINVAL;
		if (inject->insn_len != 0)
			return -EINVAL;
		/*
		 * Enforce architectural error code rules: DF, TS, NP,
		 * SS, GP, PF, AC must have error codes; all others
		 * must not.
		 */
		if (inject->has_error !=
		    x86_exception_has_error_code(inject->vector))
			return -EINVAL;
		if (inject->vector == PF_VECTOR) {
			kvm_queue_exception_e_p(vcpu, PF_VECTOR,
						inject->error_code,
						inject->cr2);
		} else if (inject->has_error) {
			kvm_queue_exception_e(vcpu, inject->vector,
					      inject->error_code);
		} else {
			kvm_queue_exception(vcpu, inject->vector);
		}
		break;
	case KVM_VMI_EVENT_TYPE_SW_EXCEPT:
		/*
		 * Software exceptions: #BP (INT3, vector 3) and
		 * #OF (INTO, vector 4). Requires insn_len for the
		 * VMCS VM-entry instruction length field.
		 */
		if (inject->vector != BP_VECTOR &&
		    inject->vector != OF_VECTOR)
			return -EINVAL;
		if (inject->insn_len < 1 || inject->insn_len > 15)
			return -EINVAL;
		if (inject->has_error)
			return -EINVAL;
		vcpu->arch.event_exit_inst_len = inject->insn_len;
		kvm_queue_exception(vcpu, inject->vector);
		break;
	case KVM_VMI_EVENT_TYPE_NMI:
		if (inject->insn_len != 0)
			return -EINVAL;
		kvm_inject_nmi(vcpu);
		break;
	case KVM_VMI_EVENT_TYPE_EXT_INT:
		/*
		 * External interrupt - any vector 0-255, delivered as
		 * a hardware interrupt (not soft). No insn_len needed.
		 *
		 * Intel SDM 26.3.1.4 requires RFLAGS.IF=1 for VM-entry
		 * injection of external interrupts. Check here rather
		 * than failing with a cryptic VM-entry failure.
		 */
		if (inject->insn_len != 0)
			return -EINVAL;
		if (!(kvm_get_rflags(vcpu) & X86_EFLAGS_IF))
			return -EBUSY;
		kvm_queue_interrupt(vcpu, inject->vector, false);
		kvm_make_request(KVM_REQ_EVENT, vcpu);
		break;
	case KVM_VMI_EVENT_TYPE_SW_INT:
		/*
		 * Software interrupt (INT nn) - any vector 0-255.
		 * Requires insn_len for VMCS VM-entry instruction
		 * length. Uses KVM's soft interrupt injection path.
		 *
		 * SDM 26.3.1.5 prohibits injection of SW_INT when
		 * blocking by STI or MOV SS is active.
		 */
		if (inject->insn_len < 1 || inject->insn_len > 15)
			return -EINVAL;
		vcpu->arch.event_exit_inst_len = inject->insn_len;
		kvm_queue_interrupt(vcpu, inject->vector, true);
		kvm_make_request(KVM_REQ_EVENT, vcpu);
		break;
	case KVM_VMI_EVENT_TYPE_PRIV_SW_INT:
		return -EOPNOTSUPP;
	default:
		return -EINVAL;
	}

	return 0;
}

bool kvm_arch_vmi_supported(void)
{
	return kvm_x86_call(vmi_has_cap)();
}

void kvm_arch_vmi_session_init(struct kvm_vmi *vmi)
{
	xa_init(&vmi->arch.msr_monitor);
}

void kvm_arch_vmi_session_cleanup(struct kvm_vmi *vmi)
{
	xa_destroy(&vmi->arch.msr_monitor);
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
	unsigned long index;
	void *entry;

	memset(vmi->arch.cr_monitor, 0, sizeof(vmi->arch.cr_monitor));
	xa_for_each(&vmi->arch.msr_monitor, index, entry)
		xa_erase(&vmi->arch.msr_monitor, index);
}

/*
 * Check whether any CR index is still monitored.
 */
static bool vmi_any_cr_enabled(struct kvm_vmi *vmi)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(vmi->arch.cr_monitor); i++) {
		if (vmi->arch.cr_monitor[i].enabled)
			return true;
	}
	return false;
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
	struct kvm_vmi *vmi = kvm->vmi;
	int idx;

	switch (ctrl->event) {
	case KVM_VMI_EVENT_CR:
		idx = vmi_cr_index(ctrl->arch.cr.index);
		if (idx < 0)
			return -EINVAL;
		if (ctrl->enable) {
			vmi->arch.cr_monitor[idx].enabled = true;
			vmi->arch.cr_monitor[idx].onchangeonly =
				ctrl->arch.cr.onchangeonly;
			vmi->arch.cr_monitor[idx].bitmask = ctrl->arch.cr.bitmask;
			vmi->enabled_events |= BIT_ULL(ctrl->event);
		} else {
			vmi->arch.cr_monitor[idx].enabled = false;
			if (!vmi_any_cr_enabled(vmi))
				vmi->enabled_events &= ~BIT_ULL(ctrl->event);
		}
		break;
	case KVM_VMI_EVENT_MSR:
		if (ctrl->enable) {
			xa_store(&vmi->arch.msr_monitor, ctrl->arch.msr.msr,
				 xa_mk_value(ctrl->arch.msr.onchangeonly),
				 GFP_KERNEL);
			vmi->enabled_events |= BIT_ULL(ctrl->event);
		} else {
			xa_erase(&vmi->arch.msr_monitor, ctrl->arch.msr.msr);
			if (xa_empty(&vmi->arch.msr_monitor))
				vmi->enabled_events &= ~BIT_ULL(ctrl->event);
		}
		break;
	default:
		return -EOPNOTSUPP; /* Not handled by arch; fall through to generic */
	}

	kvm_arch_vmi_update(kvm);
	return 0;
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

void kvm_arch_vmi_set_singlestep(struct kvm_vcpu *vcpu, bool enable)
{
	kvm_x86_call(vmi_set_singlestep)(vcpu, enable);
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
	struct kvm_vcpu_vmi *vcpu_vmi = vcpu->vmi;

	if (vcpu_vmi) {
		vcpu_vmi->arch.singlestep_active = false;
		vcpu_vmi->fast_singlestep_active = false;
	}
}

int kvm_arch_vmi_create_view(struct kvm *kvm, struct kvm_vmi_view_data *view)
{
	return kvm_x86_call(vmi_create_view)(kvm, view);
}

void kvm_arch_vmi_destroy_view(struct kvm *kvm, struct kvm_vmi_view_data *view)
{
	kvm_x86_call(vmi_destroy_view)(kvm, view);
}

void kvm_arch_vmi_switch_view(struct kvm_vcpu *vcpu,
			      struct kvm_vmi_view_data *view)
{
	kvm_x86_call(vmi_switch_view)(vcpu, view);
}

void kvm_arch_vmi_reset_view(struct kvm_vcpu *vcpu)
{
	kvm_make_request(KVM_REQ_LOAD_MMU_PGD, vcpu);
}

bool kvm_arch_vmi_view_has_root(struct kvm_vmi_view_data *view)
{
	return view->arch.tdp_root != NULL;
}

void kvm_arch_vmi_invalidate_gfn(struct kvm *kvm,
				 struct kvm_vmi_view_data *view, gfn_t gfn)
{
	write_lock(&kvm->mmu_lock);
	kvm_tdp_mmu_zap_vmi_leaf(kvm, view->arch.tdp_root, gfn);
	write_unlock(&kvm->mmu_lock);
}

void kvm_arch_vmi_invalidate_gfn_locked(struct kvm *kvm,
					 struct kvm_vmi_view_data *view,
					 gfn_t gfn)
{
	kvm_tdp_mmu_zap_vmi_leaf(kvm, view->arch.tdp_root, gfn);
}

void kvm_arch_vmi_invalidate_gfn_revert(struct kvm *kvm,
					struct kvm_vmi_view_data *view,
					gfn_t gfn)
{
	gfn_t block_start, block_end;
	bool block_has_remaps = false;
	unsigned long idx;
	void *entry;

	write_lock(&kvm->mmu_lock);

	/* Zap old mapping so next fault installs from host */
	kvm_tdp_mmu_zap_vmi_leaf(kvm, view->arch.tdp_root, gfn);

	/*
	 * If no other remaps exist in the same 2MB block,
	 * zap the level-2 non-leaf SPTE to allow subsequent
	 * faults to install 2MB huge pages again.
	 */
	block_start = gfn & ~(KVM_PAGES_PER_HPAGE(PG_LEVEL_2M) - 1);
	block_end = block_start + KVM_PAGES_PER_HPAGE(PG_LEVEL_2M);
	xa_for_each_range(&view->gfn_overrides, idx, entry,
			  block_start, block_end - 1) {
		block_has_remaps = true;
		break;
	}
	if (!block_has_remaps)
		kvm_tdp_mmu_zap_vmi_2m_block(kvm, view->arch.tdp_root, gfn);

	write_unlock(&kvm->mmu_lock);
}

/**
 * kvm_vmi_event_enabled - Check if a VMI event can be delivered.
 * @vcpu: The vCPU to check.
 * @event_type: The KVM_VMI_EVENT_* type to check.
 *
 * Returns true if the vCPU has VMI state, the event type is enabled,
 * and a ring is set up for delivery.
 */
static inline bool kvm_vmi_event_enabled(struct kvm_vcpu *vcpu, u32 event_type)
{
	struct kvm_vmi *vmi = kvm_vmi_get(vcpu->kvm);

	return vmi && (vmi->enabled_events & BIT_ULL(event_type))
		&& vcpu->vmi && vcpu->vmi->ring;
}

/* VMCS intercept queries */

bool kvm_vmi_cr3_intercept(struct kvm *kvm)
{
	struct kvm_vmi *vmi = kvm_vmi_get(kvm);

	return vmi && vmi->arch.cr_monitor[KVM_VMI_CR_IDX_CR3].enabled;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_vmi_cr3_intercept);

bool kvm_vmi_bp_intercept(struct kvm *kvm)
{
	struct kvm_vmi *vmi = kvm_vmi_get(kvm);

	return vmi && (vmi->enabled_events & BIT_ULL(KVM_VMI_EVENT_BREAKPOINT));
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_vmi_bp_intercept);

bool kvm_vmi_desc_intercept(struct kvm *kvm)
{
	struct kvm_vmi *vmi = kvm_vmi_get(kvm);

	return vmi && (vmi->enabled_events & BIT_ULL(KVM_VMI_EVENT_DESC_ACCESS));
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_vmi_desc_intercept);

/* Event handlers */

/**
 * kvm_vmi_singlestep - Handle an MTF VM-exit for VMI singlestepping
 * @vcpu: The vCPU that triggered the MTF exit.
 *
 * Called from handle_monitor_trap() when VMI singlestepping is active.
 * Disables MTF (one-shot behavior). If this was a fast singlestep
 * (SINGLESTEP_FAST response), switches back to the original view and
 * suppresses the singlestep event. Otherwise delivers the event via ring.
 */
int kvm_vmi_singlestep(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_vmi *vcpu_vmi = vcpu->vmi;
	struct kvm_vmi_ring_event ring_event = {};
	struct x86_exception exception;
	gva_t rip;
	gpa_t gpa;

	/* Disable MTF (one-shot: fires once per enable) */
	kvm_arch_vmi_set_singlestep(vcpu, false);

	/*
	 * Fast singlestep: the guest executed one instruction in the
	 * target view. Switch back to the original view and suppress
	 * the singlestep event.
	 */
	if (vcpu_vmi->fast_singlestep_active) {
		kvm_vmi_vcpu_switch_view(vcpu,
					 vcpu_vmi->fast_singlestep_restore_view);
		vcpu_vmi->fast_singlestep_active = false;
		return 1;
	}

	/* Deliver singlestep event if monitoring is enabled */
	if (!kvm_vmi_event_enabled(vcpu, KVM_VMI_EVENT_SINGLESTEP))
		return 1; /* Resume guest */

	rip = kvm_get_linear_rip(vcpu);
	gpa = kvm_mmu_gva_to_gpa_fetch(vcpu, rip, &exception);

	ring_event.type = KVM_VMI_EVENT_SINGLESTEP;
	ring_event.vcpu_id = vcpu->vcpu_id;
	ring_event.singlestep.gpa = gpa;
	trace_kvm_vmi_event_deliver(vcpu->vcpu_id, KVM_VMI_EVENT_SINGLESTEP, gpa);
	kvm_vmi_deliver_via_ring(vcpu, &ring_event);
	return 1;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_vmi_singlestep);

/**
 * kvm_vmi_hypercall - Check if a hypercall should generate a VMI event
 * @vcpu: The vCPU executing the hypercall (VMCALL/VMMCALL).
 *
 * Called from kvm_emulate_hypercall() after Xen/HV dispatch.
 * Uses the deferred pattern: returns 0 to let the caller proceed
 * with normal hypercall handling, or 1 if the event was handled
 * (DENY/SET_REGS).
 *
 * Return: 0 (caller proceeds with normal hypercall handling),
 *         1 (handled - caller returns immediately).
 */
int kvm_vmi_hypercall(struct kvm_vcpu *vcpu)
{
	struct kvm_vmi_ring_event ring_event = {};
	int ret;

	if (!kvm_vmi_event_enabled(vcpu, KVM_VMI_EVENT_HYPERCALL))
		return 0;

	ring_event.type = KVM_VMI_EVENT_HYPERCALL;
	ring_event.vcpu_id = vcpu->vcpu_id;
	ring_event.insn_len = kvm_x86_call(vmi_get_instruction_len)(vcpu);
	trace_kvm_vmi_event_deliver(vcpu->vcpu_id, KVM_VMI_EVENT_HYPERCALL, 0);
	ret = kvm_vmi_deliver_via_ring(vcpu, &ring_event);
	/* Deferred: return 0 (caller proceeds) unless DENY or SET_REGS */
	return (ret > 0 && (ret & (KVM_VMI_RESPONSE_DENY |
				   KVM_VMI_RESPONSE_SET_REGS))) ? 1 : 0;
}

/**
 * kvm_vmi_cr_write - Check if a CR write should generate a VMI event
 * @vcpu: The vCPU performing the CR write.
 * @cr_num: The CR number being written (0, 3, or 4).
 * @old_val: The current CR value before the write.
 * @new_val: The value being written to the CR.
 *
 * Called from the VMX CR access exit handler BEFORE the CR write is applied.
 * If an event should be generated, delivers it via the per-vCPU ring.
 *
 * Return: 0 (CONTINUE - let caller apply the CR write),
 *         1 (DENY - caller skips the CR write),
 *         negative errno on error.
 */
int kvm_vmi_cr_write(struct kvm_vcpu *vcpu, int cr_num, u64 old_val,
		     u64 new_val)
{
	struct kvm_vmi *vmi = kvm_vmi_get(vcpu->kvm);
	struct kvm_vcpu_vmi *vcpu_vmi = vcpu->vmi;
	struct kvm_vmi_ring_event ring_event = {};
	int cr_index, ret;

	if (!kvm_vmi_event_enabled(vcpu, KVM_VMI_EVENT_CR))
		return 0;

	cr_index = vmi_cr_index(cr_num);
	if (cr_index < 0)
		return 0;

	if (!vmi->arch.cr_monitor[cr_index].enabled)
		return 0;

	/* onchangeonly filter */
	if (vmi->arch.cr_monitor[cr_index].onchangeonly && old_val == new_val)
		return 0;

	/* bitmask filter: only trigger if changed bits overlap with mask */
	if (vmi->arch.cr_monitor[cr_index].onchangeonly &&
	    vmi->arch.cr_monitor[cr_index].bitmask &&
	    !((old_val ^ new_val) & vmi->arch.cr_monitor[cr_index].bitmask))
		return 0;

	/* Save state for DENY/CONTINUE response handling (per-vCPU) */
	vcpu_vmi->arch.cr_event_cr_num = cr_num;
	vcpu_vmi->arch.cr_event_old_val = old_val;
	vcpu_vmi->arch.cr_event_new_val = new_val;

	ring_event.type = KVM_VMI_EVENT_CR;
	ring_event.vcpu_id = vcpu->vcpu_id;
	ring_event.insn_len = kvm_x86_call(vmi_get_instruction_len)(vcpu);
	ring_event.arch.cr.index = cr_num;
	ring_event.arch.cr.old_value = old_val;
	ring_event.arch.cr.new_value = new_val;
	trace_kvm_vmi_event_deliver(vcpu->vcpu_id, KVM_VMI_EVENT_CR, new_val);
	ret = kvm_vmi_deliver_via_ring(vcpu, &ring_event);
	/* Deferred-write: return 0 (caller applies write) unless DENY */
	return (ret > 0 && (ret & KVM_VMI_RESPONSE_DENY)) ? 1 : 0;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_vmi_cr_write);

/**
 * kvm_vmi_msr_write - Check if an MSR write should generate a VMI event
 * @vcpu: The vCPU performing the MSR write.
 * @msr: The MSR index being written.
 * @old_val: The current MSR value before the write.
 * @new_val: The value being written to the MSR.
 *
 * Called from __kvm_emulate_wrmsr() BEFORE the MSR write is applied.
 *
 * Return: 0 (CONTINUE - let caller apply the MSR write),
 *         1 (DENY - caller skips the MSR write),
 *         negative errno on error.
 */
int kvm_vmi_msr_write(struct kvm_vcpu *vcpu, u32 msr, u64 old_val,
		       u64 new_val)
{
	struct kvm_vmi *vmi = kvm_vmi_get(vcpu->kvm);
	struct kvm_vmi_ring_event ring_event = {};
	void *entry;
	bool onchangeonly;
	int ret;

	if (!kvm_vmi_event_enabled(vcpu, KVM_VMI_EVENT_MSR))
		return 0;

	/* Check if this MSR is monitored */
	entry = xa_load(&vmi->arch.msr_monitor, msr);
	if (!entry)
		return 0;

	onchangeonly = xa_to_value(entry);

	/* onchangeonly filter */
	if (onchangeonly && old_val == new_val)
		return 0;

	ring_event.type = KVM_VMI_EVENT_MSR;
	ring_event.vcpu_id = vcpu->vcpu_id;
	ring_event.insn_len = kvm_x86_call(vmi_get_instruction_len)(vcpu);
	ring_event.arch.msr.index = msr;
	ring_event.arch.msr.old_value = old_val;
	ring_event.arch.msr.new_value = new_val;
	trace_kvm_vmi_event_deliver(vcpu->vcpu_id, KVM_VMI_EVENT_MSR, msr);
	ret = kvm_vmi_deliver_via_ring(vcpu, &ring_event);
	/* Deferred-write: return 0 (caller applies write) unless DENY */
	return (ret > 0 && (ret & KVM_VMI_RESPONSE_DENY)) ? 1 : 0;
}

/**
 * kvm_vmi_cpuid - Check if a CPUID instruction should generate a VMI event
 * @vcpu: The vCPU executing CPUID.
 * @leaf: The CPUID leaf (EAX value).
 * @subleaf: The CPUID subleaf (ECX value).
 *
 * Called from kvm_emulate_cpuid() BEFORE the CPUID is executed.
 *
 * Return: 0 (let caller execute CPUID normally),
 *         1 (handled - instruction skipped or exception pending),
 *         negative errno on error.
 */
int kvm_vmi_cpuid(struct kvm_vcpu *vcpu, u32 leaf, u32 subleaf)
{
	struct kvm_vmi_ring_event ring_event = {};

	if (!kvm_vmi_event_enabled(vcpu, KVM_VMI_EVENT_CPUID))
		return 0;

	ring_event.type = KVM_VMI_EVENT_CPUID;
	ring_event.vcpu_id = vcpu->vcpu_id;
	ring_event.insn_len = kvm_x86_call(vmi_get_instruction_len)(vcpu);
	ring_event.arch.cpuid.leaf = leaf;
	ring_event.arch.cpuid.subleaf = subleaf;
	trace_kvm_vmi_event_deliver(vcpu->vcpu_id, KVM_VMI_EVENT_CPUID, leaf);
	kvm_vmi_deliver_via_ring(vcpu, &ring_event);
	return 1; /* Response handler controls emulation via flags */
}

/**
 * kvm_vmi_breakpoint - Check if an INT3 should generate a VMI event
 * @vcpu: The vCPU that hit the INT3.
 *
 * Called from handle_exception_nmi() when a #BP exception is intercepted
 * and VMI breakpoint monitoring is enabled.
 */
int kvm_vmi_breakpoint(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_vmi *vcpu_vmi = vcpu->vmi;
	struct kvm_vmi_ring_event ring_event = {};
	struct x86_exception exception;
	u32 insn_len;
	gva_t rip;
	gpa_t gpa;

	if (!kvm_vmi_event_enabled(vcpu, KVM_VMI_EVENT_BREAKPOINT))
		return 0;

	insn_len = kvm_x86_call(vmi_get_instruction_len)(vcpu);
	rip = kvm_get_linear_rip(vcpu);
	gpa = kvm_mmu_gva_to_gpa_fetch(vcpu, rip, &exception);

	/* Save for potential REINJECT response */
	vcpu_vmi->arch.bp_insn_length = insn_len;

	ring_event.type = KVM_VMI_EVENT_BREAKPOINT;
	ring_event.vcpu_id = vcpu->vcpu_id;
	ring_event.insn_len = insn_len;
	ring_event.arch.breakpoint.gpa = gpa;
	trace_kvm_vmi_event_deliver(vcpu->vcpu_id, KVM_VMI_EVENT_BREAKPOINT, gpa);
	return kvm_vmi_deliver_via_ring(vcpu, &ring_event) >= 0;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_vmi_breakpoint);

/**
 * kvm_vmi_debug_exception - Check if a #DB should generate a VMI event
 * @vcpu: The vCPU that hit the #DB.
 * @dr6: The DR6 exit qualification value.
 *
 * Called from handle_exception_nmi() when VMI debug monitoring is enabled
 * and the #DB is not ICEBP and not from guest debug mode.
 */
int kvm_vmi_debug_exception(struct kvm_vcpu *vcpu, u64 dr6)
{
	struct kvm_vcpu_vmi *vcpu_vmi = vcpu->vmi;
	struct kvm_vmi_ring_event ring_event = {};
	struct x86_exception exception;
	gva_t rip;
	gpa_t gpa;

	if (!kvm_vmi_event_enabled(vcpu, KVM_VMI_EVENT_DEBUG))
		return 0;

	/* Save for potential REINJECT response */
	vcpu_vmi->arch.dbg_dr6 = dr6;

	rip = kvm_get_linear_rip(vcpu);
	gpa = kvm_mmu_gva_to_gpa_fetch(vcpu, rip, &exception);

	ring_event.type = KVM_VMI_EVENT_DEBUG;
	ring_event.vcpu_id = vcpu->vcpu_id;
	ring_event.arch.debug.pending_dbg = dr6;
	ring_event.arch.debug.gpa = gpa;
	trace_kvm_vmi_event_deliver(vcpu->vcpu_id, KVM_VMI_EVENT_DEBUG, dr6);
	return kvm_vmi_deliver_via_ring(vcpu, &ring_event) >= 0;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_vmi_debug_exception);

/**
 * kvm_vmi_desc_access - Check if a descriptor access should generate a VMI event
 * @vcpu: The vCPU performing the descriptor access.
 * @descriptor: Descriptor type (KVM_VMI_DESC_GDTR/IDTR/LDTR/TR).
 * @is_write: 1 for load (LGDT/LIDT/LLDT/LTR), 0 for store (SGDT/SIDT/SLDT/STR).
 *
 * Called from handle_desc() when VMI descriptor access monitoring is enabled.
 */
int kvm_vmi_desc_access(struct kvm_vcpu *vcpu, u8 descriptor, u8 is_write)
{
	struct kvm_vmi_ring_event ring_event = {};

	if (!kvm_vmi_event_enabled(vcpu, KVM_VMI_EVENT_DESC_ACCESS))
		return 0;

	ring_event.type = KVM_VMI_EVENT_DESC_ACCESS;
	ring_event.vcpu_id = vcpu->vcpu_id;
	ring_event.insn_len = kvm_x86_call(vmi_get_instruction_len)(vcpu);
	ring_event.arch.desc_access.descriptor = descriptor;
	ring_event.arch.desc_access.is_write = is_write;
	trace_kvm_vmi_event_deliver(vcpu->vcpu_id, KVM_VMI_EVENT_DESC_ACCESS,
				    descriptor);
	return kvm_vmi_deliver_via_ring(vcpu, &ring_event) >= 0;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_vmi_desc_access);

/**
 * kvm_vmi_io - Check if an I/O instruction should generate a VMI event
 * @vcpu: The vCPU performing the I/O.
 * @bytes: Number of bytes (1, 2, or 4).
 * @port: I/O port number.
 * @in: 1 for IN, 0 for OUT.
 * @string: 1 for string I/O (INS/OUTS), 0 for scalar.
 *
 * Called from handle_io() when VMI I/O monitoring is enabled.
 *
 * Return: 0 (caller proceeds with IO) or 1 (DENY - caller skips IO).
 */
int kvm_vmi_io(struct kvm_vcpu *vcpu, u32 bytes, u16 port, u8 in, u8 string)
{
	struct kvm_vmi_ring_event ring_event = {};
	int ret;

	if (!kvm_vmi_event_enabled(vcpu, KVM_VMI_EVENT_IO))
		return 0;

	ring_event.type = KVM_VMI_EVENT_IO;
	ring_event.vcpu_id = vcpu->vcpu_id;
	ring_event.insn_len = kvm_x86_call(vmi_get_instruction_len)(vcpu);
	ring_event.arch.io.port = port;
	ring_event.arch.io.bytes = bytes;
	ring_event.arch.io.in = in;
	ring_event.arch.io.string = string;
	trace_kvm_vmi_event_deliver(vcpu->vcpu_id, KVM_VMI_EVENT_IO, port);
	ret = kvm_vmi_deliver_via_ring(vcpu, &ring_event);
	/* Deferred: return 0 (caller handles IO) unless DENY */
	return (ret > 0 && (ret & KVM_VMI_RESPONSE_DENY)) ? 1 : 0;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_vmi_io);

/* Memory access */

/*
 * Get the access permissions for a GFN in a view.
 * Returns the explicit override if set, otherwise the view's default.
 */
static u8 vmi_resolve_access(struct kvm_vmi_view_data *view, gfn_t gfn)
{
	void *entry;

	entry = xa_load(&view->access_overrides, gfn);
	if (entry)
		return (u8)xa_to_value(entry);

	return view->default_access;
}

/*
 * Check if an EPT violation on an alternate view is an access violation
 * that should be reported to the VMI agent. Called from handle_ept_violation()
 * before entering the TDP MMU fault path.
 *
 * Returns:
 *   1 - Access violation, event delivered, don't install SPTE
 *   0 - Access allowed (or page-walk lazy populate), proceed to TDP fault
 */
int kvm_vmi_check_mem_access(struct kvm_vcpu *vcpu, gpa_t gpa,
			     unsigned long exit_qual)
{
	struct kvm_vcpu_vmi *vcpu_vmi = vcpu->vmi;
	struct kvm_vmi_view_data *view = vcpu_vmi->current_view;
	gfn_t gfn = gpa >> PAGE_SHIFT;
	u8 access, required;

	if (WARN_ON(!view))
		return 0;

	/*
	 * If the SPTE is not present (PROT_MASK == 0), let the TDP MMU
	 * fault path install it with the view's configured access
	 * restrictions. Access violations can only be checked once the
	 * SPTE is present - the next fault will have PROT_MASK set,
	 * indicating the permissions that were on the existing entry.
	 */
	if (!(exit_qual & EPT_VIOLATION_PROT_MASK))
		return 0;

	access = vmi_resolve_access(view, gfn);

	required = 0;
	if (exit_qual & EPT_VIOLATION_ACC_READ)
		required |= KVM_VMI_ACCESS_R;
	if (exit_qual & EPT_VIOLATION_ACC_WRITE)
		required |= KVM_VMI_ACCESS_W;
	if (exit_qual & EPT_VIOLATION_ACC_INSTR)
		required |= KVM_VMI_ACCESS_X;

	if ((required & access) != required) {
		struct kvm_vmi_ring_event ring_event = {};

		trace_kvm_vmi_mem_violation(vcpu->vcpu_id, gpa, required,
					   access);

		/*
		 * Access violation - always deliver mem_access event.
		 * Unlike other event types, mem_access is implicitly enabled
		 * whenever a VMI session with a ring exists.  The agent must
		 * handle EPT violations (e.g. via fast singlestep) to avoid
		 * an infinite re-fault loop.
		 */
		vcpu_vmi->arch.emul_gpa = gpa;
		ring_event.type = KVM_VMI_EVENT_MEM_ACCESS;
		ring_event.vcpu_id = vcpu->vcpu_id;
		ring_event.mem_access.gpa = gpa;
		ring_event.mem_access.access = required;
		trace_kvm_vmi_event_deliver(vcpu->vcpu_id,
					    KVM_VMI_EVENT_MEM_ACCESS,
					    gpa);
		kvm_vmi_deliver_via_ring(vcpu, &ring_event);
		return 1;
	}

	return 0;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_vmi_check_mem_access);

/*
 * Prepare a page fault struct with VMI overrides for an alternate view.
 * Called from kvm_mmu_do_page_fault() after the fault struct is created.
 *
 * Sets:
 *   fault->vmi_access - View's access mask for this GFN
 *   fault->vmi_pfn/vmi_pfn_valid - Pre-resolved PFN for remapped GFNs
 */
void kvm_vmi_setup_page_fault(struct kvm_vcpu *vcpu,
			      struct kvm_page_fault *fault)
{
	struct kvm_vcpu_vmi *vcpu_vmi = vcpu->vmi;
	struct kvm_vmi_view_data *view;
	gfn_t block_start, block_end;
	unsigned long idx;
	void *remap;
	void *entry;

	if (!vcpu_vmi || vcpu_vmi->current_view_id == 0)
		return;

	view = READ_ONCE(vcpu_vmi->current_view);
	if (!view)
		return;

	/* Set access restriction from view */
	fault->vmi_access = vmi_resolve_access(view, fault->gfn);

	/* Check for GFN remap (change_gfn) */
	remap = xa_load(&view->gfn_overrides, fault->gfn);
	if (remap) {
		fault->vmi_pfn = ((hpa_t)(unsigned long)remap) >> PAGE_SHIFT;
		fault->vmi_pfn_valid = true;
		fault->max_level = PG_LEVEL_4K;
	}

	/*
	 * If a GFN override exists in the same 2MB-aligned block as
	 * the faulting GFN, limit to 4K pages. A 2MB SPTE would
	 * cover the remapped GFN with the original (non-shadow)
	 * mapping, bypassing the remap check which only fires on
	 * per-GFN EPT violations.
	 *
	 * Only restrict the specific 2MB block, not the entire view,
	 * to avoid massive TLB pressure from global 4K enforcement.
	 */
	if (!remap && fault->max_level > PG_LEVEL_4K) {
		block_start = fault->gfn & ~(KVM_PAGES_PER_HPAGE(PG_LEVEL_2M) - 1);
		block_end = block_start + KVM_PAGES_PER_HPAGE(PG_LEVEL_2M);

		xa_for_each_range(&view->gfn_overrides,
				  idx, entry, block_start, block_end - 1) {
			fault->max_level = PG_LEVEL_4K;
			break;
		}
	}
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_vmi_setup_page_fault);
