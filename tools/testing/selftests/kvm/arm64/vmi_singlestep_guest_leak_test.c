// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI single-step guest PSTATE.SS leak regression test (arm64)
 *
 * Root-caused 2026-06-06 from a Windows-on-ARM guest crash: a VMI single-step
 * over a breakpoint leaks the guest-visible hardware software-step state into
 * guest thread contexts. VMI arms MDSCR_EL1.SS + PSTATE.SS and runs ONE
 * instruction of a LIVE, preemptible guest with the step trapping to EL2
 * (MDCR_EL2.TDE). The guest is not party to the software-step protocol (unlike
 * the in-tree stepper, whose exception entry/exit hooks clear and restore
 * MDSCR_EL1.SS per stepped thread). If an interrupt is taken in the step
 * window, the guest enters its own handler with the step bit pending and
 * hardware has already saved SPSR_EL1.SS=1 into the interrupted thread's
 * context in guest RAM, beyond KVM's reach; that thread later takes a spurious
 * software-step exception (seen in a Windows guest as a stray STATUS_SINGLE_STEP
 * at an arbitrary instruction -- a user-process crash, or on a kernel-critical
 * thread a bugcheck and reset).
 *
 * The fix masks the guest's asynchronous exceptions (PSTATE.A/I/F) for the
 * one-instruction step window, mirroring the in-tree invariant that a software
 * step runs only with interrupts disabled (kernel_enable_single_step()'s
 * WARN_ON(!irqs_disabled())), and restores them when the step disarms.
 *
 * DETERMINISTIC DETECTOR (no interrupt race needed). The guest unmasks A/I/F
 * (msr daifclr, #7) before the stepped NOP sled. The SINGLESTEP event is
 * delivered from kvm_vmi_singlestep() AFTER the step traps but BEFORE the
 * disarm restores DAIF, so the event's captured PSTATE is the value the stepped
 * instruction ran with:
 *   - unpatched: A/I/F clear (the guest's own state) -- the step ran with
 *     interrupts ENABLED, the leak window, = FAIL.
 *   - patched:   A/I/F set (masked by the fix) -- the step was atomic = PASS.
 * A second assertion confirms the restore: after stepping stops the guest reads
 * its own DAIF and reports it; A/I/F must be clear again (restored), not left
 * masked by the step window.
 *
 * Markers go to stdout: some harnesses (virtme-ng) drop a test's stderr.
 */
#include <errno.h>
#include <linux/kvm.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

/* PSTATE/SPSR async-exception mask bits (D=9, A=8, I=7, F=6). */
#define PSTATE_A	(1 << 8)
#define PSTATE_I	(1 << 7)
#define PSTATE_F	(1 << 6)
#define PSTATE_AIF	(PSTATE_A | PSTATE_I | PSTATE_F)

#define NR_STEPS	5

/* Guest DAIF read back after stepping (via GUEST_SYNC_ARGS); ~0 = not seen. */
static volatile uint64_t g_guest_daif_after;

static void guest_unmask_then_step(void)
{
	uint64_t daif;

	GUEST_SYNC(1);
	/*
	 * Unmask asynchronous exceptions (DAIFClr #7 clears A, I, F; leaves D)
	 * so an unpatched kernel single-steps the NOP sled with interrupts
	 * ENABLED -- the leak window the fix closes.
	 */
	asm volatile("msr daifclr, #7");
	/* BRK -> breakpoint event; the NOP sled is single-stepped. */
	asm volatile(
		"brk #0x7\n\t"
		"nop\n\t" "nop\n\t" "nop\n\t" "nop\n\t"
		"nop\n\t" "nop\n\t" "nop\n\t" "nop\n\t");
	/*
	 * Stepping has stopped (the agent responded CONTINUE), so this read and
	 * the ucall below run un-stepped. Report DAIF: the fix must have restored
	 * the unmasked value, not left A/I/F masked.
	 */
	asm volatile("mrs %0, daif" : "=r"(daif));
	GUEST_SYNC_ARGS(2, daif, 0, 0, 0);
	GUEST_DONE();
}

/*
 * Like vmi_vcpu_thread_fn(), but capture the post-step DAIF the guest reports
 * at GUEST_SYNC stage 2 (uc.args[1] == 2, value in uc.args[2]).
 */
static void *leak_vcpu_thread_fn(void *arg)
{
	struct vmi_vcpu_thread_arg *targ = arg;
	struct ucall uc;

	while (!targ->done) {
		vcpu_run(targ->vcpu);

		switch (get_ucall(targ->vcpu, &uc)) {
		case UCALL_DONE:
			targ->done = 1;
			return NULL;
		case UCALL_ABORT:
			REPORT_GUEST_ASSERT(uc);
			return NULL;
		case UCALL_SYNC:
			if (uc.args[1] == 2)
				g_guest_daif_after = uc.args[2];
			break;
		default:
			break;
		}
	}
	return NULL;
}

static void test_singlestep_guest_leak(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd, ss_count = 0;

	g_guest_daif_after = ~0ULL;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_unmask_then_step, &ring);
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_BREAKPOINT, 1);
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_SINGLESTEP, 1);

	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, leak_vcpu_thread_fn, &targ);

	/* Catch the BRK; skip it and start stepping the NOP sled. */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for breakpoint event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_BREAKPOINT,
		    "Expected breakpoint event, got %u", ev->type);
	ev->regs.pc += ev->insn_len;
	ev->response = KVM_VMI_RESPONSE_SET_REGS | KVM_VMI_RESPONSE_SINGLESTEP;
	vmi_ack_event(&ring, 0);

	while (!targ.done) {
		ev = vmi_wait_event_timeout(&ring, 5000);
		if (ev == NULL)
			break;
		TEST_ASSERT(ev->type == KVM_VMI_EVENT_SINGLESTEP,
			    "Expected singlestep event, got %u", ev->type);

		/*
		 * THE REGRESSION ASSERTION. The captured PSTATE is the value the
		 * stepped instruction ran with (the event is delivered before the
		 * step disarms). The guest unmasked A/I/F, so without the fix they
		 * are clear here -- the step ran preemptible and an interrupt could
		 * leak SPSR.SS into a guest thread context. The fix masks them for
		 * the step window.
		 */
		TEST_ASSERT((ev->regs.pstate & PSTATE_AIF) == PSTATE_AIF,
			    "VMI single-step ran with interrupts ENABLED: pstate=0x%llx "
			    "(A/I/F must be masked for the step window, else PSTATE.SS "
			    "can leak into a guest thread context)", ev->regs.pstate);

		if (++ss_count >= NR_STEPS) {
			ev->response = KVM_VMI_RESPONSE_CONTINUE;
			vmi_ack_event(&ring, 0);
			break;
		}
		ev->response = KVM_VMI_RESPONSE_SINGLESTEP;
		vmi_ack_event(&ring, 0);
	}

	TEST_ASSERT(ss_count >= NR_STEPS,
		    "Expected >= %d singlestep events, got %d", NR_STEPS, ss_count);

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");

	/*
	 * RESTORE ASSERTION. After stepping stopped, the guest read its own DAIF.
	 * The fix restores the guest's pre-step value, so A/I/F must be clear
	 * again (the guest had unmasked them) -- not left masked by the step.
	 */
	TEST_ASSERT(g_guest_daif_after != ~0ULL,
		    "Guest never reported its post-step DAIF");
	TEST_ASSERT((g_guest_daif_after & PSTATE_AIF) == 0,
		    "Guest DAIF not restored after step: 0x%lx (A/I/F still masked)",
		    g_guest_daif_after);

	vmi_test_teardown(vm, vmi_fd, &ring);
	pr_info("PASS: no guest PSTATE.SS leak (%d steps ran A/I/F-masked, DAIF restored)\n",
		ss_count);
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_RING));

	test_singlestep_guest_leak();

	return 0;
}
