// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI singlestep monitoring test (arm64)
 *
 * Hardware software-step (MDSCR_EL1.SS + PSTATE.SS) driven by a VMI agent.
 * Singlestep is armed from an event response (KVM_VMI_RESPONSE_SINGLESTEP), not
 * an ioctl: the agent catches a BRK, responds SET_REGS+SINGLESTEP, and then
 * receives a SINGLESTEP event per stepped instruction. One-shot: the kernel
 * disarms at each step; the agent re-arms by responding SINGLESTEP again.
 *
 * test_singlestep_count    - >= 5 steps over a NOP sled, monotonic PC (+4).
 * test_singlestep_disable  - one step then CONTINUE -> no further events.
 * test_concurrent_guestdbg - VMI single-step coexists with userspace
 *                            KVM_GUESTDBG_SINGLESTEP on the same vCPU.
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

static void guest_bp_then_nops(void)
{
	GUEST_SYNC(1);
	/* BRK -> breakpoint event; the NOP sled is single-stepped. */
	asm volatile(
		"brk #0x7\n\t"
		"nop\n\t" "nop\n\t" "nop\n\t" "nop\n\t"
		"nop\n\t" "nop\n\t" "nop\n\t" "nop\n\t");
	GUEST_SYNC(2);
	GUEST_DONE();
}

/* >= 5 single-steps over the NOP sled; PC advances by exactly 4 each step. */
static void test_singlestep_count(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	uint64_t prev_pc = 0;
	int vmi_fd, ss_count = 0;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_bp_then_nops, &ring);
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_BREAKPOINT, 1);
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_SINGLESTEP, 1);

	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

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

		/* Each step is one 4-byte instruction forward. */
		if (prev_pc)
			TEST_ASSERT(ev->regs.pc == prev_pc + 4,
				    "Step PC must advance by 4: prev 0x%lx now 0x%llx",
				    prev_pc, ev->regs.pc);
		prev_pc = ev->regs.pc;

		/*
		 * IPA payload is nonzero and its page offset tracks the PC: the
		 * kernel derives the offset 4K-granular, never with the 16K host
		 * PAGE_MASK.
		 */
		TEST_ASSERT(ev->singlestep.gpa != 0, "Expected nonzero step gpa");
		TEST_ASSERT((ev->singlestep.gpa & 0xfff) == (ev->regs.pc & 0xfff),
			    "gpa offset 0x%llx != pc offset 0x%llx",
			    ev->singlestep.gpa & 0xfff, ev->regs.pc & 0xfff);

		if (++ss_count >= 5) {
			ev->response = KVM_VMI_RESPONSE_CONTINUE;
			vmi_ack_event(&ring, 0);
			break;
		}
		ev->response = KVM_VMI_RESPONSE_SINGLESTEP;
		vmi_ack_event(&ring, 0);
	}

	TEST_ASSERT(ss_count >= 5, "Expected >= 5 singlestep events, got %d", ss_count);

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");
	vmi_test_teardown(vm, vmi_fd, &ring);
	pr_info("PASS: vmi_singlestep count (>=5 steps, monotonic PC+4)\n");
}

/* One-shot: one step then CONTINUE -> stepping stops, no trailing events. */
static void test_singlestep_disable(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_bp_then_nops, &ring);
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_BREAKPOINT, 1);
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_SINGLESTEP, 1);

	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for breakpoint event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_BREAKPOINT,
		    "Expected breakpoint event, got %u", ev->type);

	/* Skip the BRK and arm exactly one step. */
	ev->regs.pc += ev->insn_len;
	ev->response = KVM_VMI_RESPONSE_SET_REGS | KVM_VMI_RESPONSE_SINGLESTEP;
	vmi_ack_event(&ring, 0);

	/* The one step. Respond CONTINUE (no SINGLESTEP) -> stop. */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for the singlestep event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_SINGLESTEP,
		    "Expected singlestep event, got %u", ev->type);
	ev->response = KVM_VMI_RESPONSE_CONTINUE;
	vmi_ack_event(&ring, 0);

	/* No more step events (one-shot disarm held). */
	ev = vmi_wait_event_timeout(&ring, 500);
	TEST_ASSERT(ev == NULL, "Should get no further singlestep events");

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");
	vmi_test_teardown(vm, vmi_fd, &ring);
	pr_info("PASS: vmi_singlestep disable (one-shot)\n");
}

/*
 * Coexistence with userspace KVM_GUESTDBG_SINGLESTEP (spec section 8).
 *
 * Three phases on one vCPU, proving VMI and userspace stepping don't corrupt
 * each other's software-step state:
 *   phase A: userspace KVM_GUESTDBG_SINGLESTEP steps a NOP sled (KVM_EXIT_DEBUG).
 *   phase B: a BRK bootstraps VMI single-step; the agent steps a NOP sled via
 *            the ring, in-kernel (guest_debug off -> NOT KVM_EXIT_DEBUG).
 *   phase C: userspace single-step resumes on a NOP sled (the SS state must have
 *            round-tripped through the VMI window uncorrupted).
 *
 * CRITICAL (mirrors debug-exceptions.c::test_single_step_from_userspace): a
 * userspace single-step must NEVER be active across a full ucall()/GUEST_SYNC/
 * GUEST_DONE, because ucall() allocates via test_and_set_bit (LDXR/STXR) and the
 * exclusive monitor is cleared on the ERET out of every software-step exception
 * -> STXR never succeeds -> the guest hangs with no forward progress. So phase
 * boundaries are signalled with a *bare* GUEST_UCALL_NONE() (no atomics), the
 * NOP sleds are bracketed by labels, and the host disables single-step when the
 * guest is about to leave a sled (pc + 4 == <sled>_end) -- before the guest runs
 * any atomic/ucall code. The VMI window runs with guest_debug fully cleared.
 */
static volatile int g_uspace_steps;

/* Sled end labels (defined in guest_concurrent); the host disables single-step
 * as the guest is about to leave a sled (pc + 4 == <sled>_end). */
extern unsigned char ss_a_end, ss_c_end;

struct ss_thread_arg {
	struct kvm_vcpu *vcpu;
	volatile int done;
};

static void guest_concurrent(void)
{
	/* signal 1: host enables userspace single-step for phase A. Bare ucall
	 * (no atomics) -- it runs with single-step still OFF. */
	GUEST_UCALL_NONE();
	asm volatile("ss_a_begin:\n\t"
		     "nop\n\t" "nop\n\t" "nop\n\t"
		     "nop\n\t" "nop\n\t" "nop\n\t"
		     "ss_a_end:\n\t");
	/* signal 2: hand off to VMI. Host has already disabled userspace SS at
	 * ss_a_end, so this bare ucall and the BRK run un-stepped. */
	GUEST_UCALL_NONE();
	asm volatile("brk #0x7\n\t");				/* VMI bootstrap */
	/* phase B: the VMI agent steps these 4 NOPs via the ring. */
	asm volatile("nop\n\t" "nop\n\t" "nop\n\t" "nop\n\t");
	/* signal 3: host re-enables userspace single-step for phase C. */
	GUEST_UCALL_NONE();
	asm volatile("ss_c_begin:\n\t"
		     "nop\n\t" "nop\n\t" "nop\n\t"
		     "nop\n\t" "nop\n\t" "nop\n\t"
		     "ss_c_end:\n\t");
	GUEST_DONE();		/* single-step is OFF here -> ucall() is safe */
}

static void *concurrent_vcpu_fn(void *arg)
{
	struct ss_thread_arg *a = arg;
	struct kvm_run *run = a->vcpu->run;
	struct kvm_guest_debug dbg = {};
	struct ucall uc;
	uint64_t cur_end = 0;	/* end-of-sled label while userspace SS is on */
	int signal_no = 0;

	while (!a->done) {
		vcpu_run(a->vcpu);

		if (run->exit_reason == KVM_EXIT_DEBUG) {
			uint64_t pc = vcpu_get_reg(a->vcpu,
						   ARM64_CORE_REG(regs.pc));

			g_uspace_steps++;
			/* Disable single-step before the guest leaves the sled,
			 * so the trailing bare ucall / DONE runs un-stepped. */
			if (cur_end && (pc + 4) == cur_end) {
				dbg.control = 0;
				vcpu_guest_debug_set(a->vcpu, &dbg);
				cur_end = 0;
			}
			continue;
		}

		switch (get_ucall(a->vcpu, &uc)) {
		case UCALL_NONE:
			/* Phase boundary (bare ucall, no atomics). */
			if (++signal_no == 1) {
				/* phase A: userspace single-step ON */
				dbg.control = KVM_GUESTDBG_ENABLE |
					      KVM_GUESTDBG_SINGLESTEP;
				vcpu_guest_debug_set(a->vcpu, &dbg);
				cur_end = (uint64_t)&ss_a_end;
			} else if (signal_no == 2) {
				/* hand off to VMI: clear guest_debug entirely */
				dbg.control = 0;
				vcpu_guest_debug_set(a->vcpu, &dbg);
			} else if (signal_no == 3) {
				/* phase C: userspace single-step ON again */
				dbg.control = KVM_GUESTDBG_ENABLE |
					      KVM_GUESTDBG_SINGLESTEP;
				vcpu_guest_debug_set(a->vcpu, &dbg);
				cur_end = (uint64_t)&ss_c_end;
			}
			break;
		case UCALL_DONE:
			a->done = 1;
			return NULL;
		case UCALL_ABORT:
			REPORT_GUEST_ASSERT(uc);
			return NULL;
		default:
			break;
		}
	}
	return NULL;
}

static void test_concurrent_guestdbg(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct ss_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd, vmi_steps = 0;

	g_uspace_steps = 0;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_concurrent, &ring);
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_BREAKPOINT, 1);
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_SINGLESTEP, 1);

	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, concurrent_vcpu_fn, &targ);

	/* Phase B: the VMI agent catches the BRK and steps 4 NOPs via the ring.
	 * (guest_debug is cleared here, so these do NOT exit as KVM_EXIT_DEBUG.) */
	ev = vmi_wait_event_timeout(&ring, 10000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for BRK (phase B bootstrap)");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_BREAKPOINT,
		    "Expected breakpoint, got %u", ev->type);
	ev->regs.pc += ev->insn_len;
	ev->response = KVM_VMI_RESPONSE_SET_REGS | KVM_VMI_RESPONSE_SINGLESTEP;
	vmi_ack_event(&ring, 0);

	while (vmi_steps < 4) {
		ev = vmi_wait_event_timeout(&ring, 5000);
		TEST_ASSERT(ev != NULL, "Timeout waiting for VMI step %d", vmi_steps);
		TEST_ASSERT(ev->type == KVM_VMI_EVENT_SINGLESTEP,
			    "Expected singlestep, got %u", ev->type);
		vmi_steps++;
		ev->response = (vmi_steps < 4) ? KVM_VMI_RESPONSE_SINGLESTEP
					       : KVM_VMI_RESPONSE_CONTINUE;
		vmi_ack_event(&ring, 0);
	}

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest must complete (instruction stream uncorrupted)");

	/* Coexistence invariants: VMI stepped its 4, and userspace stepped across
	 * phases A+C -- proving the SS state round-tripped through the VMI window
	 * without corruption. Each 6-NOP sled yields ~5 steps (the host disables
	 * SS as the guest leaves the sled), so >= 8 across A+C. */
	TEST_ASSERT(vmi_steps == 4, "Expected 4 VMI steps, got %d", vmi_steps);
	TEST_ASSERT(g_uspace_steps >= 8,
		    "Expected >= 8 userspace steps (phases A+C), got %d",
		    g_uspace_steps);

	vmi_test_teardown(vm, vmi_fd, &ring);
	pr_info("PASS: vmi_singlestep concurrent (userspace=%d, vmi=4)\n",
		g_uspace_steps);
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_RING));

	test_singlestep_count();
	test_singlestep_disable();
	test_concurrent_guestdbg();

	return 0;
}
