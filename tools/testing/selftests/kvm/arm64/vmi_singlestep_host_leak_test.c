// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI single-step host MDSCR_EL1.SS leak regression test (arm64)
 *
 * Confirmed host-freeze bug: under VHE the host kernel runs at EL2 and shares
 * the live MDSCR_EL1 with the guest. When a VMI agent drives a PLAIN single-step
 * (KVM_VMI_RESPONSE_SINGLESTEP), kvm_vmi_apply_singlestep() writes MDSCR_EL1.SS
 * into the live, VHE-host-shared register. On the plain-singlestep ring-block
 * vcpu_put path (and the no-guest-entry exit) the value was never restored, so
 * the physical CPU that ran KVM_RUN was left with MDSCR_EL1.SS=1 -- the host
 * single-step enable. On the real host this cascaded into a host-wide SIGTRAP
 * storm and a freeze.
 *
 * DETECTOR. MDSCR_EL1 is per-CPU, so the leak is only reachable on the CPU that
 * ran KVM_RUN. The whole process is pinned to a single CPU, so the vCPU thread
 * (KVM_RUN) and the agent thread (ring drain) share it. The plain-singlestep
 * ring-block leaves MDSCR_EL1.SS set on that CPU at vcpu_put and yields it; the
 * agent is then scheduled onto the poisoned CPU to process the event. On the
 * unpatched kernel the agent's first userspace instruction software-steps and
 * takes SIGTRAP -> the handler reports and _exit(1)s = FAIL. A SIGALRM backstop
 * catches the case where the poisoned CPU wedges instead of trapping. On the
 * patched kernel kvm_vcpu_put_debug() restores the host MDSCR_EL1, the agent
 * runs un-stepped, all steps complete and the guest reaches DONE = PASS.
 *
 * Markers go to stdout: some harnesses (virtme-ng) drop a test's stderr.
 */
#include <errno.h>
#include <linux/kvm.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

#define PIN_CPU		0	/* vCPU + agent share this CPU; it gets poisoned */
#define NR_STEPS	8	/* >= 4: force the agent onto the poisoned CPU repeatedly */
#define WATCHDOG_SECS	20	/* the workflow completes in << 1s; backstop a wedge */

static const char sigtrap_msg[] =
	"FAIL: host EL0 SIGTRAP -- MDSCR_EL1.SS leaked to the host (single-step armed)\n";
static const char sigalrm_msg[] =
	"FAIL: workflow wedged on the poisoned CPU -- MDSCR_EL1.SS leak\n";

/*
 * On SIGTRAP/SIGALRM, write a marker and _exit(1) -- a raw syscall. The task
 * leaves to the kernel before stepping resumes, so the handler terminates the
 * process cleanly even amid an active single-step storm.
 */
static void fail_handler(int sig)
{
	if (sig == SIGALRM)
		write(STDOUT_FILENO, sigalrm_msg, sizeof(sigalrm_msg) - 1);
	else
		write(STDOUT_FILENO, sigtrap_msg, sizeof(sigtrap_msg) - 1);
	_exit(1);
}

static void pin_to_cpu(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	TEST_ASSERT(sched_setaffinity(0, sizeof(set), &set) == 0,
		    "sched_setaffinity(cpu=%d) failed: %d", cpu, errno);
}

static void guest_bp_then_nops(void)
{
	GUEST_SYNC(1);
	/* BRK -> breakpoint event; the NOP sled is single-stepped. */
	asm volatile(
		"brk #0x7\n\t"
		"nop\n\t" "nop\n\t" "nop\n\t" "nop\n\t"
		"nop\n\t" "nop\n\t" "nop\n\t" "nop\n\t"
		"nop\n\t" "nop\n\t" "nop\n\t" "nop\n\t");
	GUEST_SYNC(2);
	GUEST_DONE();
}

static void test_singlestep_host_leak(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd, ss_count = 0;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_bp_then_nops, &ring);
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_BREAKPOINT, 1);
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_SINGLESTEP, 1);

	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* Catch the BRK; skip it and start stepping the NOP sled (PLAIN step). */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for breakpoint event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_BREAKPOINT,
		    "Expected breakpoint event, got %u", ev->type);
	ev->regs.pc += ev->insn_len;
	ev->response = KVM_VMI_RESPONSE_SET_REGS | KVM_VMI_RESPONSE_SINGLESTEP;
	vmi_ack_event(&ring, 0);

	/*
	 * Each iteration the agent blocks in the ring (the CPU is yielded to it
	 * after the vCPU's plain-singlestep vcpu_put), then re-arms a step. With
	 * the process pinned to one CPU the agent repeatedly resumes on the
	 * poisoned CPU; on the unpatched kernel it software-steps into SIGTRAP.
	 */
	while (!targ.done) {
		ev = vmi_wait_event_timeout(&ring, 5000);
		if (ev == NULL)
			break;
		TEST_ASSERT(ev->type == KVM_VMI_EVENT_SINGLESTEP,
			    "Expected singlestep event, got %u", ev->type);

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

	alarm(0);
	vmi_test_teardown(vm, vmi_fd, &ring);
	pr_info("PASS: no host MDSCR_EL1.SS leak (%d plain steps, same-CPU agent survived)\n",
		ss_count);
}

int main(int argc, char *argv[])
{
	struct sigaction sa = {};

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_RING));

	/* Pin everything to one CPU so the agent lands on the poisoned CPU. */
	pin_to_cpu(PIN_CPU);

	sa.sa_handler = fail_handler;
	sigemptyset(&sa.sa_mask);
	TEST_ASSERT(sigaction(SIGTRAP, &sa, NULL) == 0,
		    "sigaction(SIGTRAP) failed: %d", errno);
	TEST_ASSERT(sigaction(SIGALRM, &sa, NULL) == 0,
		    "sigaction(SIGALRM) failed: %d", errno);
	alarm(WATCHDOG_SECS);

	test_singlestep_host_leak();

	return 0;
}
