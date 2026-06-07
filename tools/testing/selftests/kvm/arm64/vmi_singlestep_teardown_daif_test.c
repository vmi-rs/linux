// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI single-step teardown DAIF-restore regression test (arm64)
 *
 * Companion to vmi_singlestep_guest_leak_test. That test proves the SS-leak fix
 * masks guest A/I/F for the step window AND restores them on a NORMAL disarm.
 * This test proves the restore also survives a SESSION TEARDOWN that lands while
 * a step is in flight -- the "DAIF teardown hang" that blocks committing the
 * SS-leak fix (see /opt/.claude/unresolved/).
 *
 * THE BUG. The VMI single-step masks the guest's DAIF (A/I/F) in *vcpu_cpsr and
 * stashes the original in the per-session vcpu->vmi->arch. The restore is left
 * to a later kvm_vmi_apply_singlestep(want=false) on the vCPU thread. If the
 * agent tears the session down (close(vmi_fd) -> kvm_vmi_release) while a step
 * is armed and DAIF masked, that restore can be skipped:
 *   - reset_vcpu_state clears singlestep_active on the agent thread, so the
 *     vCPU's own step-completion no longer requests the disarm apply, and
 *   - vcpu->vmi is SRCU-freed; if the freeing wins the race, the late
 *     apply_singlestep sees vcpu->vmi == NULL and cannot unmask (the saved
 *     DAIF is gone with the freed struct).
 * Result on a real guest: it resumes with interrupts masked (and the hardware
 * step still armed) -> a silent spin / hang. A selftest guest does not depend on
 * the timer IRQ, so it does not visibly hang -- instead we read the guest's own
 * DAIF after the teardown and assert A/I/F were restored. If the step state is
 * also leaked (SS still armed) the guest cannot make progress and never reports;
 * we treat that timeout as the same failure.
 *
 * REPRODUCTION. Per round: open a VMI session, arm a step via a BRK, wait for
 * the SINGLESTEP event (the vCPU is now blocked in-kernel for the ack with DAIF
 * masked), then close(vmi_fd) WITHOUT acking -> teardown mid-step. Then let the
 * guest run on and report its DAIF. Loop many rounds to hit the SRCU
 * free-vs-apply race.
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

#define NR_ROUNDS	50

/* vCPU<->agent handshake (single vCPU, two host threads). */
static volatile int g_at_sync;		/* guest reached the pre-BRK sync */
static volatile int g_round_ready;	/* agent opened the session; proceed */
static volatile int g_reported;		/* (round+1) once the guest reports DAIF */
static volatile uint64_t g_daif;	/* guest DAIF read after the teardown */
static volatile int g_done;

static void guest_code(void)
{
	int i;

	for (i = 0; i < NR_ROUNDS; i++) {
		/* Tell the agent we are about to arm; wait until the session is up. */
		GUEST_SYNC(1);
		/* Unmask A/I/F so a leaked mask is observable as nonzero below. */
		asm volatile("msr daifclr, #7");
		/* BRK -> breakpoint event; the agent skips it and arms one step. */
		asm volatile(
			"brk #0x7\n\t"
			"nop\n\t" "nop\n\t" "nop\n\t" "nop\n\t"
			"nop\n\t" "nop\n\t" "nop\n\t" "nop\n\t");
		/*
		 * The session was torn down mid-step. If DAIF was restored the read
		 * is the guest's unmasked value; if it leaked, A/I/F are set here.
		 */
		uint64_t daif;

		asm volatile("mrs %0, daif" : "=r"(daif));
		GUEST_SYNC_ARGS(2, daif, i, 0, 0);
	}
	GUEST_DONE();
}

static void *vcpu_thread_fn(void *arg)
{
	struct kvm_vcpu *vcpu = arg;
	struct ucall uc;

	while (!g_done) {
		vcpu_run(vcpu);

		switch (get_ucall(vcpu, &uc)) {
		case UCALL_DONE:
			g_done = 1;
			return NULL;
		case UCALL_ABORT:
			/* A guest abort (e.g. stuck stepping) is a failure signal. */
			g_done = 1;
			REPORT_GUEST_ASSERT(uc);
			return NULL;
		case UCALL_SYNC:
			if (uc.args[1] == 1) {
				g_at_sync = 1;
				while (!g_round_ready && !g_done)
					cpu_relax();
				g_round_ready = 0;
			} else if (uc.args[1] == 2) {
				g_daif = uc.args[2];
				g_reported = (int)uc.args[3] + 1;
			}
			break;
		default:
			break;
		}
	}
	return NULL;
}

/* Poll a volatile int for @want, up to @ms milliseconds. */
static bool wait_int(volatile int *p, int want, int ms)
{
	int t;

	for (t = 0; t < ms; t += 2) {
		if (*p == want)
			return true;
		usleep(2000);
	}
	return *p == want;
}

static void test_singlestep_teardown_daif(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	pthread_t thread;
	int round, leaks = 0, hangs = 0;

	vmi_force_el1_guests();
	vm = vm_create_with_one_vcpu(&vcpu, guest_code);

	pthread_create(&thread, NULL, vcpu_thread_fn, vcpu);

	for (round = 0; round < NR_ROUNDS; round++) {
		struct vmi_test_ring ring;
		struct kvm_vmi_ring_event *ev;
		int vmi_fd;

		/* Wait for the guest to reach the pre-BRK sync. */
		TEST_ASSERT(wait_int(&g_at_sync, 1, 5000) || g_done,
			    "round %d: guest never reached pre-BRK sync", round);
		if (g_done)
			break;
		g_at_sync = 0;

		/* Open a fresh session and enable BP + SS, then release the guest. */
		vmi_fd = vmi_create(vm);
		vmi_setup_ring(vmi_fd, 0, &ring);
		vmi_control_event(vmi_fd, KVM_VMI_EVENT_BREAKPOINT, 1);
		vmi_control_event(vmi_fd, KVM_VMI_EVENT_SINGLESTEP, 1);
		g_round_ready = 1;

		/* Catch the BRK; skip it and arm exactly one step. */
		ev = vmi_wait_event_timeout(&ring, 5000);
		TEST_ASSERT(ev != NULL, "round %d: timeout waiting for BRK", round);
		TEST_ASSERT(ev->type == KVM_VMI_EVENT_BREAKPOINT,
			    "round %d: expected BRK, got %u", round, ev->type);
		ev->regs.pc += ev->insn_len;
		ev->response = KVM_VMI_RESPONSE_SET_REGS | KVM_VMI_RESPONSE_SINGLESTEP;
		vmi_ack_event(&ring, 0);

		/* The step ran; the vCPU now blocks for this ack with DAIF masked. */
		ev = vmi_wait_event_timeout(&ring, 5000);
		TEST_ASSERT(ev != NULL, "round %d: timeout waiting for SS event", round);
		TEST_ASSERT(ev->type == KVM_VMI_EVENT_SINGLESTEP,
			    "round %d: expected SS, got %u", round, ev->type);

		/*
		 * TEARDOWN MID-STEP: close the session without acking. The blocked
		 * vCPU is woken by kvm_vmi_release; the DAIF restore now races the
		 * SRCU free of vcpu->vmi.
		 */
		close(vmi_fd);
		vmi_teardown_ring(&ring);

		/* The guest should resume and report a RESTORED (unmasked) DAIF. */
		if (!wait_int(&g_reported, round + 1, 4000)) {
			/* Never resumed cleanly -> DAIF+SS leaked, guest stuck. */
			hangs++;
			pr_info("FAIL round %d: guest did not resume after teardown-mid-step "
				"(DAIF/step state leaked -> hang)\n", round);
			break;
		}
		if (g_daif & PSTATE_AIF) {
			leaks++;
			pr_info("FAIL round %d: guest DAIF not restored after teardown: "
				"0x%lx (A/I/F still masked)\n", round, (unsigned long)g_daif);
		}
	}

	g_done = 1;
	g_round_ready = 1;	/* unstick the vCPU thread if it is waiting */
	pthread_join(thread, NULL);

	TEST_ASSERT(leaks == 0 && hangs == 0,
		    "DAIF teardown leak: %d masked-restore, %d hangs over %d rounds",
		    leaks, hangs, round);

	kvm_vm_free(vm);
	pr_info("PASS: DAIF restored across %d teardown-mid-step rounds\n", round);
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_RING));

	test_singlestep_teardown_daif();

	return 0;
}
