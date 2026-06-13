// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI close-after-TEARDOWN_RING quiesce regression test (arm64, RF6e).
 *
 * THE BUG (RF6e). struct kvm_vcpu_vmi has ONE bool `teardown` doing two jobs:
 * the ring deliver-fence (re-checked by the ring producer/consumer so they never
 * touch a freed ring page) AND the run-loop pause-wait escape
 * (kvm_vmi_vcpu_pause_wait: pause_count==0 || teardown). kvm_vmi_free_ring() sets
 * teardown=true and never clears it (only a later SETUP_RING would). So after
 * KVM_VMI_TEARDOWN_RING on a LIVE session, teardown stays true. A later
 * close(vmi_fd) -> kvm_vmi_release() pauses every vCPU (kvm_vmi_pause_vm) so each
 * parks with vcpu->mutex DROPPED before free_ring's mutex_lock. But the parked
 * vCPU's pause-wait escapes immediately on the stale teardown=true, so instead of
 * parking it busy-cycles mutex_unlock -> wait(returns) -> mutex_lock and never
 * quiesces; release's mutex_lock starves and close(vmi_fd) hangs.
 *
 * This is the SEPARATE bug the RF1 test (vmi_teardown_ring_halt_test) called out
 * and deliberately did not trigger ("An explicit close while the unsignaled vCPU
 * thread is alive would hang"). Here we DO the explicit close.
 *
 * REPRODUCTION. Same as RF1: 1-vCPU guest syncs once then spins in WFI; open a
 * VMI session + ring while the vCPU is parked at the sync; release the guest so
 * it halts in kvm_vcpu_block() (WFI) holding vcpu->mutex; KVM_VMI_TEARDOWN_RING
 * (returns 0 since RF1) leaves teardown=true. THEN close(vmi_fd) with the vCPU
 * still alive and halted. A watchdog bounds the hang: on the buggy kernel close
 * never returns -> watchdog prints FAIL and _exit(1)s; on a fixed kernel close
 * returns promptly -> POST_CLOSE_OK + PASS.
 *
 * Markers go to stdout: virtme-ng can drop a test's stderr.
 */
#include <errno.h>
#include <linux/kvm.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

/* vCPU<->agent handshake (single vCPU, two host threads). */
static volatile int g_at_sync;	/* guest reached the pre-WFI sync */
static volatile int g_go;	/* agent set up the session; proceed to WFI */
static volatile int g_close_done;	/* close(vmi_fd) returned */

#define WATCHDOG_SECS 15

static void guest_code(void)
{
	/* Announce, wait for the agent, then halt forever in WFI. */
	GUEST_SYNC(1);
	for (;;)
		asm volatile("wfi");
}

static void *vcpu_thread_fn(void *arg)
{
	struct kvm_vcpu *vcpu = arg;
	struct ucall uc;

	/* First run returns on GUEST_SYNC(1). */
	vcpu_run(vcpu);
	if (get_ucall(vcpu, &uc) == UCALL_SYNC && uc.args[1] == 1)
		g_at_sync = 1;

	while (!g_go)
		usleep(1000);

	/* Second run: the guest WFIs and the vCPU halts in kvm_vcpu_block()
	 * holding vcpu->mutex. The process exit kills this thread. */
	vcpu_run(vcpu);
	return NULL;
}

static void *watchdog_fn(void *arg)
{
	int i;

	/* On a fixed kernel close(vmi_fd) returns in well under a second; give
	 * a generous bound for slow vng before declaring a hang. */
	for (i = 0; i < WATCHDOG_SECS * 10 && !g_close_done; i++)
		usleep(100000);

	if (!g_close_done) {
		pr_info("FAIL: close(vmi_fd) hung after TEARDOWN_RING with a halted vCPU (RF6e)\n");
		fflush(stdout);
		_exit(1);
	}
	return NULL;
}

static void test_close_after_ring_teardown(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	pthread_t vthread, wthread;
	int vmi_fd, ret, t;

	vmi_force_el1_guests();
	vm = vm_create_with_one_vcpu(&vcpu, guest_code);

	pthread_create(&vthread, NULL, vcpu_thread_fn, vcpu);

	/* Wait for the guest to reach the pre-WFI sync (vCPU not in KVM_RUN). */
	for (t = 0; t < 5000 && !g_at_sync; t += 2)
		usleep(2000);
	TEST_ASSERT(g_at_sync, "guest never reached the pre-WFI sync");

	/* Set up the session + ring while the vCPU is parked at the sync, so
	 * KVM_VMI_TEARDOWN_RING reaches kvm_vmi_free_ring() (sets teardown=true)
	 * rather than -ENOENT. */
	vmi_fd = vmi_create(vm);
	vmi_setup_ring(vmi_fd, 0, &ring);
	pr_info("SETUP_OK: session up, ring established for vCPU 0\n");

	/* Release the guest; it WFIs and the vCPU halts holding vcpu->mutex. */
	g_go = 1;
	usleep(300000);	/* let the vCPU re-enter KVM_RUN and halt on WFI */

	/* TEARDOWN_RING (returns 0 since RF1) leaves teardown=true on a live
	 * session. */
	ret = vmi_teardown_ring_ioctl(vmi_fd, 0);
	TEST_ASSERT(ret == 0, "KVM_VMI_TEARDOWN_RING failed: %d (errno=%d)",
		    ret, errno);
	pr_info("TEARDOWN_RING_OK: ring torn down, vCPU 0 still halted in WFI\n");
	fflush(stdout);

	/* THE RF6e TRIGGER: close the session while the vCPU is alive and
	 * halted. On the buggy kernel kvm_vmi_release() cannot quiesce the vCPU
	 * (stale teardown=true defeats the pause), so close() hangs; the
	 * watchdog bounds it. */
	pthread_create(&wthread, NULL, watchdog_fn, NULL);

	pr_info("PRE_CLOSE: close(vmi_fd) with vCPU 0 halted after TEARDOWN_RING\n");
	fflush(stdout);
	close(vmi_fd);
	g_close_done = 1;
	pr_info("POST_CLOSE_OK: close(vmi_fd) returned; session quiesced\n");
	pr_info("PASS: VMI close after TEARDOWN_RING completed with a halted vCPU\n");
	fflush(stdout);

	pthread_join(wthread, NULL);
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_RING));

	test_close_after_ring_teardown();

	return 0;
}
