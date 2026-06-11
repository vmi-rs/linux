// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI teardown-with-halted-vCPU deadlock regression test (arm64)
 *
 * THE BUG. kvm_vmi_release() (virt/kvm/vmi/vmi.c), run when the agent closes
 * vmi_fd, takes vcpu->mutex for every vCPU that has a VMI session attached --
 * first in the single-step DAIF restore loop, then again in kvm_vmi_free_ring()
 * -- each preceded only by a kvm_vcpu_kick(). That is safe for a vCPU PARKED in
 * kvm_vmi_deliver_via_ring()/kvm_vmi_vcpu_pause_wait(), because those paths drop
 * vcpu->mutex before waiting. But a vCPU HALTED in kvm_vcpu_block() (guest in
 * WFI) holds vcpu->mutex for the whole KVM_RUN, and on arm64 a bare
 * kvm_vcpu_kick() does NOT drive it out of KVM_RUN -- it wakes, finds no work,
 * and re-blocks still holding the mutex. So mutex_lock() in kvm_vmi_release()
 * blocks forever: the agent's close() wedges in 'D' state in kvm_vmi_release,
 * and the guest is frozen. Both are uninterruptible, so only killing the VMM
 * (which signals the halted vCPU's INTERRUPTIBLE sleep) recovers it.
 *
 * This is the deterministic core of the intermittent "DAIF teardown hang" seen
 * in high-rate runs: any vCPU sitting in WFI when the session is torn down
 * deadlocks the release. A high-rate sysreg/mem-access monitor just makes idle
 * (halted) vCPUs the common case at teardown.
 *
 * REPRODUCTION. Create a 1-vCPU guest that syncs once and then spins in WFI.
 * While it is parked at the sync (not in KVM_RUN, so the VMI ioctls are safe),
 * open a VMI session, set up the ring, and enable TTBR0_EL1 sysreg monitoring.
 * Release the guest so it WFIs and the vCPU halts in kvm_vcpu_block() holding
 * vcpu->mutex. Then close(vmi_fd): on the buggy kernel kvm_vmi_release()
 * deadlocks and this process never prints TEARDOWN_OK (a hang == failure,
 * caught by the kselftest 'timeout' or an external timeout under vng). On a
 * fixed kernel close() returns and we print PASS.
 *
 * Markers go to stdout: virtme-ng can drop a test's stderr.
 */
#include <errno.h>
#include <linux/kvm.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

/* vCPU<->agent handshake (single vCPU, two host threads). */
static volatile int g_at_sync;	/* guest reached the pre-WFI sync */
static volatile int g_go;	/* agent set up the session; proceed to WFI */

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

	/*
	 * Second run: the guest WFIs and the vCPU halts in kvm_vcpu_block()
	 * holding vcpu->mutex. On the buggy kernel this never returns; on a
	 * fixed kernel teardown may bounce it out to userspace. Either way the
	 * process exits once main() is done, killing this thread.
	 */
	vcpu_run(vcpu);
	return NULL;
}

static void test_teardown_halt(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	pthread_t thread;
	int vmi_fd, t;

	vmi_force_el1_guests();
	vm = vm_create_with_one_vcpu(&vcpu, guest_code);

	pthread_create(&thread, NULL, vcpu_thread_fn, vcpu);

	/* Wait for the guest to reach the pre-WFI sync (vCPU not in KVM_RUN). */
	for (t = 0; t < 5000 && !g_at_sync; t += 2)
		usleep(2000);
	TEST_ASSERT(g_at_sync, "guest never reached the pre-WFI sync");

	/* Set up the session while the vCPU is parked at the sync. */
	vmi_fd = vmi_create(vm);
	vmi_setup_ring(vmi_fd, 0, &ring);
	vmi_control_sysreg(vmi_fd, KVM_VMI_SYSREG_TTBR0_EL1,
			   /*onchangeonly=*/1, /*bitmask=*/0, /*enable=*/1);
	pr_info("SETUP_OK: session up, TTBR0_EL1 monitor enabled\n");

	/* Release the guest; it WFIs and the vCPU halts holding vcpu->mutex. */
	g_go = 1;
	usleep(300000);	/* let the vCPU re-enter KVM_RUN and halt on WFI */

	/*
	 * TEARDOWN WITH A HALTED vCPU. On the buggy kernel kvm_vmi_release()
	 * deadlocks here on mutex_lock(&vcpu->mutex); this print is the last
	 * thing seen and TEARDOWN_OK never appears.
	 */
	pr_info("TEARDOWN_BEGIN: closing vmi_fd with vCPU 0 halted in WFI\n");
	fflush(stdout);
	close(vmi_fd);
	pr_info("TEARDOWN_OK: kvm_vmi_release() returned with a halted vCPU\n");

	vmi_teardown_ring(&ring);
	pr_info("PASS: VMI teardown completed with a halted vCPU\n");
	fflush(stdout);

	/*
	 * The vCPU thread is still inside KVM_RUN (halted, now without VMI).
	 * Don't try to join it or free the VM cleanly; the process exit below
	 * tears everything down. The point of this test is solely that close()
	 * returned.
	 */
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_RING));

	test_teardown_halt();

	return 0;
}
