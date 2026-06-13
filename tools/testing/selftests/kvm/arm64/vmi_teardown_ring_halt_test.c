// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI TEARDOWN_RING-with-halted-vCPU deadlock regression test (arm64, RF1)
 *
 * THE BUG (RF1). kvm_vmi_free_ring() (virt/kvm/vmi/vmi.c) tears down a vCPU's
 * kernel-side ring under vcpu->mutex, taking it with the sequence
 * "kvm_vcpu_kick(vcpu); mutex_lock(&vcpu->mutex);". That is safe in
 * kvm_vmi_release() (vmi_fd close), which pauses every vCPU first via
 * kvm_vmi_pause_vm() so they park having DROPPED vcpu->mutex. But the
 * KVM_VMI_TEARDOWN_RING ioctl (kvm_vmi_teardown_ring()) calls free_ring with NO
 * such pause. A vCPU HALTED in kvm_vcpu_block() (guest in WFI) holds vcpu->mutex
 * for the whole KVM_RUN, and on arm64 a bare kvm_vcpu_kick() does NOT drive it
 * out of KVM_RUN -- it wakes, finds no work, and re-blocks still holding the
 * mutex. So mutex_lock(&vcpu->mutex) in free_ring blocks forever: the ioctl
 * thread wedges in 'D' state and the ioctl never returns. (x86 exits to
 * userspace on KVM_REQ_UNBLOCK rather than re-blocking with the mutex held, so
 * the deadlock is arm64-specific -- hence no x86 entry.)
 *
 * REPRODUCTION. Create a 1-vCPU guest that syncs once and then spins in WFI.
 * While it is parked at the sync (not in KVM_RUN, so the VMI ioctls are safe),
 * open a VMI session and set up the ring -- this establishes vcpu->vmi and the
 * ring_page so KVM_VMI_TEARDOWN_RING reaches free_ring rather than -ENOENT.
 * (No sysreg monitor is needed; RF1 is purely about free_ring's mutex_lock.)
 * Release the guest so it WFIs and the vCPU halts in kvm_vcpu_block() holding
 * vcpu->mutex. Then issue KVM_VMI_TEARDOWN_RING for that vCPU: on the buggy
 * kernel the ioctl deadlocks in mutex_lock() and this process never prints
 * TEARDOWN_RING_OK (a hang == failure, caught by the kselftest 'timeout' or an
 * external timeout under vng). On a fixed kernel the ioctl returns 0 and we
 * print PASS.
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
	 * holding vcpu->mutex. On the buggy kernel the TEARDOWN_RING ioctl
	 * never returns; on a fixed kernel teardown may bounce it out to
	 * userspace. Either way the process exits once main() is done, killing
	 * this thread.
	 */
	vcpu_run(vcpu);
	return NULL;
}

static void test_teardown_ring_halt(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	pthread_t thread;
	int vmi_fd, ret, t;

	vmi_force_el1_guests();
	vm = vm_create_with_one_vcpu(&vcpu, guest_code);

	pthread_create(&thread, NULL, vcpu_thread_fn, vcpu);

	/* Wait for the guest to reach the pre-WFI sync (vCPU not in KVM_RUN). */
	for (t = 0; t < 5000 && !g_at_sync; t += 2)
		usleep(2000);
	TEST_ASSERT(g_at_sync, "guest never reached the pre-WFI sync");

	/*
	 * Set up the session + ring while the vCPU is parked at the sync. The
	 * ring establishes vcpu->vmi + ring_page so KVM_VMI_TEARDOWN_RING
	 * reaches kvm_vmi_free_ring() (the deadlock site) rather than -ENOENT.
	 */
	vmi_fd = vmi_create(vm);
	vmi_setup_ring(vmi_fd, 0, &ring);
	pr_info("SETUP_OK: session up, ring established for vCPU 0\n");

	/* Release the guest; it WFIs and the vCPU halts holding vcpu->mutex. */
	g_go = 1;
	usleep(300000);	/* let the vCPU re-enter KVM_RUN and halt on WFI */

	/*
	 * TEARDOWN_RING WITH A HALTED vCPU. On the buggy kernel
	 * kvm_vmi_free_ring() deadlocks here on mutex_lock(&vcpu->mutex); this
	 * print is the last thing seen and TEARDOWN_RING_OK never appears.
	 */
	pr_info("TEARDOWN_RING_BEGIN: KVM_VMI_TEARDOWN_RING with vCPU 0 halted in WFI\n");
	fflush(stdout);
	ret = vmi_teardown_ring_ioctl(vmi_fd, 0);
	TEST_ASSERT(ret == 0, "KVM_VMI_TEARDOWN_RING failed: %d (errno=%d)",
		    ret, errno);
	pr_info("TEARDOWN_RING_OK: KVM_VMI_TEARDOWN_RING returned with a halted vCPU\n");
	pr_info("PASS: VMI TEARDOWN_RING completed with a halted vCPU\n");
	fflush(stdout);

	/*
	 * Proof complete: the ioctl returned. Do NOT explicitly close(vmi_fd)
	 * here. free_ring leaves vcpu_vmi->teardown = true, and the run-loop
	 * pause-wait condition is (pause_count == 0 || teardown), so a subsequent
	 * kvm_vmi_release() cannot quiesce this still-halted vCPU -- it spins out
	 * of the pause instead of parking, and release's mutex_lock starves. That
	 * teardown-flag overload is a SEPARATE, deeper bug (the teardown-quiesce /
	 * ring-deliver-lifetime mess); RF1 covers only the TEARDOWN_RING ioctl
	 * deadlock. Returning from main() is clean: the process exit SIGKILLs the
	 * halted vCPU thread, whose run-loop signal_pending check breaks it out of
	 * KVM_RUN and drops vcpu->mutex, so the implicit fd close completes. (An
	 * explicit close while the unsignaled vCPU thread is alive would hang --
	 * that is the separate bug, and is not what this test asserts.)
	 * (That separate bug is RF6e, since fixed via a distinct session_teardown
	 * pause escape; see vmi_teardown_ring_close_test.)
	 */
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_RING));

	test_teardown_ring_halt();

	return 0;
}
