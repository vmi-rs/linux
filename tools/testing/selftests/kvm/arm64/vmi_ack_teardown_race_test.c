// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI ACK_EVENT vs ring-teardown use-after-free test (arm64, RF7)
 *
 * THE BUG (RF7). kvm_vmi_ack_event() (the KVM_VMI_ACK_EVENT ioctl,
 * virt/kvm/vmi/vmi.c) advances the ring consumer index with
 * "WRITE_ONCE(vcpu_vmi->ring->req_cons, ...)" after a lock-free
 * "!vcpu_vmi->ring" check, holding NO lock. kvm_vmi_free_ring() frees the ring
 * page ("__free_page(ring_page); ring = NULL") under vcpu->mutex.
 * kvm_vmi_ioctl() is .unlocked_ioctl, so one thread doing KVM_VMI_ACK_EVENT and
 * another doing KVM_VMI_TEARDOWN_RING run concurrently on the same vmi_fd. The
 * ack caller is an agent thread, not a vCPU, so kvm_vmi_pause_vm() in the
 * teardown path does not park it. If TEARDOWN_RING frees the ring between ack's
 * check and its req_cons write, ack writes through a freed page ->
 * use-after-free.
 *
 * (The vcpu->vmi struct UAF via close(vmi_fd) is NOT reachable here: an
 * in-flight ioctl holds an fdget reference, so kvm_vmi_release() cannot run
 * until the ack returns, and TEARDOWN_RING never frees the struct. So the fix
 * is vcpu->mutex only -- no SRCU. The srcu-stable snapshot is RF6.)
 *
 * REPRODUCIBILITY (read before trusting a clean run). The vulnerable window --
 * between the lock-free !ring check and the req_cons write -- is only a few
 * instructions wide, so a free essentially never lands in it from natural
 * userspace racing. To prove the race is real and that the fix closes it, this
 * test is DETERMINISTIC when the kernel is built with a diagnostic delay
 * inserted into kvm_vmi_ack_event() between the check and the write, capturing
 * the ring pointer into a local first (mimicking the compiler caching it):
 *
 *     if (!vcpu_vmi || !vcpu_vmi->ring)
 *             return -EINVAL;
 *     {
 *         struct kvm_vmi_ring_header *r = vcpu_vmi->ring;
 *         msleep(50);   // <-- DIAGNOSTIC ONLY, never committed (RF7 RED proof)
 *         smp_wmb();
 *         WRITE_ONCE(r->req_cons, r->req_cons + 1);
 *         wake_up(&vcpu_vmi->wq);
 *         return 0;
 *     }
 *
 * (the RED build also needs "#include <linux/delay.h>"). With that delay, the
 * racer parks inside ack AFTER passing the !ring check but BEFORE the write.
 * This test's handshake (g_acking) waits for the racer to enter that window,
 * then has the main thread TEARDOWN_RING the ring -- which __free_page()s it --
 * while the racer is parked. When the racer wakes it writes req_cons through the
 * freed page: KASAN reports a use-after-free in kvm_vmi_ack_event(). With the
 * fix (vcpu->mutex held across the re-checked write), the racer holds the mutex
 * over that window, so free_ring blocks until the write completes (or, if the
 * free won the lock first, ack's re-check returns -EINVAL): the page is never
 * freed under the write, KASAN stays clean even with the window maximally
 * widened.
 *
 * Without the diagnostic delay this test still runs (a valid no-crash /
 * serialization stress guard for the fix) but cannot be expected to trigger the
 * UAF on a buggy kernel -- the window is too narrow. Kernel-side verdict in all
 * cases: presence/absence of a KASAN report; the process "passes" if it
 * completes without crashing. Run under CONFIG_KASAN (e.g. in vng).
 *
 * The vCPU is created but never run: ACK_EVENT advances req_cons
 * unconditionally (no pending event needed), and the racer only issues the
 * ioctl -- it never touches the userspace ring mmap, which is decoupled
 * (kvm_vmi_ring_mmap uses remap_pfn_range, taking no page reference).
 */
#include <errno.h>
#include <linux/kvm.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

#define DEFAULT_ITERS	2000

static int g_vmi_fd;
static volatile int g_acking;	/* racer announces it is about to ACK */
static volatile int g_done;	/* tell the racer to stop */

static void guest_idle(void)
{
	GUEST_DONE();	/* never actually run; vm_create needs a guest entry */
}

/*
 * Racer: loop issuing KVM_VMI_ACK_EVENT on vCPU 0. Announces g_acking right
 * before each call so the main thread can time its TEARDOWN_RING to land while
 * the racer is inside kvm_vmi_ack_event() (parked after the !ring check, before
 * the req_cons write, when built with the diagnostic delay). Errors (-EINVAL
 * once the ring is gone) are ignored.
 */
static void *racer_fn(void *arg)
{
	while (!g_done) {
		g_acking = 1;
		__vmi_ack_event_err(g_vmi_fd, 0);	/* may UAF the freed ring */
	}
	return NULL;
}

static void test_ack_teardown_uaf(unsigned long nr_iters)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	struct vmi_test_ring ring;
	pthread_t racer;
	unsigned long i;
	long w;

	vm = vm_create_with_one_vcpu(&vcpu, guest_idle);
	g_vmi_fd = vmi_create(vm);
	g_acking = 0;
	g_done = 0;

	pthread_create(&racer, NULL, racer_fn, NULL);

	for (i = 0; i < nr_iters; i++) {
		/* Establish a fresh ring on vCPU 0. */
		vmi_setup_ring(g_vmi_fd, 0, &ring);

		/* Wait for the racer to start an ack on this live ring. */
		g_acking = 0;
		for (w = 0; !g_acking && w < 200000000L; w++)
			;

		/*
		 * Let the racer get past the lock-free !ring check and into the
		 * diagnostic delay (when present). 200us is far below the 50ms
		 * delay, so the racer is reliably parked post-check when we free.
		 */
		usleep(200);

		/*
		 * Free the ring while the racer is parked post-check. On the
		 * buggy kernel the racer's later req_cons write lands on this
		 * freed page.
		 */
		vmi_teardown_ring_ioctl(g_vmi_fd, 0);

		/* Release this iteration's userspace mmap/fds. */
		vmi_teardown_ring(&ring);
	}

	g_done = 1;
	pthread_join(racer, NULL);

	close(g_vmi_fd);
	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	unsigned long nr_iters = DEFAULT_ITERS;

	if (argc > 1)
		nr_iters = strtoul(argv[1], NULL, 0);

	vmi_force_el1_guests();
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_RING));

	test_ack_teardown_uaf(nr_iters);

	pr_info("PASS: vmi_ack_teardown_race driver completed (%lu iters) -- "
		"check the kernel console for a KASAN use-after-free report\n",
		nr_iters);
	return 0;
}
