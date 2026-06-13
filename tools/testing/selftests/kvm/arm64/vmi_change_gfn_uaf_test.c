// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI change_gfn vs destroy_view use-after-free test (arm64)
 *
 * kvm_vmi_change_gfn() holds vmi->lock for the full view lookup and
 * dereference sequence. kvm_vmi_destroy_view() also erases the view under
 * vmi->lock, then defers the struct free past in-flight SRCU readers via
 * call_srcu(). Together these prevent a concurrent CHANGE_GFN and
 * DESTROY_VIEW from racing: the xa_load in change_gfn and the xa_erase in
 * destroy_view are mutually exclusive under vmi->lock, and the SRCU grace
 * period ensures no reader touches a freed view.
 *
 * This test confirms that invariant holds under KASAN by stress-racing both
 * operations. The absence of a KASAN report (slab-use-after-free) is the
 * pass criterion; the test process completing without crashing is a secondary
 * signal only.
 *
 * This test drives that race: per round, one thread hammers change_gfn() on a
 * freshly-created view while the main thread destroys it, with a barrier so both
 * fire together. A UAF is silent on a normal kernel, so the detector is KASAN:
 * run under a CONFIG_KASAN kernel (e.g. in vng) and check the console for
 * "BUG: KASAN: ... use-after-free in kvm_vmi_change_gfn". With the race fixed
 * (e.g. change_gfn serialized against destroy_view), the run is KASAN-clean.
 *
 * The test itself "passes" if it completes without the test process crashing;
 * the kernel-side verdict is the absence of a KASAN report in the console.
 * destroy_view requires vcpu_count == 0, so no vCPU is ever switched onto the
 * view (the vCPUs are created but never run).
 */
#include <errno.h>
#include <linux/kvm.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

#define NR_ROUNDS		20000
#define CHANGES_PER_ROUND	24
#define OLD_GFN			0x1000ULL

struct racer_arg {
	int vmi_fd;
	uint64_t shadow_gfn;
};

/* Shared with the racer thread; set by main before each round's start barrier. */
static volatile uint32_t g_view_id;
static pthread_barrier_t g_start;	/* both threads released to act together */
static pthread_barrier_t g_done;	/* round complete, ready for the next */

static void guest_idle(void)
{
	GUEST_DONE();	/* never actually run; vm_create needs a guest entry */
}

/*
 * Reader: hammer change_gfn() on the round's view exactly as the main thread
 * destroys it. Errors (-ENOENT once destroyed, -EBUSY, etc.) are expected and
 * ignored -- we only care about the kernel touching a freed view.
 */
static void *racer_fn(void *arg)
{
	struct racer_arg *ra = arg;
	int round, k;

	for (round = 0; round < NR_ROUNDS; round++) {
		pthread_barrier_wait(&g_start);

		uint32_t view = g_view_id;

		for (k = 0; k < CHANGES_PER_ROUND; k++)
			__vmi_change_gfn_err(ra->vmi_fd, view, OLD_GFN,
					     ra->shadow_gfn);

		pthread_barrier_wait(&g_done);
	}
	return NULL;
}

static void test_change_gfn_destroy_view_uaf(void)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	struct racer_arg ra;
	pthread_t racer;
	int round;

	vm = vm_create_with_one_vcpu(&vcpu, guest_idle);

	ra.vmi_fd = vmi_create(vm);
	/*
	 * A shadow GFN as the change_gfn target: change_gfn resolves it via
	 * vmi->shadow_pages (no memslot faultin) and still performs the full
	 * sequence of view-> dereferences that races the free.
	 */
	ra.shadow_gfn = vmi_alloc_gfn(ra.vmi_fd);

	pthread_barrier_init(&g_start, NULL, 2);
	pthread_barrier_init(&g_done, NULL, 2);

	pthread_create(&racer, NULL, racer_fn, &ra);

	for (round = 0; round < NR_ROUNDS; round++) {
		g_view_id = vmi_create_view(ra.vmi_fd, KVM_VMI_ACCESS_RWX);

		pthread_barrier_wait(&g_start);

		/* Free the view out from under the racer's change_gfn() calls. */
		vmi_destroy_view_err(ra.vmi_fd, g_view_id);

		pthread_barrier_wait(&g_done);
	}

	pthread_join(racer, NULL);

	pthread_barrier_destroy(&g_start);
	pthread_barrier_destroy(&g_done);

	close(ra.vmi_fd);
	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	vmi_force_el1_guests();
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));

	test_change_gfn_destroy_view_uaf();

	pr_info("PASS: vmi_change_gfn_uaf driver completed (%d rounds) -- "
		"check the kernel console for a KASAN use-after-free report\n",
		NR_ROUNDS);
	return 0;
}
