// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI switch_view vs destroy_view use-after-free test (arm64, RF2)
 *
 * THE BUG (RF2). kvm_vmi_switch_view() (the KVM_VMI_SWITCH_VIEW ioctl,
 * virt/kvm/vmi/vmi.c) looks up the target view with
 * "new_view = xa_load(&vmi->views, sv->view_id)" WITHOUT holding vmi->lock,
 * then for each vCPU does "atomic_inc(&new_view->vcpu_count)" under the
 * per-vCPU view_lock. view_lock serializes only against that vCPU's own view
 * switches, NOT against KVM_VMI_DESTROY_VIEW. kvm_vmi_destroy_view() erases the
 * view under vmi->lock once vcpu_count == 0 and then kfree()s it (and frees its
 * arch stage-2 root) after dropping the lock. kvm_vmi_ioctl() is
 * .unlocked_ioctl and takes no lock, so two threads on the same vmi_fd can run
 * SWITCH_VIEW(view) and DESTROY_VIEW(view) concurrently. If switch_view's
 * xa_load() wins just before destroy_view's gate+erase+free, switch_view then
 * atomic_inc()s a freed view -> use-after-free. This is the exact UAF class
 * 7bc2164c fixed for change_gfn/mem-access, left unfixed on switch_view.
 *
 * REPRODUCIBILITY (read this before trusting a clean run). Unlike the
 * change_gfn UAF, switch_view's vulnerable window -- between the lock-free
 * xa_load() and the atomic_inc() -- is only a lock acquisition wide (tens of
 * nanoseconds), whereas change_gfn dereferences the freed view microseconds
 * later (memslot lookup + faultin + stage-2 unmap). A free that lands in
 * switch_view's window therefore essentially never happens from natural
 * userspace racing (verified: 60000 free-events x 3 racers under preempt=full,
 * 0 KASAN reports). To prove the race is real and that the fix closes it, this
 * test is designed to be DETERMINISTIC when the kernel is built with a
 * diagnostic delay inserted between the xa_load() and the per-vCPU loop in
 * kvm_vmi_switch_view():
 *
 *     new_view = xa_load(&vmi->views, sv->view_id);
 *     if (!new_view)
 *             return -ENOENT;
 *     msleep(50);   // <-- DIAGNOSTIC ONLY, never committed (RF2 RED proof)
 *
 * With that delay, a single racer parks inside switch_view() AFTER it has
 * loaded the view but BEFORE it increments the refcount (so vcpu_count is still
 * 0). This test's handshake (g_loading) waits for the racer to enter that
 * window, then has the main thread DESTROY_VIEW the view -- which succeeds
 * (count == 0) and kfree()s it -- while the racer is parked. When the racer
 * wakes it atomic_inc()s the freed view: KASAN reports a slab-use-after-free in
 * kvm_vmi_switch_view(). With the fix (xa_load + loop serialized under
 * vmi->lock), the racer holds vmi->lock across that same delay, so the main
 * thread's DESTROY_VIEW blocks until the inc has happened and then observes
 * vcpu_count == 1 -> -EBUSY: the view is never freed under the inc, KASAN stays
 * clean even with the window maximally widened.
 *
 * Without the diagnostic delay this test still runs (and is a valid
 * serialization / no-crash stress guard for the fix), but it cannot be expected
 * to trigger the UAF on a buggy kernel -- the window is too narrow. The
 * kernel-side verdict in all cases is the presence/absence of a KASAN report;
 * the test process "passes" if it completes without crashing. Run under
 * CONFIG_KASAN (e.g. in vng).
 *
 * The vCPU is created but never run: switch_view's ioctl path only does the
 * refcount bookkeeping and schedules a lazy arch reload (KVM_REQ_VMI_UPDATE),
 * so nothing dereferences the (possibly stale) current_view -- that lock-free
 * fault-path reader is a separate, deferred issue (RF6b), kept out of this test
 * by never entering the guest.
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

#define DEFAULT_FREES	4000

static int g_vmi_fd;
static volatile uint32_t g_view_id;	/* published racer target (0 = idle) */
static volatile uint32_t g_loading;	/* racer announces the id it is switching onto */
static volatile int g_done;		/* tell the racer to stop */

static void guest_idle(void)
{
	GUEST_DONE();	/* never actually run; vm_create needs a guest entry */
}

/*
 * Racer: switch vCPU 0 onto the published view and back to host view 0. It
 * announces the id in g_loading right before the switch-onto ioctl so the main
 * thread can time its DESTROY_VIEW to land while the racer is inside
 * kvm_vmi_switch_view() (parked after xa_load, before atomic_inc, when built
 * with the diagnostic delay). Errors (-ENOENT once destroyed) are ignored.
 */
static void *racer_fn(void *arg)
{
	while (!g_done) {
		uint32_t v = g_view_id;

		if (!v)
			continue;

		g_loading = v;
		__vmi_switch_view_err(g_vmi_fd, v);	/* inc: may land on freed view */
		g_loading = 0;
		__vmi_switch_view_err(g_vmi_fd, 0);	/* drop the ref */
	}
	return NULL;
}

static void test_switch_view_destroy_view_uaf(unsigned long nr_frees)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	pthread_t racer;
	unsigned long i;
	long w;
	int ret;

	vm = vm_create_with_one_vcpu(&vcpu, guest_idle);
	g_vmi_fd = vmi_create(vm);
	g_view_id = 0;
	g_loading = 0;
	g_done = 0;

	pthread_create(&racer, NULL, racer_fn, NULL);

	for (i = 0; i < nr_frees; i++) {
		uint32_t vid = vmi_create_view(g_vmi_fd, KVM_VMI_ACCESS_RWX);

		/* Publish the view; the racer starts switching onto it. */
		g_view_id = vid;

		/* Wait for the racer to enter switch_view() on this id. */
		for (w = 0; g_loading != vid && w < 200000000L; w++)
			;

		/*
		 * Let the racer get past the lock-free xa_load and into the
		 * diagnostic delay (when present). 200us is far below the 50ms
		 * delay, so the racer is reliably parked post-load when we free.
		 */
		usleep(200);

		/* No further engagements on this id. */
		g_view_id = 0;

		/*
		 * Free the view while the racer is parked post-load (count still
		 * 0). On the buggy kernel the racer's later atomic_inc() lands on
		 * this freed view. Spin past any transient -EBUSY (a stray ref
		 * from the racer's previous cycle).
		 */
		while ((ret = vmi_destroy_view_err(g_vmi_fd, vid)) == -EBUSY)
			;
	}

	g_done = 1;
	pthread_join(racer, NULL);

	/* Park vCPU 0 back on the host view before teardown. */
	__vmi_switch_view_err(g_vmi_fd, 0);

	close(g_vmi_fd);
	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	unsigned long nr_frees = DEFAULT_FREES;

	if (argc > 1)
		nr_frees = strtoul(argv[1], NULL, 0);

	vmi_force_el1_guests();
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));

	test_switch_view_destroy_view_uaf(nr_frees);

	pr_info("PASS: vmi_switch_view_uaf driver completed (%lu free-events) -- "
		"check the kernel console for a KASAN use-after-free report\n",
		nr_frees);
	return 0;
}
