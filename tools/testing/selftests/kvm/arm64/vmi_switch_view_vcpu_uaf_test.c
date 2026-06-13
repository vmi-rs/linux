// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI vCPU-thread switch_view vs destroy_view use-after-free test
 * (arm64, RF6c)
 *
 * THE BUG (RF6c). __kvm_vmi_vcpu_switch_view_locked() (virt/kvm/vmi/vmi.c) --
 * the core per-vCPU view switch run ON THE vCPU THREAD from a ring
 * KVM_VMI_RESPONSE_SWITCH_VIEW (and from fast-singlestep completion) -- holds
 * only the per-vCPU view_lock, NOT vmi->lock. It does
 *
 *     new_view = xa_load(&vmi->views, view_id);   // lookup, no vmi->lock
 *     ...
 *     atomic_inc(&new_view->vcpu_count);          // bump a maybe-freed view
 *
 * Concurrently the agent thread runs KVM_VMI_DESTROY_VIEW on the same vmi_fd
 * (.unlocked_ioctl, no shared lock). destroy_view erases the view under
 * vmi->lock once its vcpu_count == 0 and kfree()s it. view_lock serializes only
 * a vCPU's own switches, not DESTROY_VIEW, so if the vCPU-thread switch's
 * xa_load() wins just before destroy's gate+erase+free, the later atomic_inc()
 * lands on a freed view -> use-after-free. This is the vCPU-thread sibling of
 * the RF2 ioctl-path race (vmi_switch_view_uaf_test): RF2's KVM_VMI_SWITCH_VIEW
 * ioctl was fixed by taking vmi->lock, but the vCPU-thread switch cannot take
 * vmi->lock (it runs under view_lock from the ring-response path), so it needs
 * the separate RF6c fix.
 *
 * THE FIX (RF6c, this commit). A per-view "dying" flag plus a symmetric
 * store-load barrier handshake: destroy_view publishes WRITE_ONCE(dying,true);
 * smp_mb(); re-reads vcpu_count, and the switch does atomic_inc(count);
 * smp_mb__after_atomic(); if (READ_ONCE(dying)) back off. The two full barriers
 * forbid the "both miss" outcome, so a view destroy has committed to free is
 * never left referenced by a vCPU's current_view; the inc itself is also done
 * under a brief srcu_read_lock(&kvm->srcu) so the struct cannot be call_srcu'd
 * out mid-deref.
 *
 * REPRODUCIBILITY (read before trusting a clean run). The window between the
 * lock-free xa_load() and the atomic_inc() is a few instructions, so a free
 * essentially never lands in it from natural racing. To prove the race is real
 * and that the fix closes it, this test is DETERMINISTIC when the kernel is
 * built with a diagnostic delay inserted into __kvm_vmi_vcpu_switch_view_locked()
 * between the new_view xa_load() and the atomic_inc():
 *
 *     new_view = xa_load(&vmi->views, view_id);
 *     if (!new_view)
 *             return -ENOENT;
 *     ...
 *     if (new_view) {
 *             msleep(50);   // <-- DIAGNOSTIC ONLY, never committed (RF6c RED)
 *             atomic_inc(&new_view->vcpu_count);
 *     }
 *
 * (the RED build also needs "#include <linux/delay.h>"). With that delay, the
 * vCPU thread -- driven into the switch by the agent's SWITCH_VIEW response to
 * a MEM_ACCESS event -- parks AFTER loading the (still-live) target view but
 * BEFORE incrementing its refcount (vcpu_count still 0). The agent thread then
 * DESTROY_VIEW(view) -- which succeeds (count == 0) and kfree()s it -- while the
 * vCPU is parked. When the vCPU wakes it atomic_inc()s the freed view: KASAN
 * reports a slab-use-after-free in __kvm_vmi_vcpu_switch_view_locked(), "Freed
 * by ... kvm_vmi_destroy_view". With the fix the vCPU observes dying (or the
 * struct stays live under srcu) and backs off, so KASAN stays clean even with
 * the window maximally widened.
 *
 * Without the diagnostic delay this test still runs (a valid no-crash guard for
 * the fix) but cannot be expected to trigger the UAF on a buggy kernel -- the
 * window is too narrow. Kernel-side verdict in all cases: presence/absence of a
 * KASAN report; the process "passes" if it completes without crashing. Run
 * under CONFIG_KASAN (e.g. in vng).
 *
 * GFN math is host-page based (gfn = gpa / getpagesize()); never a 4K shift.
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

#define DENY_GPA	0x10000000ULL	/* 256 MB: read-denied in the start view */
#define DENY_MEMSLOT	10
#define DEFAULT_ROUNDS	2000

static volatile int g_stop;	/* ask the vCPU thread to exit at the next sync */

/* Guest: read a denied page (raises MEM_ACCESS), with a GUEST_SYNC between reads
 * so the vCPU thread periodically returns to userspace (and can observe a stop
 * request). The agent answers the violation with SWITCH_VIEW so the vCPU thread
 * runs the switch. */
static void guest_touch_denied(void)
{
	volatile uint64_t *ptr = (volatile uint64_t *)DENY_GPA;
	uint64_t sink = 0;

	GUEST_SYNC(1);
	for (;;) {
		sink += *ptr;	/* R-denied in the start view -> MEM_ACCESS */
		GUEST_SYNC(2);	/* yield so the vCPU thread can stop cleanly */
	}
	(void)sink;
}

static void *vcpu_thread_fn(void *arg)
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
			targ->done = 1;
			REPORT_GUEST_ASSERT(uc);
			return NULL;
		case UCALL_SYNC:
			/* Stop requested: exit cleanly at a sync point (not while
			 * blocked mid-event-delivery in the kernel). */
			if (g_stop) {
				targ->done = 1;
				return NULL;
			}
			break;
		default:
			break;
		}
	}
	return NULL;
}

static void test_vcpu_switch_view_uaf(unsigned long nr_rounds)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	struct kvm_vmi_ring_event *ev;
	pthread_t thread;
	size_t psz = getpagesize();
	uint64_t deny_gfn = DENY_GPA / psz;
	uint32_t start_view;
	unsigned long i;

	vm = vm_create_with_one_vcpu(&vcpu, guest_touch_denied);
	ring.vmi_fd = vmi_create(vm);
	vmi_setup_ring(ring.vmi_fd, 0, &ring);

	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, DENY_GPA,
				    DENY_MEMSLOT,
				    vm_calc_num_guest_pages(vm->mode, psz), 0);
	virt_map(vm, DENY_GPA, DENY_GPA, vm_calc_num_guest_pages(vm->mode, psz));

	/* Start view denies reads of DENY_GPA so the touch raises MEM_ACCESS. */
	start_view = vmi_create_view(ring.vmi_fd, KVM_VMI_ACCESS_RWX);
	vmi_set_mem_access(ring.vmi_fd, start_view, deny_gfn, KVM_VMI_ACCESS_X);
	vmi_control_event(ring.vmi_fd, KVM_VMI_EVENT_MEM_ACCESS, 1);
	vmi_switch_view(ring.vmi_fd, start_view);

	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vcpu_thread_fn, &targ);

	for (i = 0; i < nr_rounds && !targ.done; i++) {
		/* Fresh target view for the vCPU-thread switch to race. */
		uint32_t target = vmi_create_view(ring.vmi_fd, KVM_VMI_ACCESS_RWX);

		/* Wait for the R violation on the denied page. */
		ev = vmi_wait_event_timeout(&ring, 5000);
		if (!ev)
			break;

		/*
		 * Answer with SWITCH_VIEW to the fresh target. On ack the vCPU
		 * thread runs __kvm_vmi_vcpu_switch_view_locked(target) and, with
		 * the diagnostic delay, parks after xa_load(target) before
		 * atomic_inc -- target's vcpu_count is still 0.
		 */
		ev->response = KVM_VMI_RESPONSE_SWITCH_VIEW;
		ev->view_id = target;
		vmi_ack_event(&ring, 0);

		/* Let the vCPU thread enter the switch and park in the delay. */
		usleep(300);

		/*
		 * Free the target while the vCPU is parked post-load (count 0).
		 * On the buggy kernel the vCPU's later atomic_inc() lands here.
		 */
		while (vmi_destroy_view_err(ring.vmi_fd, target) == -EBUSY)
			usleep(50);

		/*
		 * The vCPU (on fix: backed off to start_view; on bug: now on the
		 * freed target). Pull it back to start_view via a VM-wide switch
		 * so the next round's denied touch fires MEM_ACCESS again, and so
		 * any raised refcount on a live target is released.
		 */
		vmi_switch_view(ring.vmi_fd, start_view);
	}

	/*
	 * Terminate cleanly. The vCPU may be blocked in the kernel delivering a
	 * MEM_ACCESS waiting for an ack. Request a stop, switch every vCPU to
	 * view 0 (reads now succeed, no more violations), and drain-ack pending
	 * events with CONTINUE so the vCPU thread unblocks, runs the faulting
	 * read on view 0, reaches a GUEST_SYNC, sees g_stop, and exits.
	 */
	g_stop = 1;
	vmi_switch_view(ring.vmi_fd, 0);
	while (!targ.done) {
		ev = vmi_wait_event_timeout(&ring, 200);
		if (ev) {
			ev->response = KVM_VMI_RESPONSE_CONTINUE;
			vmi_ack_event(&ring, 0);
		}
	}
	pthread_join(thread, NULL);

	__vmi_switch_view_err(ring.vmi_fd, 0);
	vmi_teardown_ring(&ring);
	close(ring.vmi_fd);
	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	unsigned long nr_rounds = DEFAULT_ROUNDS;

	if (argc > 1)
		nr_rounds = strtoul(argv[1], NULL, 0);

	vmi_force_el1_guests();
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_RING));

	test_vcpu_switch_view_uaf(nr_rounds);

	pr_info("PASS: vmi_switch_view_vcpu_uaf driver completed (%lu rounds) -- "
		"check the kernel console for a KASAN use-after-free report\n",
		nr_rounds);
	return 0;
}
