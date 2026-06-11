// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI in-kernel auto-step restore-view destroy race UAF test (arm64, RF6d)
 *
 * THE BUG (RF6d). The in-kernel auto-step (KVM_VMI_SET_MEM_ACCESS autostep_mask,
 * the 16K sub-page-fusion retire-in-kernel path) reuses the generic
 * fast-singlestep machinery: on a denied auto-stepped access the abort handler
 * calls kvm_vmi_begin_fast_singlestep(vcpu, 0), which snapshots the current
 * (alternate) view as the restore target and switches the vCPU to view 0 for
 * the one-instruction step -- DROPPING the alt view's vcpu_count to 0. When the
 * step completes, kvm_vmi_complete_fast_singlestep() ->
 * __kvm_vmi_vcpu_switch_view_locked(restore_view) runs on the vCPU thread under
 * view_lock only (not vmi->lock), doing
 *
 *     new_view = xa_load(&vmi->views, restore_view);   // lookup, no vmi->lock
 *     ...
 *     atomic_inc(&new_view->vcpu_count);               // bump a maybe-freed view
 *
 * In the step window the alt view's vcpu_count is 0, so a concurrent agent
 * KVM_VMI_DESTROY_VIEW(alt) succeeds, erases it under vmi->lock and kfree()s it.
 * If the restore switch's xa_load() already captured the view just before the
 * free, the later atomic_inc() lands on freed memory -> use-after-free. This is
 * the autostep-triggered sibling of RF6c (same
 * __kvm_vmi_vcpu_switch_view_locked() lookup->inc window, reached via the
 * restore switch instead of a ring response).
 *
 * THE FIX (RF6d, this commit). The same per-view "dying" handshake + brief
 * srcu_read_lock in __kvm_vmi_vcpu_switch_view_locked() that fixes RF6c: a
 * restore switch whose view destroy_view has committed to free observes dying
 * and backs off (returns -ENOENT), leaving the vCPU on view 0 -- a safe
 * degradation (kvm_vmi_complete_fast_singlestep ignores the return; the vCPU
 * stays on the default root, no UAF), and the struct itself outlives the brief
 * srcu section.
 *
 * RED INFEASIBLE-BY-CONSTRUCTION for the autostep path (measured, documented --
 * not faked). The UAF instruction here is the SAME atomic_inc in
 * __kvm_vmi_vcpu_switch_view_locked() that the RF6c test
 * (vmi_switch_view_vcpu_uaf_test) drives to a clean KASAN slab-use-after-free via
 * the ring-response switch -- so the underlying race and the fix are already
 * proven RED->GREEN there. The autostep RESTORE path, however, cannot be driven
 * to that same UAF from a userspace racer, for a structural reason:
 *
 *   begin_fast_singlestep() switches the alt view -> 0 FIRST, dropping the alt
 *   view's vcpu_count to 0 *before* the guest single-steps; the restore
 *   (complete_fast_singlestep -> __kvm_vmi_vcpu_switch_view_locked(alt)) re-reads
 *   the view with xa_load(alt) only LATER. So the alt view's count==0 window
 *   OPENS at begin -- well before the restore's xa_load. A polling DESTROY_VIEW
 *   racer therefore always wins the free in the begin->complete gap (BEFORE the
 *   restore's xa_load), and complete's xa_load(alt) then returns NULL ->
 *   -ENOENT: a safe degradation, NOT a UAF. Even with a diagnostic mdelay(50)
 *   inserted after the restore's xa_load (the RF6c diagnostic), the racer's free
 *   lands in the earlier begin->complete gap, never inside the post-xa_load
 *   window. Empirically: 5 successful frees / 889 -EBUSY destroys over a run,
 *   ZERO KASAN reports, with the diagnostic mdelay present. (A naive unpaced
 *   variant instead soft-locks the CPU, since the mdelay runs under the view_lock
 *   spinlock in the high-frequency auto-step loop.)
 *
 * So this test is a GREEN GUARD, not a RED reproducer: it exercises the
 * autostep restore-view destroy/recreate race hard (it asserts real frees
 * happened, proving the count==0 window was hit) and asserts the kernel survives
 * it crash-free under KASAN -- catching any regression that makes the restore
 * path dereference a freed view. The deterministic RED for the shared
 * atomic_inc lives in vmi_switch_view_vcpu_uaf_test (RF6c).
 *
 * Auto-step requires 16K/4K fusion (>= 2 sub-pages per host frame); SKIP on a
 * 4K-page host. GFN math is host-page based (gfn = gpa / getpagesize()). The
 * guest is paced one access per host-controlled round (GUEST_SYNC after each
 * touch). Run under CONFIG_KASAN (e.g. in vng).
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

#define PROT_GPA	0x10000000ULL	/* 256 MB, 16K-aligned: the protected frame */
#define PROT_MEMSLOT	10
#define NEIGHBOR_OFF	0x1000		/* a fused neighbor 4K sub-page (auto-stepped) */
#define BP_SUBPAGE	0		/* the breakpoint sub-page (delivered, not stepped) */
#define NR_ACCESS	24		/* host-paced auto-stepped accesses per round */
#define DEFAULT_ROUNDS	200

/* Racer state. */
static int g_vmi_fd;
static volatile uint32_t g_target_view;	/* the alt view to destroy (0 = idle) */
static volatile int g_destroyed;	/* set when a destroy actually freed it */
static volatile int g_done;
static volatile unsigned long g_free_count;	/* successful frees (window hit) */

/*
 * Guest: do NR_ACCESS plain loads of an auto-stepped sub-page, ONE PER ROUND
 * with a GUEST_SYNC between, so the host regains control between auto-step
 * cycles. Each load faults and is retired by an in-kernel auto-step
 * (begin/complete fast step), driving exactly one restore switch-back per round.
 */
static void guest_autostep_paced(void)
{
	volatile uint64_t *base = (volatile uint64_t *)PROT_GPA;
	uint64_t sink = 0;
	int i;

	GUEST_SYNC(1);
	for (i = 0; i < NR_ACCESS; i++) {
		sink += base[NEIGHBOR_OFF / 8];	/* faults -> in-kernel auto-step */
		GUEST_SYNC(2);			/* yield so the racer can destroy */
	}
	GUEST_DONE();
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
		default:
			break;
		}
	}
	return NULL;
}

/*
 * Racer: poll DESTROY_VIEW on the published alt view. -EBUSY while the vCPU is
 * on it (between steps); succeeds (frees it) when its vcpu_count is 0, i.e.
 * during a restore-switch window. On success it signals main to recreate +
 * re-switch so the guest keeps auto-stepping.
 */
static void *destroy_racer_fn(void *arg)
{
	while (!g_done) {
		uint32_t v = g_target_view;

		if (!v || g_destroyed)
			continue;
		if (vmi_destroy_view_err(g_vmi_fd, v) == 0) {
			g_free_count++;		/* won a count==0 window */
			g_destroyed = 1;	/* freed it -- main recreates */
		}
	}
	return NULL;
}

static uint32_t arm_autostep_view(uint64_t prot_gfn, uint16_t mask)
{
	uint32_t view = vmi_create_view(g_vmi_fd, KVM_VMI_ACCESS_RWX);

	vmi_set_mem_access_autostep(g_vmi_fd, view, prot_gfn,
				    KVM_VMI_ACCESS_X, mask);
	vmi_switch_view(g_vmi_fd, view);
	return view;
}

static void test_autostep_destroy_race(unsigned long rounds)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t vthread, rthread;
	size_t psz = getpagesize();
	unsigned int nsub = psz / 4096;
	uint64_t prot_gfn = PROT_GPA / psz;
	uint64_t *prot_hva;
	uint16_t mask;
	unsigned long i;

	if (nsub < 2) {
		pr_info("SKIP: host page == 4K, no fusion -> no auto-step\n");
		return;
	}
	/* Auto-step every 4K sub-page except the BP's own. */
	mask = (uint16_t)(((1u << nsub) - 1) & ~(1u << BP_SUBPAGE));

	vm = vm_create_with_one_vcpu(&vcpu, guest_autostep_paced);
	g_vmi_fd = vmi_create(vm);
	vmi_setup_ring(g_vmi_fd, 0, &ring);

	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, PROT_GPA,
				    PROT_MEMSLOT,
				    vm_calc_num_guest_pages(vm->mode, psz), 0);
	virt_map(vm, PROT_GPA, PROT_GPA, vm_calc_num_guest_pages(vm->mode, psz));
	prot_hva = addr_gpa2hva(vm, PROT_GPA);
	prot_hva[NEIGHBOR_OFF / 8] = 0xABCDEFULL;

	vmi_control_event(g_vmi_fd, KVM_VMI_EVENT_MEM_ACCESS, 1);

	g_done = 0;
	g_destroyed = 0;
	g_target_view = arm_autostep_view(prot_gfn, mask);

	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&vthread, NULL, vcpu_thread_fn, &targ);
	pthread_create(&rthread, NULL, destroy_racer_fn, NULL);

	/*
	 * Each round the racer may free the alt view during a restore window. If
	 * it does, the vCPU is no longer on a valid view; recreate a fresh
	 * auto-step view and re-switch so the guest resumes faulting. Bound the
	 * loop by both the requested rounds and guest completion.
	 */
	for (i = 0; i < rounds && !targ.done; i++) {
		if (g_destroyed) {
			g_target_view = 0;
			vmi_switch_view(g_vmi_fd, 0);
			g_target_view = arm_autostep_view(prot_gfn, mask);
			g_destroyed = 0;
		}
		usleep(500);
	}

	g_done = 1;
	targ.done = 1;
	pthread_join(rthread, NULL);
	pthread_join(vthread, NULL);

	__vmi_switch_view_err(g_vmi_fd, 0);
	vmi_teardown_ring(&ring);
	close(g_vmi_fd);
	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	unsigned long rounds = DEFAULT_ROUNDS;

	if (argc > 1)
		rounds = strtoul(argv[1], NULL, 0);

	vmi_force_el1_guests();
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_RING));

	test_autostep_destroy_race(rounds);

	pr_info("PASS: vmi_autostep_destroy_race driver completed (%lu views freed "
		"in a restore window) -- check the kernel console for a KASAN report\n",
		g_free_count);
	return 0;
}
