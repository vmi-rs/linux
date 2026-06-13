// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI fault-path view-struct use-after-free test (arm64, RF6b)
 *
 * THE BUG (RF6b). The arm64 stage-2 fault path reads the vCPU's active
 * alternate view through a RAW pointer and dereferences it across several
 * statements with NO SRCU/RCU protection of the struct lifetime. Concretely
 * the arm64 stage-2 fault helper (arch/arm64/kvm/vmi.c) does
 *
 *     view = vcpu_vmi->current_view;
 *     ...
 *     if (xa_load(&view->gfn_overrides, gfn)) ...        // deref view
 *     xa_for_each_range(&view->gfn_overrides, ...)        // deref view
 *
 * and similar helpers added in later commits do the same. These run from the abort handler under
 * srcu_read_lock(&kvm->srcu) (kvm_handle_guest_abort, arm64/kvm/mmu.c:2089),
 * but the view struct itself is freed SYNCHRONOUSLY by kvm_vmi_destroy_view()
 * (virt/kvm/vmi/vmi.c): once a view's vcpu_count hits 0 it does xa_erase()
 * then kfree(view) immediately, ignoring kvm->srcu entirely. So a vCPU that
 * is parked mid-fault holding a stale "view" local races a concurrent
 * KVM_VMI_SWITCH_VIEW(->0) + KVM_VMI_DESTROY_VIEW on the agent thread: the
 * switch drops vcpu_count to 0 (the parked vCPU is in the fault handler, not
 * holding view_lock), destroy then frees the view, and the woken fault helper
 * dereferences freed memory -> use-after-free.
 *
 * THE FIX (RF6b, this commit). current_view becomes __rcu; the view struct is
 * freed via call_srcu(&kvm->srcu, &view->rcu_head, free_view) after the SRCU
 * grace period, so a deref inside the fault path's SRCU section always sees a
 * live struct. The fault helpers read it via srcu_dereference (Commit 2). The
 * arch stage-2 *root* drain stays synchronous (it is the protector of the page
 * table root, not the struct).
 *
 * REPRODUCIBILITY (read before trusting a clean run). The window between the
 * "view = current_view" read and the xa_load() deref inside
 * kvm_vmi_view_force_pte_gfn() is a few instructions, so a free essentially
 * never lands in it from natural racing. To prove the race is real and that the
 * fix closes it, this test is DETERMINISTIC when the kernel is built with a
 * diagnostic delay inserted into kvm_vmi_view_force_pte_gfn() after the
 * current_view read and before the gfn_overrides deref:
 *
 *     view = vcpu_vmi->current_view;
 *     if (!view)
 *             return false;
 *     msleep(50);   // <-- DIAGNOSTIC ONLY, never committed (RF6b RED proof)
 *     if (xa_load(&view->gfn_overrides, gfn))
 *             return true;
 *
 * (the RED build also needs "#include <linux/delay.h>"). With that delay, a
 * vCPU faulting on the protected page parks inside the helper AFTER reading the
 * (still-live) view but BEFORE dereferencing it. The agent thread then
 * SWITCH_VIEW(vcpu,0) (drops vcpu_count to 0) + DESTROY_VIEW(view) (frees it)
 * while the vCPU is parked; when the vCPU wakes it derefs the freed view ->
 * KASAN slab-use-after-free in kvm_vmi_view_force_pte_gfn(), "Freed by ...
 * kvm_vmi_destroy_view". With the fix (call_srcu free + srcu_dereference) the
 * struct outlives the SRCU section, so KASAN stays clean even with the window
 * maximally widened.
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

#define PROT_GPA	0x10000000ULL	/* 256 MB, 16K-aligned: the faulting frame */
#define PROT_MEMSLOT	10
#define DEFAULT_ROUNDS	2000

static volatile int g_done;		/* tell the guest loop to stop */

/*
 * Guest: spin reading the protected page. Each first-touch after a view switch
 * faults into the stage-2 handler, driving the kvm_vmi_view_* fault helpers
 * (and, with the diagnostic delay, parking the vCPU thread inside them).
 */
static void guest_fault_loop(void)
{
	volatile uint64_t *ptr = (volatile uint64_t *)PROT_GPA;
	uint64_t sink = 0;

	GUEST_SYNC(1);
	for (;;) {
		sink += *ptr;
		GUEST_SYNC(2);	/* yield so the agent can switch/destroy */
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
		default:
			break;
		}
	}
	return NULL;
}

static void test_view_rcu_free_uaf(unsigned long nr_rounds)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	size_t psz = getpagesize();
	uint64_t prot_gfn = PROT_GPA / psz;
	uint64_t *prot_hva;
	int vmi_fd;
	unsigned long i;

	vm = vm_create_with_one_vcpu(&vcpu, guest_fault_loop);
	vmi_fd = vmi_create(vm);

	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, PROT_GPA,
				    PROT_MEMSLOT,
				    vm_calc_num_guest_pages(vm->mode, psz), 0);
	virt_map(vm, PROT_GPA, PROT_GPA, vm_calc_num_guest_pages(vm->mode, psz));
	prot_hva = addr_gpa2hva(vm, PROT_GPA);
	*prot_hva = 0xC0FFEEULL;

	targ.vcpu = vcpu;
	targ.done = 0;
	g_done = 0;
	pthread_create(&thread, NULL, vcpu_thread_fn, &targ);

	for (i = 0; i < nr_rounds && !targ.done; i++) {
		/*
		 * Fresh alt view per round, switch the vCPU onto it (so the
		 * stage-2 fault path enters the kvm_vmi_view_* helpers on its
		 * next touch -- vcpu->arch.hw_mmu becomes the view's mmu), then
		 * race a SWITCH_VIEW(->0) + DESTROY_VIEW against the vCPU's
		 * in-flight fault. Default RWX, no access overrides, so
		 * kvm_vmi_view_force_pte_gfn() returns false and the fault reaches
		 * the gfn_overrides deref where the diagnostic delay parks it.
		 */
		uint32_t view = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);

		vmi_switch_view(vmi_fd, view);

		/* Give the vCPU time to fault and park inside the helper. */
		usleep(300);

		/* Drop the vCPU off the view (count -> 0) while it is parked. */
		vmi_switch_view(vmi_fd, 0);

		/*
		 * Free the view out from under the parked fault helper. On the
		 * buggy kernel the helper's later deref lands on this freed
		 * struct. Spin past a transient -EBUSY.
		 */
		while (vmi_destroy_view_err(vmi_fd, view) == -EBUSY)
			usleep(50);
	}

	targ.done = 1;
	g_done = 1;
	pthread_join(thread, NULL);

	/* Park back on the host view before teardown. */
	__vmi_switch_view_err(vmi_fd, 0);

	close(vmi_fd);
	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	unsigned long nr_rounds = DEFAULT_ROUNDS;

	if (argc > 1)
		nr_rounds = strtoul(argv[1], NULL, 0);

	vmi_force_el1_guests();
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));

	test_view_rcu_free_uaf(nr_rounds);

	pr_info("PASS: vmi_view_rcu_free driver completed (%lu rounds) -- "
		"check the kernel console for a KASAN use-after-free report\n",
		nr_rounds);
	return 0;
}
