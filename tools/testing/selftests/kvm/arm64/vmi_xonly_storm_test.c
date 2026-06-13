// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI execute-only stealth storm characterization (arm64, 16K host)
 *
 * A VMI agent hides software breakpoints from in-guest integrity checks
 * (Windows PatchGuard) by marking the breakpoint page execute-only in an alt
 * view: a guest READ permission-faults -> MEM_ACCESS -> the agent fast-steps
 * the read on the clean default view, so the checker sees the original bytes.
 *
 * On a 16K host running a 4K-granule guest the stage-2 leaf is one 16K host
 * page = four fused guest-4K pages, and the per-GFN access override is keyed on
 * the host (16K) GFN (kvm_vmi_view_denies(fault_ipa >> PAGE_SHIFT=14)). So the
 * execute-only protection cannot be confined to the one 4K page that holds the
 * breakpoint: a data access to ANY of the four fused guest pages faults too.
 * Each fault is a full userspace ring round-trip (kvm_vmi_deliver_via_ring: a
 * non-killable wait_event + a per-fault kvm->srcu drop + vcpu_put/vcpu_load,
 * with no rate limit) and arm64 has no in-kernel single-step escape yet, so the
 * agent must answer every access individually. On a hot page that is a storm.
 *
 * The first two scenarios CHARACTERIZE the storm (the per-access userspace
 * round-trip and the fusion amplification); the third VALIDATES the fix: the
 * KVM_VMI_SET_MEM_ACCESS autostep_mask, which retires neighbor faults in the
 * kernel so they never reach userspace, while the breakpoint's own sub-page
 * still delivers exactly as on x86.
 *
 *   read_storm     - NR_ACCESS reads of one execute-only address with NO mask.
 *                    Confirms one ring event per access (no batching / no rate
 *                    limit), measures the per-access round-trip cost, and
 *                    verifies the guest read the correct (clean) bytes. This is
 *                    the unmitigated storm.
 *   amplification  - one read into each 4K sub-page of the 16K frame. Confirms
 *                    a single execute-only override faults across all fused
 *                    guest pages (sub-page-resolved via fault_ipa bits [13:12]).
 *   autostep_neigh - same frame, but the neighbor sub-pages are marked
 *                    autostep_mask. NR_ACCESS neighbor reads are retired
 *                    in-kernel (zero events); only the one breakpoint-sub-page
 *                    read is delivered. The contrast with read_storm (same
 *                    mechanism, mask off vs on) is the before/after of the fix.
 *
 * Both answer with KVM_VMI_RESPONSE_SINGLESTEP_FAST, which disarms single-step
 * in the kernel before yielding -- it never leaks MDSCR_EL1.SS to the host (cf.
 * the host MDSCR restore in kvm_vcpu_put_debug). Safe to run in vng L1.
 *
 * GFN math is host-page based (gfn = gpa / getpagesize()); never a 4K shift.
 */
#include <errno.h>
#include <linux/kvm.h>
#include <linux/kvm_vmi.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

#define PROT_GPA	0x10000000ULL	/* 256 MB, 16K-aligned: the protected frame */
#define RESULT_GPA	0x10100000ULL	/* far away, different 16K frame, always RWX */
#define PROT_MEMSLOT	10
#define RESULT_MEMSLOT	11

#define SLOT_VAL	0xABCDULL	/* small, so NR_ACCESS * SLOT_VAL cannot wrap */
#define NR_ACCESS	1024		/* loop iterations = expected ring events */

/* ---- read_storm ------------------------------------------------------- */

static void guest_read_storm(void)
{
	volatile uint64_t *base = (volatile uint64_t *)PROT_GPA;
	volatile uint64_t *result = (volatile uint64_t *)RESULT_GPA;
	uint64_t sum = 0;
	int i;

	GUEST_SYNC(1);
	/*
	 * Each LDR permission-faults on the execute-only frame; the agent
	 * fast-steps it on the clean view and execution returns here, so the
	 * loop makes one fault of forward progress per iteration.
	 */
	for (i = 0; i < NR_ACCESS; i++)
		sum += base[0];
	*result = sum;
	GUEST_SYNC(2);
	/* Each read must have seen the clean byte (the fast-step served view 0). */
	GUEST_ASSERT_EQ(sum, (uint64_t)NR_ACCESS * SLOT_VAL);
	GUEST_DONE();
}

static void run_read_storm(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	struct timespec t0, t1;
	size_t psz = getpagesize();
	uint64_t prot_gfn = PROT_GPA / psz;
	uint64_t *prot_hva, *result_hva;
	uint32_t view1;
	int vmi_fd, count = 0;
	double secs, per_us;

	vm = vm_create_with_one_vcpu(&vcpu, guest_read_storm);
	vmi_fd = vmi_create(vm);
	vmi_setup_ring(vmi_fd, 0, &ring);

	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, PROT_GPA, PROT_MEMSLOT,
				    vm_calc_num_guest_pages(vm->mode, psz), 0);
	virt_map(vm, PROT_GPA, PROT_GPA, vm_calc_num_guest_pages(vm->mode, psz));
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, RESULT_GPA,
				    RESULT_MEMSLOT,
				    vm_calc_num_guest_pages(vm->mode, psz), 0);
	virt_map(vm, RESULT_GPA, RESULT_GPA, vm_calc_num_guest_pages(vm->mode, psz));

	prot_hva = addr_gpa2hva(vm, PROT_GPA);
	result_hva = addr_gpa2hva(vm, RESULT_GPA);
	*prot_hva = SLOT_VAL;
	*result_hva = 0;

	/* Execute-only in the alt view (S2AP=00): a data READ permission-faults. */
	view1 = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);
	vmi_set_mem_access(vmi_fd, view1, prot_gfn, KVM_VMI_ACCESS_X);

	vmi_control_event(vmi_fd, KVM_VMI_EVENT_MEM_ACCESS, 1);
	vmi_switch_view(vmi_fd, view1);

	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	clock_gettime(CLOCK_MONOTONIC, &t0);
	while (count < NR_ACCESS) {
		ev = vmi_wait_event_timeout(&ring, 5000);
		TEST_ASSERT(ev != NULL,
			    "Timeout after %d/%d events (storm stalled?)",
			    count, NR_ACCESS);
		TEST_ASSERT(ev->type == KVM_VMI_EVENT_MEM_ACCESS,
			    "Expected MEM_ACCESS, got %u (no SINGLESTEP must leak)",
			    ev->type);
		TEST_ASSERT(ev->mem_access.access & KVM_VMI_ACCESS_R,
			    "Expected R violation, got access 0x%x",
			    ev->mem_access.access);
		TEST_ASSERT(ev->mem_access.gpa / psz == prot_gfn,
			    "Expected GFN 0x%lx, got GPA 0x%llx",
			    (unsigned long)prot_gfn,
			    (unsigned long long)ev->mem_access.gpa);
		count++;
		ev->response = KVM_VMI_RESPONSE_SINGLESTEP_FAST;
		vmi_ack_event(&ring, 0);
	}
	clock_gettime(CLOCK_MONOTONIC, &t1);

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");

	/* One ring event per denied access: no batching, no rate limit. */
	TEST_ASSERT(count == NR_ACCESS,
		    "Expected %d events (one per access), got %d", NR_ACCESS, count);
	/* The fast-step served the clean bytes on every access. */
	TEST_ASSERT(*result_hva == (uint64_t)NR_ACCESS * SLOT_VAL,
		    "Guest sum 0x%lx, expected 0x%lx",
		    (unsigned long)*result_hva,
		    (unsigned long)((uint64_t)NR_ACCESS * SLOT_VAL));

	secs = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
	per_us = secs * 1e6 / NR_ACCESS;
	pr_info("PASS: read storm: %d events in %.3f s = %.0f events/s, %.1f us/access\n",
		NR_ACCESS, secs, NR_ACCESS / secs, per_us);
	pr_info("      (each access is one userspace ring round-trip; this is the\n");
	pr_info("       per-access cost a hot execute-only page pays, x%lu in the\n",
		(unsigned long)(psz / vm->page_size));
	pr_info("       worst case from 16K/%luK page fusion.)\n",
		(unsigned long)(vm->page_size / 1024));

	vmi_switch_view(vmi_fd, 0);
	vmi_destroy_view(vmi_fd, view1);
	vmi_teardown_ring(&ring);
	close(vmi_fd);
	kvm_vm_free(vm);
}

/* ---- amplification ---------------------------------------------------- */

static void guest_amp(void)
{
	volatile uint64_t *base = (volatile uint64_t *)PROT_GPA;
	volatile uint64_t *result = (volatile uint64_t *)RESULT_GPA;
	uint64_t sum = 0;

	GUEST_SYNC(1);
	/* One read into each 4K sub-page of the single 16K host frame. */
	sum += base[0x0000 / 8];
	sum += base[0x1000 / 8];
	sum += base[0x2000 / 8];
	sum += base[0x3000 / 8];
	*result = sum;
	GUEST_SYNC(2);
	GUEST_DONE();
}

static void run_amplification(void)
{
	const uint64_t want[4] = { 0x0000, 0x1000, 0x2000, 0x3000 };
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	size_t psz = getpagesize();
	uint64_t prot_gfn = PROT_GPA / psz;
	uint64_t *prot_hva;
	uint32_t view1;
	int vmi_fd, i, seen = 0;

	vm = vm_create_with_one_vcpu(&vcpu, guest_amp);
	vmi_fd = vmi_create(vm);
	vmi_setup_ring(vmi_fd, 0, &ring);

	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, PROT_GPA, PROT_MEMSLOT,
				    vm_calc_num_guest_pages(vm->mode, psz), 0);
	virt_map(vm, PROT_GPA, PROT_GPA, vm_calc_num_guest_pages(vm->mode, psz));
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, RESULT_GPA,
				    RESULT_MEMSLOT,
				    vm_calc_num_guest_pages(vm->mode, psz), 0);
	virt_map(vm, RESULT_GPA, RESULT_GPA, vm_calc_num_guest_pages(vm->mode, psz));

	prot_hva = addr_gpa2hva(vm, PROT_GPA);
	for (i = 0; i < 4; i++)
		prot_hva[want[i] / 8] = SLOT_VAL;
	*(uint64_t *)addr_gpa2hva(vm, RESULT_GPA) = 0;

	/* A single override on the 16K host GFN protects the whole frame. */
	view1 = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);
	vmi_set_mem_access(vmi_fd, view1, prot_gfn, KVM_VMI_ACCESS_X);

	vmi_control_event(vmi_fd, KVM_VMI_EVENT_MEM_ACCESS, 1);
	vmi_switch_view(vmi_fd, view1);

	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* Expect exactly four faults, one per 4K sub-page, in ascending order. */
	for (i = 0; i < 4; i++) {
		uint64_t off;

		ev = vmi_wait_event_timeout(&ring, 5000);
		TEST_ASSERT(ev != NULL, "Timeout waiting for sub-page %d fault", i);
		TEST_ASSERT(ev->type == KVM_VMI_EVENT_MEM_ACCESS,
			    "Expected MEM_ACCESS, got %u", ev->type);
		TEST_ASSERT(ev->mem_access.gpa / psz == prot_gfn,
			    "Sub-page %d not in the protected host GFN 0x%lx (GPA 0x%llx)",
			    i, (unsigned long)prot_gfn,
			    (unsigned long long)ev->mem_access.gpa);
		off = ev->mem_access.gpa & (psz - 1);
		TEST_ASSERT(off == want[i],
			    "Sub-page %d faulted at offset 0x%lx, expected 0x%lx",
			    i, (unsigned long)off, (unsigned long)want[i]);
		seen++;
		ev->response = KVM_VMI_RESPONSE_SINGLESTEP_FAST;
		vmi_ack_event(&ring, 0);
	}

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");
	TEST_ASSERT(seen == 4, "Expected 4 sub-page faults, got %d", seen);

	pr_info("PASS: amplification: 1 execute-only override on host GFN 0x%lx faulted\n",
		(unsigned long)prot_gfn);
	pr_info("      all 4 sub-page offsets {0,4K,8K,12K} of the 16K frame -- %lu\n",
		(unsigned long)(psz / vm->page_size));
	pr_info("      distinct guest %luK page(s) collateral to one protected page.\n",
		(unsigned long)(vm->page_size / 1024));

	vmi_switch_view(vmi_fd, 0);
	vmi_destroy_view(vmi_fd, view1);
	vmi_teardown_ring(&ring);
	close(vmi_fd);
	kvm_vm_free(vm);
}

/* ---- autostep_neighbors (the fix) ------------------------------------- */

#define BP_SUBPAGE	0		/* the breakpoint's own 4K sub-page */
#define NEIGHBOR_OFF	0x1000		/* a fused neighbor 4K sub-page */

static void guest_autostep(void)
{
	volatile uint64_t *base = (volatile uint64_t *)PROT_GPA;
	volatile uint64_t *result = (volatile uint64_t *)RESULT_GPA;
	uint64_t sum = 0;
	int i;

	GUEST_SYNC(1);
	/* Neighbor sub-page: every read is auto-stepped in-kernel (no event). */
	for (i = 0; i < NR_ACCESS; i++)
		sum += base[NEIGHBOR_OFF / 8];
	/* Breakpoint's own sub-page: this fault IS delivered to userspace. */
	sum += base[0];
	*result = sum;
	GUEST_SYNC(2);
	GUEST_ASSERT_EQ(sum, (uint64_t)(NR_ACCESS + 1) * SLOT_VAL);
	GUEST_DONE();
}

static void run_autostep_neighbors(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	size_t psz = getpagesize();
	unsigned int nsub = psz / 4096;
	uint64_t prot_gfn = PROT_GPA / psz;
	uint64_t *prot_hva, *result_hva;
	uint32_t view1;
	uint16_t mask;
	int vmi_fd, count = 0;

	/* No page fusion at a 4K host -> nothing to auto-step; skip. */
	if (nsub < 2) {
		pr_info("SKIP: autostep neighbors (host page == 4K, no fusion)\n");
		return;
	}
	/* Auto-step every 4K sub-page of the host page except the BP's own. */
	mask = (uint16_t)(((1u << nsub) - 1) & ~(1u << BP_SUBPAGE));

	vm = vm_create_with_one_vcpu(&vcpu, guest_autostep);
	vmi_fd = vmi_create(vm);
	vmi_setup_ring(vmi_fd, 0, &ring);

	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, PROT_GPA, PROT_MEMSLOT,
				    vm_calc_num_guest_pages(vm->mode, psz), 0);
	virt_map(vm, PROT_GPA, PROT_GPA, vm_calc_num_guest_pages(vm->mode, psz));
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, RESULT_GPA,
				    RESULT_MEMSLOT,
				    vm_calc_num_guest_pages(vm->mode, psz), 0);
	virt_map(vm, RESULT_GPA, RESULT_GPA, vm_calc_num_guest_pages(vm->mode, psz));

	prot_hva = addr_gpa2hva(vm, PROT_GPA);
	result_hva = addr_gpa2hva(vm, RESULT_GPA);
	prot_hva[0] = SLOT_VAL;
	prot_hva[NEIGHBOR_OFF / 8] = SLOT_VAL;
	*result_hva = 0;

	/* Execute-only frame; auto-step the neighbor sub-pages in-kernel. */
	view1 = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);
	vmi_set_mem_access_autostep(vmi_fd, view1, prot_gfn, KVM_VMI_ACCESS_X, mask);

	vmi_control_event(vmi_fd, KVM_VMI_EVENT_MEM_ACCESS, 1);
	vmi_switch_view(vmi_fd, view1);

	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	while (!targ.done) {
		ev = vmi_wait_event_timeout(&ring, 5000);
		if (ev == NULL)
			break;

		TEST_ASSERT(ev->type == KVM_VMI_EVENT_MEM_ACCESS,
			    "Expected MEM_ACCESS, got %u", ev->type);
		/*
		 * The only fault that may reach userspace is the breakpoint's
		 * own sub-page (offset 0). A neighbor fault here means the mask
		 * was not honored -- the storm leaked to userspace.
		 */
		TEST_ASSERT((ev->mem_access.gpa & (psz - 1)) == 0,
			    "Neighbor fault leaked to userspace at offset 0x%llx (mask not honored)",
			    (unsigned long long)(ev->mem_access.gpa & (psz - 1)));
		TEST_ASSERT(ev->mem_access.gpa / psz == prot_gfn,
			    "Fault outside protected GFN: GPA 0x%llx",
			    (unsigned long long)ev->mem_access.gpa);
		count++;
		ev->response = KVM_VMI_RESPONSE_SINGLESTEP_FAST;
		vmi_ack_event(&ring, 0);
	}

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");

	/*
	 * NR_ACCESS neighbor reads were auto-stepped in-kernel (zero events);
	 * only the one breakpoint-sub-page read was delivered to userspace.
	 */
	TEST_ASSERT(count == 1,
		    "Expected exactly 1 delivered event (BP sub-page), got %d -- the %d neighbor reads should be auto-stepped in-kernel",
		    count, NR_ACCESS);
	TEST_ASSERT(*result_hva == (uint64_t)(NR_ACCESS + 1) * SLOT_VAL,
		    "Guest sum 0x%lx, expected 0x%lx (auto-step must serve clean bytes)",
		    (unsigned long)*result_hva,
		    (unsigned long)((uint64_t)(NR_ACCESS + 1) * SLOT_VAL));

	pr_info("PASS: autostep neighbors: %d neighbor reads retired in-kernel (0 events),\n",
		NR_ACCESS);
	pr_info("      1 breakpoint-sub-page read delivered to userspace (x86-identical path).\n");

	vmi_switch_view(vmi_fd, 0);
	vmi_destroy_view(vmi_fd, view1);
	vmi_teardown_ring(&ring);
	close(vmi_fd);
	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	vmi_force_el1_guests();
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_RING));

	run_read_storm();
	run_amplification();
	run_autostep_neighbors();

	return 0;
}
