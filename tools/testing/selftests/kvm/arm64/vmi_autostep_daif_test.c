// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI in-kernel auto-step DAIF-leak regression test (arm64)
 *
 * Companion to vmi_singlestep_teardown_daif_test. That test covers the DAIF
 * restore across a SESSION TEARDOWN. This one covers the DAIF restore on the
 * LIVE path: an in-kernel auto-step (KVM_VMI_SET_MEM_ACCESS autostep_mask, the
 * 16K sub-page-fusion retire-in-kernel path) masks the guest's A/I/F for the
 * one-instruction step window and must restore them when the step disarms, with
 * NO session teardown involved.
 *
 * THE BUG (observed live with kvm-trace-arm64 on a Windows guest). The VMI
 * single-step masks guest PSTATE.A/I/F in *vcpu_cpsr (kvm_vmi_mask_singlestep_daif)
 * and restores them only from a later kvm_vmi_apply_singlestep(want=false), which
 * runs only when KVM_REQ_VMI_UPDATE is pending on the next entry. daif_masked and
 * singlestep_active are decoupled flags. If the step disarms on a path that does
 * not leave a pending KVM_REQ_VMI_UPDATE (so the disarm apply never runs), the
 * vCPU re-enters the guest with A/I/F still masked -> interrupts disabled ->
 * silent spin/hang. On a real guest that needs the timer IRQ this wedges the VM
 * (vCPUs spin with IRQs masked); a selftest guest does not need interrupts, so
 * instead the guest reads its own DAIF right after the auto-stepped access and we
 * assert A/I/F were restored.
 *
 * REPRODUCTION. Mark a 16K host frame execute-only in an alt view with the
 * neighbor 4K sub-pages auto-stepped (autostep_mask), exactly like
 * vmi_xonly_storm_test's autostep scenario - but place the guest's working data
 * on an auto-stepped sub-page and have the guest unmask A/I/F, touch that data
 * (each touch is retired by an in-kernel auto-step), then read DAIF and assert it
 * was restored. Two scenarios:
 *   plain      - a plain load of an auto-stepped sub-page, in a loop, checking
 *                DAIF after each access (the access pattern of the passing
 *                autostep_neighbors test, plus the missing DAIF oracle).
 *   exclusive  - an LDXR/STXR atomic increment whose variable lives on an
 *                auto-stepped sub-page (a spinlock-class primitive). The step-ERET
 *                clears the exclusive monitor, so the STXR can fail and the loop
 *                re-faults; this is the access shape seen wedged in the field (the
 *                spinning vCPUs sat on a spinlock). Detect both a leaked DAIF and
 *                a livelock (the guest never finishing).
 *
 * GFN math is host-page based (gfn = gpa / getpagesize()); never a 4K shift.
 *
 * Markers go to stdout: some harnesses (virtme-ng) drop a test's stderr.
 */
#include <errno.h>
#include <linux/kvm.h>
#include <linux/kvm_vmi.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

#define PROT_GPA	0x10000000ULL	/* 256 MB, 16K-aligned: the protected frame */
#define RESULT_GPA	0x10100000ULL	/* far away, different 16K frame, always RWX */
#define PROT_MEMSLOT	10
#define RESULT_MEMSLOT	11

#define NEIGHBOR_OFF	0x1000		/* a fused neighbor 4K sub-page (auto-stepped) */
#define BP_SUBPAGE	0		/* the "breakpoint" sub-page (delivered) */
#define NR_ACCESS	256		/* auto-stepped accesses per scenario */

#define NR_CONTEND_VCPUS	2	/* contention scenario vCPU count */
#define NR_INC			128	/* atomic increments per contending vCPU */

/* PSTATE/SPSR async-exception mask bits (D=9, A=8, I=7, F=6). */
#define PSTATE_A	(1 << 8)
#define PSTATE_I	(1 << 7)
#define PSTATE_F	(1 << 6)
#define PSTATE_AIF	(PSTATE_A | PSTATE_I | PSTATE_F)

/* Guest -> host result slots in the RWX result page. */
#define R_DONE		0	/* set to 1 when the guest finished the loop */
#define R_DAIF		1	/* DAIF observed after an auto-stepped access */
#define R_ITER		2	/* iteration at which a leak was caught (or NR_ACCESS) */
#define R_SUM		3	/* data checksum (auto-step must serve clean bytes) */

/* ---- plain: load an auto-stepped sub-page, check DAIF after each ------- */

static void guest_plain(void)
{
	volatile uint64_t *base = (volatile uint64_t *)PROT_GPA;
	volatile uint64_t *result = (volatile uint64_t *)RESULT_GPA;
	uint64_t sum = 0, daif = 0;
	int i;

	GUEST_SYNC(1);
	/* Unmask A/I/F so a leaked single-step mask is observable as nonzero. */
	asm volatile("msr daifclr, #7");

	for (i = 0; i < NR_ACCESS; i++) {
		sum += base[NEIGHBOR_OFF / 8];		/* faults -> in-kernel auto-step */
		asm volatile("mrs %0, daif" : "=r"(daif));
		if (daif & PSTATE_AIF)
			break;				/* caught a leaked mask */
	}

	result[R_DAIF] = daif;
	result[R_ITER] = i;
	result[R_SUM] = sum;
	result[R_DONE] = 1;
	GUEST_SYNC(2);
	GUEST_DONE();
}

/* ---- exclusive: LDXR/STXR atomic on an auto-stepped sub-page ----------- */

static void guest_exclusive(void)
{
	volatile uint64_t *base = (volatile uint64_t *)PROT_GPA;
	volatile uint64_t *result = (volatile uint64_t *)RESULT_GPA;
	uint64_t daif = 0, val, succeeded = 0;
	uint32_t st;
	int i;

	GUEST_SYNC(1);
	asm volatile("msr daifclr, #7");

	for (i = 0; i < NR_ACCESS; i++) {
		/*
		 * ONE LDXR/STXR attempt (no in-asm retry) on a variable that lives
		 * on the auto-stepped sub-page. Each access faults and is retired by
		 * an in-kernel auto-step. Record whether the STXR succeeded: if the
		 * step round-trip clears the exclusive monitor, STXR returns nonzero
		 * (fail) every time and a real atomic/spinlock can never progress.
		 */
		asm volatile(
			"ldxr %0, [%3]\n\t"
			"add  %0, %0, #1\n\t"
			"stxr %w1, %0, [%3]\n\t"
			: "=&r"(val), "=&r"(st), "+m"(*(base + NEIGHBOR_OFF / 8))
			: "r"(base + NEIGHBOR_OFF / 8)
			: "memory");
		if (st == 0)
			succeeded++;
		asm volatile("mrs %0, daif" : "=r"(daif));
		if (daif & PSTATE_AIF)
			break;
	}

	result[R_DAIF] = daif;
	result[R_ITER] = succeeded;	/* number of successful STXRs */
	result[R_SUM] = base[NEIGHBOR_OFF / 8];
	result[R_DONE] = 1;
	GUEST_SYNC(2);
	GUEST_DONE();
}

/* ---- contention: real spinlock-class atomic on an auto-stepped var --- */

static void guest_contend(void)
{
	volatile uint64_t *ctr = (volatile uint64_t *)(PROT_GPA + NEIGHBOR_OFF);
	uint64_t tmp;
	uint32_t st;
	int i;

	/*
	 * Atomically increment a shared counter that lives on an auto-stepped
	 * sub-page, with the architectural LDXR/STXR retry loop. Run on multiple
	 * vCPUs: contention makes the STXR genuinely fail and retry, exercising the
	 * atomic-step retry path. If the auto-step cleared the exclusive monitor
	 * the STXR could never succeed and this would livelock (caught by timeout).
	 */
	for (i = 0; i < NR_INC; i++) {
		asm volatile(
			"1: ldxr %0, [%2]\n\t"
			"   add  %0, %0, #1\n\t"
			"   stxr %w1, %0, [%2]\n\t"
			"   cbnz %w1, 1b\n\t"
			: "=&r"(tmp), "=&r"(st)
			: "r"(ctr)
			: "memory");
	}
	GUEST_DONE();
}

/* Run the vCPU; absorb ucalls. Any auto-stepped access stays in-kernel, so
 * normally no ring event arrives and the guest runs to GUEST_DONE. */
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

static void run_scenario(const char *name, void (*guest_fn)(void), bool atomic)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	size_t psz = getpagesize();
	unsigned int nsub = psz / 4096;
	uint64_t prot_gfn = PROT_GPA / psz;
	uint64_t *prot_hva, *result_hva;
	uint32_t view1;
	uint16_t mask;
	int vmi_fd, t;

	if (nsub < 2) {
		pr_info("SKIP: %s (host page == 4K, no fusion -> no auto-step)\n", name);
		return;
	}
	/* Auto-step every 4K sub-page of the host frame except the BP's own. */
	mask = (uint16_t)(((1u << nsub) - 1) & ~(1u << BP_SUBPAGE));

	vm = vm_create_with_one_vcpu(&vcpu, guest_fn);
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
	prot_hva[NEIGHBOR_OFF / 8] = 0;
	memset(result_hva, 0, psz);

	/* Execute-only frame; auto-step the neighbor sub-pages in-kernel. */
	view1 = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);
	vmi_set_mem_access_autostep(vmi_fd, view1, prot_gfn, KVM_VMI_ACCESS_X, mask);

	vmi_control_event(vmi_fd, KVM_VMI_EVENT_MEM_ACCESS, 1);
	vmi_switch_view(vmi_fd, view1);

	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vcpu_thread_fn, &targ);

	/*
	 * Wait for the guest to finish the loop. A leaked DAIF does not stop a
	 * selftest guest, so it will finish and report; a livelock (exclusive
	 * monitor lost to the step) will NOT, which we treat as the same failure.
	 */
	for (t = 0; t < 15000 && !READ_ONCE(result_hva[R_DONE]) && !targ.done; t += 5)
		usleep(5000);

	TEST_ASSERT(READ_ONCE(result_hva[R_DONE]) == 1,
		    "%s: guest did not finish (auto-step livelock over the exclusive access)",
		    name);
	if (atomic)
		TEST_ASSERT(result_hva[R_ITER] > 0,
			    "%s: 0/%d STXR succeeded -- the auto-step round-trip clears the exclusive monitor, so atomics/spinlocks livelock",
			    name, NR_ACCESS);
	TEST_ASSERT(!(result_hva[R_DAIF] & PSTATE_AIF),
		    "%s: guest DAIF not restored after auto-step: 0x%lx (A/I/F masked)",
		    name, (unsigned long)result_hva[R_DAIF]);

	pr_info("PASS: %s: %d auto-stepped accesses, %lu STXR ok, DAIF restored (0x%lx)\n",
		name, NR_ACCESS, (unsigned long)result_hva[R_ITER],
		(unsigned long)result_hva[R_DAIF]);

	targ.done = 1;
	pthread_join(thread, NULL);

	vmi_switch_view(vmi_fd, 0);
	vmi_destroy_view(vmi_fd, view1);
	vmi_teardown_ring(&ring);
	close(vmi_fd);
	kvm_vm_free(vm);
}

static void run_contention(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpus[NR_CONTEND_VCPUS];
	struct vmi_vcpu_thread_arg targ[NR_CONTEND_VCPUS] = {};
	pthread_t threads[NR_CONTEND_VCPUS];
	struct vmi_test_ring ring;
	size_t psz = getpagesize();
	unsigned int nsub = psz / 4096;
	uint64_t prot_gfn = PROT_GPA / psz;
	uint64_t *prot_hva, *ctr_hva;
	uint32_t view1;
	uint16_t mask;
	int vmi_fd, i, t, done;

	if (nsub < 2) {
		pr_info("SKIP: contention (host page == 4K, no fusion -> no auto-step)\n");
		return;
	}
	mask = (uint16_t)(((1u << nsub) - 1) & ~(1u << BP_SUBPAGE));

	vm = vm_create_with_vcpus(NR_CONTEND_VCPUS, guest_contend, vcpus);
	vmi_fd = vmi_create(vm);
	vmi_setup_ring(vmi_fd, 0, &ring);

	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, PROT_GPA, PROT_MEMSLOT,
				    vm_calc_num_guest_pages(vm->mode, psz), 0);
	virt_map(vm, PROT_GPA, PROT_GPA, vm_calc_num_guest_pages(vm->mode, psz));
	prot_hva = addr_gpa2hva(vm, PROT_GPA);
	ctr_hva = (uint64_t *)((char *)prot_hva + NEIGHBOR_OFF);
	*ctr_hva = 0;

	view1 = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);
	vmi_set_mem_access_autostep(vmi_fd, view1, prot_gfn, KVM_VMI_ACCESS_X, mask);
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_MEM_ACCESS, 1);
	vmi_switch_view(vmi_fd, view1);

	for (i = 0; i < NR_CONTEND_VCPUS; i++) {
		targ[i].vcpu = vcpus[i];
		targ[i].done = 0;
		pthread_create(&threads[i], NULL, vcpu_thread_fn, &targ[i]);
	}

	/* Wait for both vCPUs to finish; a broken atomic step livelocks here. */
	for (t = 0; t < 20000; t += 5) {
		done = 0;
		for (i = 0; i < NR_CONTEND_VCPUS; i++)
			done += READ_ONCE(targ[i].done);
		if (done == NR_CONTEND_VCPUS)
			break;
		usleep(5000);
	}

	for (i = 0; i < NR_CONTEND_VCPUS; i++)
		TEST_ASSERT(READ_ONCE(targ[i].done),
			    "contention: vCPU %d did not finish (atomic-step livelock under contention)",
			    i);

	for (i = 0; i < NR_CONTEND_VCPUS; i++)
		pthread_join(threads[i], NULL);

	TEST_ASSERT(*ctr_hva == (uint64_t)NR_CONTEND_VCPUS * NR_INC,
		    "contention: counter %lu, expected %lu (lost atomic increments)",
		    (unsigned long)*ctr_hva,
		    (unsigned long)((uint64_t)NR_CONTEND_VCPUS * NR_INC));

	pr_info("PASS: contention: %d vCPUs x %d atomic incs on an auto-stepped var -> counter %lu\n",
		NR_CONTEND_VCPUS, NR_INC, (unsigned long)*ctr_hva);

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

	run_scenario("plain-load", guest_plain, false);
	run_scenario("exclusive-atomic", guest_exclusive, true);
	run_contention();

	return 0;
}
