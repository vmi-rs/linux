// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI teardown stress: residual fast-singlestep vs VM-wide-switch race
 * (arm64, 16K).
 *
 * The targeted fix "KVM: VMI: redirect fast-singlestep restore on a VM-wide
 * view switch" closed the DETERMINISTIC single-teardown case
 * (vmi_xonly_coresident_test), but a residual cross-vCPU race remained: the
 * VM-wide KVM_VMI_SWITCH_VIEW ioctl mutated each vCPU's view state (the view
 * refcounts and the fast-singlestep restore target) from the agent thread,
 * unserialized against the vCPU's OWN fast-singlestep completion. Under
 * repeated teardowns it intermittently left a refcount on the trap view, so
 * KVM_VMI_DESTROY_VIEW returned -EBUSY (a leaked view). It reproduced ~1/6 on a
 * live guest doing back-to-back stealth passes.
 *
 * This test hammers exactly that window. NR_VCPUS vCPUs free-run, continuously
 * faulting on two co-resident X-only breakpoints in a trap view; per-ring
 * responders fast-step every fault back to a clean view (restore target = the
 * trap view). The main thread repeatedly: create a trap view, remap the BP
 * frame to the X-only shadow, switch ALL vCPUs onto it, let fast-steps flow,
 * then switch back to view 0 and DESTROY the trap view -- STRESS_ITERS times.
 * Every destroy must succeed: a single -EBUSY is the residual race, and a hung
 * vCPU (never reaches GUEST_DONE) is a teardown desync. The per-vCPU view_lock
 * serializing the VM-wide switch against the fast-singlestep completion is what
 * makes every destroy clean.
 *
 * GFN math is host-page based (gfn = gpa / getpagesize()); never a 4K shift.
 */
#include <errno.h>
#include <linux/kvm.h>
#include <linux/kvm_vmi.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

#define NR_VCPUS	4

#define FUNC_GPA	0x10000000ULL	/* 256 MB, 16K-aligned: the two functions */
#define COUNTER_GPA	0x10004000ULL	/* +16K: per-vCPU function-call counters */
#define RESULT_GPA	0x10008000ULL	/* +32K: per-vCPU stealth-clean read counts */
#define STOP_GPA	0x1000C000ULL	/* +48K: shared stop flag */
#define FUNC_MEMSLOT	10
#define COUNTER_MEMSLOT	11
#define RESULT_MEMSLOT	12
#define STOP_MEMSLOT	13

#define FN_A_OFF	0x0000		/* sub-page 0 */
#define FN_B_OFF	0x1000		/* sub-page 1 */

#define STRESS_ITERS	120		/* create/switch/fault/teardown/destroy cycles */
#define EVENTS_PER_ITER	24		/* fast-steps to let flow before each teardown */
#define EVENT_WAIT_MS	3000		/* per-iter cap waiting for events to flow */

/*
 * Target function; counter address in x0 (AAPCS64). The shadow copy replaces
 * the first instruction (the LDR) with BRK #0.
 *   ldr x1, [x0] ; add x1, x1, #1 ; str x1, [x0] ; ret
 */
static const uint32_t func_code[] = {
	0xF9400001,	/* ldr x1, [x0] */
	0x91000421,	/* add x1, x1, #1 */
	0xF9000001,	/* str x1, [x0] */
	0xD65F03C0,	/* ret */
};
#define FUNC_LDR0	0xF9400001u	/* the clean first word a stealth read must see */
#define BRK_INSN	0xD4200000u	/* brk #0 */

static void guest_code(uint64_t idx)
{
	void (*fn_a)(uint64_t) = (void (*)(uint64_t))(FUNC_GPA + FN_A_OFF);
	void (*fn_b)(uint64_t) = (void (*)(uint64_t))(FUNC_GPA + FN_B_OFF);
	volatile uint32_t *bp_word = (volatile uint32_t *)(FUNC_GPA + FN_A_OFF);
	volatile uint32_t *stop = (volatile uint32_t *)STOP_GPA;
	uint64_t counter_addr = COUNTER_GPA + idx * sizeof(uint64_t);
	volatile uint64_t *result = (volatile uint64_t *)(RESULT_GPA +
							  idx * sizeof(uint64_t));
	uint64_t clean = 0;

	/*
	 * Free-run until the agent is done stressing teardown. Each iteration
	 * completes fully before re-checking @stop, so on exit the per-vCPU
	 * function counter is exactly twice the clean-read count iff every BP
	 * page read was redirected to clean code (no BRK leaked) and both BPs
	 * fast-stepped correctly.
	 */
	while (!*stop) {
		fn_a(counter_addr);	/* BRK at sub-page 0 when on the trap view */
		fn_b(counter_addr);	/* BRK at sub-page 1 when on the trap view */
		if (*bp_word == FUNC_LDR0)
			clean++;
	}
	*result = clean;
	GUEST_DONE();
}

/* Per-ring responder: drains one vCPU's ring and fast-steps every fault on the
 * clean view, until the main thread signals stop. */
struct responder_arg {
	struct vmi_test_ring *ring;
	uint32_t vcpu_id;
	uint32_t clean_view;
	volatile int *events;
	volatile int *stop;
};

static void *responder_fn(void *arg)
{
	struct responder_arg *ra = arg;
	struct kvm_vmi_ring_event *ev;

	while (!*ra->stop) {
		ev = vmi_wait_event_timeout(ra->ring, 100);
		if (ev == NULL)
			continue;

		TEST_ASSERT(ev->type == KVM_VMI_EVENT_BREAKPOINT ||
			    ev->type == KVM_VMI_EVENT_MEM_ACCESS,
			    "vCPU %u: unexpected event %u (SINGLESTEP leaked?)",
			    ra->vcpu_id, ev->type);

		ev->response = KVM_VMI_RESPONSE_SWITCH_VIEW |
			       KVM_VMI_RESPONSE_SINGLESTEP_FAST;
		ev->view_id = ra->clean_view;
		vmi_ack_event(ra->ring, ra->vcpu_id);
		(*ra->events)++;
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpus[NR_VCPUS];
	struct vmi_test_ring rings[NR_VCPUS];
	struct vmi_vcpu_thread_arg targ[NR_VCPUS];
	struct responder_arg rarg[NR_VCPUS];
	pthread_t vthread[NR_VCPUS], rthread[NR_VCPUS];
	size_t psz = getpagesize();
	unsigned int nsub = psz / 4096;
	uint64_t func_gfn = FUNC_GPA / psz;
	uint64_t shadow_gfn;
	uint32_t *func_hva, *shadow;
	uint64_t *counter_hva, *result_hva;
	uint32_t *stop_hva;
	uint32_t clean_view;
	uint16_t mask;
	volatile int events = 0, stop = 0;
	int vmi_fd, i, iter;
	int ebusy = 0, last_ebusy_iter = -1;

	vmi_force_el1_guests();
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_RING));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_ALLOC_GFN));

	/* No 16K/4K fusion on a 4K host: two co-resident BPs cannot share a
	 * frame, so the scenario does not exist. */
	if (nsub < 2) {
		pr_info("SKIP: co-resident X-only (host page == 4K, no fusion)\n");
		return KSFT_SKIP;
	}
	/* Deliver both BP sub-pages (0 and 1); auto-step the true neighbors. */
	mask = (uint16_t)(((1u << nsub) - 1) & ~((1u << 0) | (1u << 1)));

	vm = vm_create_with_vcpus(NR_VCPUS, guest_code, vcpus);
	vmi_fd = vmi_create(vm);
	for (i = 0; i < NR_VCPUS; i++) {
		vcpu_args_set(vcpus[i], 1, (uint64_t)i);
		vmi_setup_ring(vmi_fd, i, &rings[i]);
	}

	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, FUNC_GPA, FUNC_MEMSLOT,
				    vm_calc_num_guest_pages(vm->mode, psz), 0);
	virt_map(vm, FUNC_GPA, FUNC_GPA, vm_calc_num_guest_pages(vm->mode, psz));
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, COUNTER_GPA,
				    COUNTER_MEMSLOT,
				    vm_calc_num_guest_pages(vm->mode, psz), 0);
	virt_map(vm, COUNTER_GPA, COUNTER_GPA, vm_calc_num_guest_pages(vm->mode, psz));
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, RESULT_GPA,
				    RESULT_MEMSLOT,
				    vm_calc_num_guest_pages(vm->mode, psz), 0);
	virt_map(vm, RESULT_GPA, RESULT_GPA, vm_calc_num_guest_pages(vm->mode, psz));
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, STOP_GPA,
				    STOP_MEMSLOT,
				    vm_calc_num_guest_pages(vm->mode, psz), 0);
	virt_map(vm, STOP_GPA, STOP_GPA, vm_calc_num_guest_pages(vm->mode, psz));

	func_hva = addr_gpa2hva(vm, FUNC_GPA);
	counter_hva = addr_gpa2hva(vm, COUNTER_GPA);
	result_hva = addr_gpa2hva(vm, RESULT_GPA);
	stop_hva = addr_gpa2hva(vm, STOP_GPA);
	memcpy((uint8_t *)func_hva + FN_A_OFF, func_code, sizeof(func_code));
	memcpy((uint8_t *)func_hva + FN_B_OFF, func_code, sizeof(func_code));
	memset(counter_hva, 0, NR_VCPUS * sizeof(uint64_t));
	memset(result_hva, 0, NR_VCPUS * sizeof(uint64_t));
	*stop_hva = 0;

	/* Shadow: a 16K copy of the func frame with BRK planted at both
	 * functions' first instruction. One shadow, two co-resident BPs. */
	shadow_gfn = vmi_alloc_gfn(vmi_fd);
	shadow = mmap(NULL, psz, PROT_READ | PROT_WRITE, MAP_SHARED, vmi_fd,
		      shadow_gfn * psz);
	TEST_ASSERT(shadow != MAP_FAILED, "mmap shadow failed: %d", errno);
	memcpy(shadow, func_hva, psz);
	shadow[FN_A_OFF / 4] = BRK_INSN;
	shadow[FN_B_OFF / 4] = BRK_INSN;

	clean_view = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);

	vmi_control_event(vmi_fd, KVM_VMI_EVENT_BREAKPOINT, 1);
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_MEM_ACCESS, 1);

	/* Responders first, so no vCPU blocks undrained; then the vCPUs. */
	for (i = 0; i < NR_VCPUS; i++) {
		rarg[i].ring = &rings[i];
		rarg[i].vcpu_id = i;
		rarg[i].clean_view = clean_view;
		rarg[i].events = &events;
		rarg[i].stop = &stop;
		pthread_create(&rthread[i], NULL, responder_fn, &rarg[i]);
	}
	for (i = 0; i < NR_VCPUS; i++) {
		targ[i].vcpu = vcpus[i];
		targ[i].done = 0;
		pthread_create(&vthread[i], NULL, vmi_vcpu_thread_fn, &targ[i]);
	}

	/*
	 * Repeatedly attach a fresh trap view, let fast-steps flow on it, then
	 * switch everyone back to view 0 and destroy it -- the exact attach/
	 * teardown cycle the live reactor does back-to-back. Each destroy is a
	 * chance for a fast-singlestep completing in the teardown window to
	 * resurrect the trap view's refcount.
	 */
	for (iter = 0; iter < STRESS_ITERS; iter++) {
		uint32_t trap_view = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);
		int target, waited = 0, err;

		/* Trap view: remap the func frame to the X-only shadow so reads
		 * of the BP pages are redirected; the mask delivers both BP
		 * sub-pages and auto-steps the rest. */
		vmi_change_gfn(vmi_fd, trap_view, func_gfn, shadow_gfn);
		vmi_set_mem_access_autostep(vmi_fd, trap_view, func_gfn,
					    KVM_VMI_ACCESS_X, mask);
		vmi_switch_view(vmi_fd, trap_view);

		/* Let fast-steps (restore target = trap_view) flow. */
		target = events + EVENTS_PER_ITER;
		while (events < target && waited < EVENT_WAIT_MS) {
			usleep(1000);
			waited++;
		}

		/* Tear down in the live reactor's order, then destroy. */
		vmi_switch_view(vmi_fd, 0);
		vmi_change_gfn(vmi_fd, trap_view, func_gfn, KVM_VMI_INVALID_GFN);

		err = vmi_destroy_view_err(vmi_fd, trap_view);
		if (err) {
			ebusy++;
			last_ebusy_iter = iter;
			/* The view leaked (refcount stuck); stop so leaked
			 * stage-2 mmus do not pile up. The failure is reported
			 * below. */
			break;
		}
	}

	/* Stop the guests and the responders. */
	WRITE_ONCE(*stop_hva, 1);
	for (i = 0; i < NR_VCPUS; i++)
		pthread_join(vthread[i], NULL);
	stop = 1;
	for (i = 0; i < NR_VCPUS; i++)
		pthread_join(rthread[i], NULL);

	TEST_ASSERT(ebusy == 0,
		    "destroy_view -EBUSY on iter %d (residual fast-step/switch race); %d of %d teardowns leaked",
		    last_ebusy_iter, ebusy, STRESS_ITERS);

	for (i = 0; i < NR_VCPUS; i++) {
		TEST_ASSERT(targ[i].done, "vCPU %d did not complete (teardown desync)", i);
		TEST_ASSERT(result_hva[i] > 0, "vCPU %d made no progress", i);
		TEST_ASSERT(counter_hva[i] == 2 * result_hva[i],
			    "vCPU %d counter %lu != 2*clean %lu (BRK leaked or step corrupted)",
			    i, (unsigned long)counter_hva[i],
			    (unsigned long)result_hva[i]);
	}

	vmi_switch_view(vmi_fd, 0);
	vmi_destroy_view(vmi_fd, clean_view);
	munmap(shadow, psz);
	vmi_free_gfn(vmi_fd, shadow_gfn);
	for (i = 0; i < NR_VCPUS; i++)
		vmi_teardown_ring(&rings[i]);
	close(vmi_fd);
	kvm_vm_free(vm);

	pr_info("PASS: teardown stress (%d vCPUs, %d teardowns): %d events, 0 -EBUSY\n",
		NR_VCPUS, STRESS_ITERS, events);
	return 0;
}
