// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI two-co-resident X-only breakpoints, multi-vCPU + mid-run teardown
 * (arm64, 16K).
 *
 * Reproduces a guest-destabilizing bug seen live: a VMI agent that keeps TWO
 * software breakpoints in ONE 16K host frame (two fused 4K guest sub-pages)
 * execute-only (X-only stealth) in an alternate view on a multi-vCPU guest,
 * and steps over every BRK and stealth-read fault via SWITCH_VIEW|FAST_SS,
 * crashes the GUEST at/after teardown. A single vCPU, a single breakpoint, or
 * no-stealth (RWX) does not.
 *
 * The suspected mechanism is a teardown/fast-step race that needs concurrency:
 * the agent destroys the trap view while ANOTHER vCPU still references it (mid
 * in-kernel fast-singlestep whose restore target IS that view, or hw_mmu still
 * pointing at the view's stage-2). Two co-resident BPs (plus the X-only read
 * redirects they add) keep more vCPUs faulting on the shared frame at once,
 * widening the window vs a single BP, and a single vCPU cannot hit it at all
 * (it is parked on its ring during teardown, with no fast-step in flight).
 *
 * Layout (one 16K host frame = FUNC_GPA, four fused 4K sub-pages):
 *   sub-page 0 (FUNC_GPA+0x0000): function A, first insn replaced by BRK in shadow
 *   sub-page 1 (FUNC_GPA+0x1000): function B, first insn replaced by BRK in shadow
 *   sub-page 2..3: neighbors (auto-stepped by the mask)
 * All NR_VCPUS vCPUs call both functions and read sub-page 0 (a BP page) in a
 * loop. Each vCPU has its own counter and result slot (no cross-vCPU sharing).
 * The X-only read of a BP page is redirected to the clean view, so it must see
 * the ORIGINAL instruction word, never the planted BRK.
 *
 * The agent installs both BPs, runs the vCPUs under stealth, and TEARS DOWN
 * mid-run (switch to view 0, disable monitoring, revert the GFN remap, destroy
 * the trap view) from the main thread while the vCPUs are still faulting. It
 * then lets every vCPU finish on the clean view. Detection is by clean
 * completion: a teardown/fast-step desync hangs or corrupts a vCPU, so it never
 * reaches GUEST_DONE (its join blocks to the kselftest timeout) or finishes
 * with a wrong counter. Success = every vCPU completes, every counter is exact,
 * and every stealth read saw clean code.
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
#define COUNTER_GPA	0x10004000ULL	/* +16K: per-vCPU counters */
#define RESULT_GPA	0x10008000ULL	/* +32K: per-vCPU stealth-clean counts */
#define FUNC_MEMSLOT	10
#define COUNTER_MEMSLOT	11
#define RESULT_MEMSLOT	12

#define FN_A_OFF	0x0000		/* sub-page 0 */
#define FN_B_OFF	0x1000		/* sub-page 1 */

#define LOOP		400		/* iterations per vCPU; each calls A and B */
#define TEARDOWN_AFTER	100		/* tear down after this many events (all rings) */

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
	uint64_t counter_addr = COUNTER_GPA + idx * sizeof(uint64_t);
	volatile uint64_t *result = (volatile uint64_t *)(RESULT_GPA +
							  idx * sizeof(uint64_t));
	uint64_t clean = 0;
	int i;

	for (i = 0; i < LOOP; i++) {
		fn_a(counter_addr);	/* BRK at sub-page 0 */
		fn_b(counter_addr);	/* BRK at sub-page 1 */
		/* Read a BP page: under X-only stealth this is redirected to the
		 * clean view and must read the original instruction, not BRK. */
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
	uint32_t clean_view, trap_view;
	uint16_t mask;
	volatile int events = 0, stop = 0;
	int vmi_fd, i;

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

	func_hva = addr_gpa2hva(vm, FUNC_GPA);
	counter_hva = addr_gpa2hva(vm, COUNTER_GPA);
	result_hva = addr_gpa2hva(vm, RESULT_GPA);
	memcpy((uint8_t *)func_hva + FN_A_OFF, func_code, sizeof(func_code));
	memcpy((uint8_t *)func_hva + FN_B_OFF, func_code, sizeof(func_code));
	memset(counter_hva, 0, NR_VCPUS * sizeof(uint64_t));
	memset(result_hva, 0, NR_VCPUS * sizeof(uint64_t));

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
	trap_view = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);

	/* Trap view: remap the func frame to the shadow, and make it X-only so
	 * data reads of the BP pages are redirected (PatchGuard stealth). The
	 * combined mask delivers both BP sub-pages and auto-steps the rest. */
	vmi_change_gfn(vmi_fd, trap_view, func_gfn, shadow_gfn);
	vmi_set_mem_access_autostep(vmi_fd, trap_view, func_gfn,
				    KVM_VMI_ACCESS_X, mask);

	vmi_control_event(vmi_fd, KVM_VMI_EVENT_BREAKPOINT, 1);
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_MEM_ACCESS, 1);
	vmi_switch_view(vmi_fd, trap_view);

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

	/* Tear the stealth down WHILE the vCPUs are still faulting, in the same
	 * order the live reactor does. A vCPU mid-fast-step whose restore target
	 * is trap_view, or whose hw_mmu still points at trap_view's stage-2, now
	 * races destroy_view. */
	while (events < TEARDOWN_AFTER)
		usleep(1000);
	vmi_switch_view(vmi_fd, 0);
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_BREAKPOINT, 0);
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_MEM_ACCESS, 0);
	vmi_change_gfn(vmi_fd, trap_view, func_gfn, KVM_VMI_INVALID_GFN);
	vmi_destroy_view(vmi_fd, trap_view);

	/* Every vCPU must reach GUEST_DONE on the clean view. A hang here (join
	 * never returns) is the bug, caught by the kselftest timeout. */
	for (i = 0; i < NR_VCPUS; i++)
		pthread_join(vthread[i], NULL);
	stop = 1;
	for (i = 0; i < NR_VCPUS; i++)
		pthread_join(rthread[i], NULL);

	for (i = 0; i < NR_VCPUS; i++) {
		TEST_ASSERT(targ[i].done, "vCPU %d did not complete", i);
		TEST_ASSERT(counter_hva[i] == (uint64_t)LOOP * 2,
			    "vCPU %d counter %lu, expected %d (did not run cleanly)",
			    i, (unsigned long)counter_hva[i], LOOP * 2);
		TEST_ASSERT(result_hva[i] == (uint64_t)LOOP,
			    "vCPU %d stealth-clean reads %lu, expected %d (BRK leaked)",
			    i, (unsigned long)result_hva[i], LOOP);
	}

	vmi_switch_view(vmi_fd, 0);
	vmi_destroy_view(vmi_fd, clean_view);
	munmap(shadow, psz);
	vmi_free_gfn(vmi_fd, shadow_gfn);
	for (i = 0; i < NR_VCPUS; i++)
		vmi_teardown_ring(&rings[i]);
	close(vmi_fd);
	kvm_vm_free(vm);

	pr_info("PASS: co-resident X-only teardown (%d vCPUs): %d events, all counters=%d\n",
		NR_VCPUS, events, LOOP * 2);
	return 0;
}
