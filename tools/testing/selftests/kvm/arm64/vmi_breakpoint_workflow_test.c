// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI breakpoint workflow integration test (arm64, K13)
 *
 * The complete shadow-page breakpoint loop:
 *   clean view: original code page.
 *   trap view:  code GFN remapped to a shadow page whose FIRST instruction is
 *               replaced by BRK #0.
 * Per hit (vCPU in the trap view):
 *   1. PC at func+0 = BRK -> BREAKPOINT event (PC stays at the BRK).
 *   2. Agent responds SWITCH_VIEW(clean) | SINGLESTEP_FAST.
 *   3. Kernel steps the original first instruction (LDR) in the clean view,
 *      auto-returns to the trap view (no singlestep event).
 *   4. func+4.. (ADD/STR/RET, unchanged in the shadow) run in the trap view;
 *      the function returns having incremented the counter once.
 *   5. Next iteration re-traps.
 * After N iterations the breakpoint count and the guest counter must both == N.
 *
 * The LDR-in-clean / ADD+STR-in-trap split still increments correctly because
 * registers and the (un-remapped) counter page are view-independent.
 *
 * Run twice: shadow page backed by a normal memslot, and by KVM_VMI_ALLOC_GFN
 * (mirroring x86 vmi_alloc_gfn_test Test 4).
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

#define FUNC_GPA	0x10000000ULL	/* 256 MB, 16K-aligned: target function */
#define COUNTER_GPA	0x10004000ULL	/* +16K: counter incremented by the function */
#define SHADOW_GPA	0x10008000ULL	/* +32K: shadow page (memslot variant only) */
#define FUNC_MEMSLOT	10
#define COUNTER_MEMSLOT	11
#define SHADOW_MEMSLOT	12

#define BP_ITERATIONS	20

/*
 * Target function; the counter address is passed in x0 (AAPCS64). The shadow
 * copy replaces func_code[0] (the LDR) with BRK #0.
 *   ldr x1, [x0] ; add x1, x1, #1 ; str x1, [x0] ; ret
 */
static const uint32_t func_code[] = {
	0xF9400001,	/* ldr x1, [x0] */
	0x91000421,	/* add x1, x1, #1 */
	0xF9000001,	/* str x1, [x0] */
	0xD65F03C0,	/* ret */
};
#define BRK_INSN	0xD4200000u	/* brk #0 */

static void guest_code(void)
{
	void (*fn)(uint64_t) = (void (*)(uint64_t))FUNC_GPA;
	volatile uint64_t *counter = (volatile uint64_t *)COUNTER_GPA;
	int i;

	GUEST_SYNC(1);
	for (i = 0; i < BP_ITERATIONS; i++)
		fn(COUNTER_GPA);
	GUEST_SYNC(*counter);
	GUEST_DONE();
}

static void run_workflow(bool use_alloc_gfn)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	size_t psz = getpagesize();
	uint64_t func_gfn = FUNC_GPA / psz;
	uint64_t shadow_gfn;
	uint32_t *func_hva, *shadow = NULL;
	uint64_t *counter_hva;
	uint32_t clean_view, trap_view;
	int vmi_fd, bp_count = 0;

	vm = vm_create_with_one_vcpu(&vcpu, guest_code);
	vmi_fd = vmi_create(vm);
	vmi_setup_ring(vmi_fd, 0, &ring);

	/* Code page (executable) + counter page; both mapped in the guest. */
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, FUNC_GPA, FUNC_MEMSLOT,
				    vm_calc_num_guest_pages(vm->mode, psz), 0);
	virt_map(vm, FUNC_GPA, FUNC_GPA, vm_calc_num_guest_pages(vm->mode, psz));
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, COUNTER_GPA,
				    COUNTER_MEMSLOT,
				    vm_calc_num_guest_pages(vm->mode, psz), 0);
	virt_map(vm, COUNTER_GPA, COUNTER_GPA, vm_calc_num_guest_pages(vm->mode, psz));

	func_hva = addr_gpa2hva(vm, FUNC_GPA);
	counter_hva = addr_gpa2hva(vm, COUNTER_GPA);
	memcpy(func_hva, func_code, sizeof(func_code));
	*counter_hva = 0;

	/*
	 * Shadow page: a copy of the function with the first instruction
	 * replaced by BRK. Sourced either from a normal memslot or from
	 * KVM_VMI_ALLOC_GFN (a VMI shadow page, mmap'd via the vmi_fd).
	 */
	if (use_alloc_gfn) {
		shadow_gfn = vmi_alloc_gfn(vmi_fd);
		shadow = mmap(NULL, psz, PROT_READ | PROT_WRITE, MAP_SHARED,
			      vmi_fd, shadow_gfn * psz);
		TEST_ASSERT(shadow != MAP_FAILED, "mmap shadow failed: %d", errno);
	} else {
		vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, SHADOW_GPA,
					    SHADOW_MEMSLOT,
					    vm_calc_num_guest_pages(vm->mode, psz), 0);
		/* No virt_map: the shadow is reached only via the GFN remap. */
		shadow = addr_gpa2hva(vm, SHADOW_GPA);
		shadow_gfn = SHADOW_GPA / psz;
	}
	memcpy(shadow, func_code, sizeof(func_code));
	shadow[0] = BRK_INSN;

	clean_view = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);
	trap_view = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);

	/* Trap view: remap the code GFN to the shadow page. Clean view: original. */
	vmi_change_gfn(vmi_fd, trap_view, func_gfn, shadow_gfn);

	vmi_control_event(vmi_fd, KVM_VMI_EVENT_BREAKPOINT, 1);
	vmi_switch_view(vmi_fd, trap_view);

	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	while (!targ.done) {
		ev = vmi_wait_event_timeout(&ring, 5000);
		if (ev == NULL)
			break;

		TEST_ASSERT(ev->type == KVM_VMI_EVENT_BREAKPOINT,
			    "Unexpected event type %u (no SINGLESTEP must leak)",
			    ev->type);
		bp_count++;

		/* Fast step the original instruction in the clean view, then
		 * auto-return to the trap view (no singlestep event). */
		ev->response = KVM_VMI_RESPONSE_SWITCH_VIEW |
			       KVM_VMI_RESPONSE_SINGLESTEP_FAST;
		ev->view_id = clean_view;
		vmi_ack_event(&ring, 0);
	}

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");

	/* bp_count == N proves auto-return (a failed return would leave the vCPU
	 * in the clean view -> only 1 trap). counter == N proves the real code
	 * ran each time. */
	TEST_ASSERT(bp_count == BP_ITERATIONS,
		    "Expected %d breakpoints, got %d", BP_ITERATIONS, bp_count);
	TEST_ASSERT(*counter_hva == BP_ITERATIONS,
		    "Counter is %lu, expected %d",
		    (unsigned long)*counter_hva, BP_ITERATIONS);

	vmi_switch_view(vmi_fd, 0);
	vmi_change_gfn(vmi_fd, trap_view, func_gfn, KVM_VMI_INVALID_GFN);
	vmi_destroy_view(vmi_fd, trap_view);
	vmi_destroy_view(vmi_fd, clean_view);
	if (use_alloc_gfn) {
		munmap(shadow, psz);
		vmi_free_gfn(vmi_fd, shadow_gfn);
	}
	vmi_teardown_ring(&ring);
	close(vmi_fd);
	kvm_vm_free(vm);

	pr_info("PASS: breakpoint workflow (%s shadow): %d breakpoints, counter=%d\n",
		use_alloc_gfn ? "alloc_gfn" : "memslot",
		bp_count, BP_ITERATIONS);
}

int main(int argc, char *argv[])
{
	vmi_force_el1_guests();
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_RING));

	run_workflow(false);	/* shadow page backed by a normal memslot */
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_ALLOC_GFN));
	run_workflow(true);	/* shadow page from KVM_VMI_ALLOC_GFN */

	return 0;
}
