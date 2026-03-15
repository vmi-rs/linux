// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI breakpoint workflow integration test
 *
 * Tests the complete shadow-page breakpoint workflow via ring-based delivery:
 *
 *   View 1 (clean): Alternate view with the original code page.
 *   View 2 (trap):  GFN remapped to a shadow page with INT3 patched.
 *
 * Per-breakpoint-hit workflow:
 *   1. vCPU runs in trap view (view 2), hits INT3 -> breakpoint ring event
 *   2. Host responds: switch to clean view (view 1) + SINGLESTEP_FAST
 *   3. Guest executes original instruction in view 1 (fast singlestep)
 *   4. MTF fires -> kernel switches back to trap view, no singlestep event
 *   5. Guest hits INT3 again on next loop iteration -> repeat
 *
 * The guest function at a known GPA increments a counter. After N
 * iterations, the test verifies the counter matches and that we got
 * the expected number of breakpoint events.
 */
#include <linux/kvm.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

/* GPAs for the test function, counter, and shadow page */
#define FUNC_GPA	0x900000  /* 9MB: code page with target function */
#define COUNTER_GPA	0x901000  /* 9MB+4K: counter incremented by function */
#define SHADOW_GPA	0x902000  /* 9MB+8K: shadow page with INT3 */

#define BP_ITERATIONS	5

/*
 * Machine code for the target function:
 *   inc qword ptr [COUNTER_GPA]  ; 48 FF 04 25 <addr32>  (8 bytes)
 *   ret                          ; C3                     (1 byte)
 */
static const uint8_t func_code[] = {
	0x48, 0xFF, 0x04, 0x25,				/* inc qword ptr */
	(COUNTER_GPA >>  0) & 0xFF,			/* addr byte 0 */
	(COUNTER_GPA >>  8) & 0xFF,			/* addr byte 1 */
	(COUNTER_GPA >> 16) & 0xFF,			/* addr byte 2 */
	(COUNTER_GPA >> 24) & 0xFF,			/* addr byte 3 */
	0xC3,						/* ret */
};

#define INT3_OPCODE 0xCC

static void guest_code(void)
{
	typedef void (*func_t)(void);
	func_t fn = (func_t)FUNC_GPA;
	volatile uint64_t *counter = (volatile uint64_t *)COUNTER_GPA;
	int i;

	GUEST_SYNC(1); /* Ready */

	for (i = 0; i < BP_ITERATIONS; i++)
		fn();

	/* Report the counter value */
	GUEST_SYNC(*counter);

	GUEST_DONE();
}

int main(int argc, char *argv[])
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;
	uint32_t clean_view_id, trap_view_id;
	uint8_t *func_hva, *shadow_hva;
	uint64_t *counter_hva;
	uint64_t func_gfn = FUNC_GPA >> 12;
	uint64_t shadow_gfn = SHADOW_GPA >> 12;
	int bp_count = 0;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));

	vm = vm_create_with_one_vcpu(&vcpu, guest_code);
	vmi_fd = vmi_create(vm);
	vmi_setup_ring(vmi_fd, 0, &ring);

	/* Map pages: function code, counter, shadow page */
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    FUNC_GPA, 20, 1, 0);
	virt_map(vm, FUNC_GPA, FUNC_GPA, 1);

	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    COUNTER_GPA, 21, 1, 0);
	virt_map(vm, COUNTER_GPA, COUNTER_GPA, 1);

	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    SHADOW_GPA, 22, 1, 0);
	/* Shadow page doesn't need guest virtual mapping - only used via GFN remap */

	/* Get HVAs */
	func_hva = addr_gpa2hva(vm, FUNC_GPA);
	counter_hva = addr_gpa2hva(vm, COUNTER_GPA);
	shadow_hva = addr_gpa2hva(vm, SHADOW_GPA);

	/* Write function code to the code page */
	memcpy(func_hva, func_code, sizeof(func_code));

	/* Create shadow page: copy of code page with INT3 at offset 0 */
	memcpy(shadow_hva, func_code, sizeof(func_code));
	shadow_hva[0] = INT3_OPCODE;

	/* Initialize counter to 0 */
	*counter_hva = 0;

	/* Create view 1 (clean): original code, for singlestep */
	clean_view_id = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);

	/* Create view 2 (trap): remapped code page to shadow */
	trap_view_id = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);

	/* Remap the code page GFN in trap view to point to shadow page */
	vmi_change_gfn(vmi_fd, trap_view_id, func_gfn, shadow_gfn);

	/* Enable breakpoint events (fast singlestep needs no event) */
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_BREAKPOINT, 1);

	/* Switch vCPU to trap view */
	vmi_switch_view(vmi_fd, trap_view_id);

	/* Start vCPU thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* Main event loop */
	while (!targ.done) {
		ev = vmi_wait_event_timeout(&ring, 5000);
		if (ev == NULL)
			break;

		if (ev->type == KVM_VMI_EVENT_BREAKPOINT) {
			bp_count++;

			/*
			 * Fast singlestep: switch to clean view,
			 * execute the original instruction, then
			 * auto-switch back to trap view (no event).
			 */
			ev->response = KVM_VMI_RESPONSE_SWITCH_VIEW |
				       KVM_VMI_RESPONSE_SINGLESTEP_FAST;
			ev->view_id = clean_view_id;
			vmi_ack_event(&ring, 0);
			continue;
		}

		TEST_FAIL("Unexpected ring event type %u", ev->type);
	}

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");

	TEST_ASSERT(bp_count == BP_ITERATIONS,
		    "Expected %d breakpoints, got %d",
		    BP_ITERATIONS, bp_count);
	TEST_ASSERT(*counter_hva == BP_ITERATIONS,
		    "Counter is %lu, expected %d",
		    (unsigned long)*counter_hva, BP_ITERATIONS);

	pr_info("PASS: Full breakpoint workflow - %d iterations, "
		"%d breakpoints (no singlestep events), counter=%lu\n",
		BP_ITERATIONS, bp_count,
		(unsigned long)*counter_hva);

	/* Cleanup */
	vmi_switch_view(vmi_fd, 0);
	vmi_destroy_view(vmi_fd, trap_view_id);
	vmi_destroy_view(vmi_fd, clean_view_id);
	vmi_teardown_ring(&ring);
	close(vmi_fd);
	kvm_vm_free(vm);
	return 0;
}
