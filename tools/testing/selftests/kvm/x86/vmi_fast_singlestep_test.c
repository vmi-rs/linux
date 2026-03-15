// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI fast singlestep test
 *
 * Tests fast singlestep: responding to an event with both SWITCH_VIEW and
 * SINGLESTEP_FAST flags causes the vCPU to switch to a different view,
 * execute one instruction, then automatically switch back to the original
 * view without generating a singlestep event.
 *
 * Scenario (mem_access-based):
 *   1. Create two alternate views; view 1 has a data page set to no-read
 *   2. View 2 has the same page with full RWX (default)
 *   3. Guest reads from the data page -> mem_access ring event on view 1
 *   4. Host responds with SWITCH_VIEW(view 2) + SINGLESTEP_FAST
 *   5. vCPU switches to view 2 (page accessible), executes read, MTF fires
 *   6. Kernel automatically switches back to view 1, no singlestep event
 *   7. Repeat: second read triggers another mem_access (page still protected)
 *      (the second mem_access proves the view was restored to view 1)
 */
#include <linux/kvm.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

#define DATA_GPA	0x800000  /* 8MB */
#define RESULT_GPA	0x801000  /* 8MB + 4K */

#define DATA_PATTERN	0xDEADBEEFCAFEBABEULL

static void guest_code(void)
{
	volatile uint64_t *data = (volatile uint64_t *)DATA_GPA;
	volatile uint64_t *result = (volatile uint64_t *)RESULT_GPA;

	GUEST_SYNC(1);

	/* First read: triggers mem_access -> fast singlestep */
	*result = *data;
	GUEST_SYNC(2);

	/* Second read: page should STILL be protected (back on view 1) */
	*result = *data;
	GUEST_SYNC(3);

	GUEST_DONE();
}

/*
 * Test SINGLESTEP_FAST without SWITCH_VIEW: should default to view 0.
 *
 * Setup:
 *   - One alternate view (view 1) with data page set to no-read
 *   - View 0 (host) has the page accessible (default)
 *   - vCPU on view 1
 *   - Guest reads data page -> mem_access event
 *   - Host responds with SINGLESTEP_FAST only (no SWITCH_VIEW)
 *   - Kernel switches to view 0, executes one instruction, switches back
 *   - Second read triggers another mem_access (proves auto-return to view 1)
 */
static void test_fast_singlestep_default_view(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;
	uint32_t view1_id;
	uint64_t test_gfn = DATA_GPA >> 12;
	uint64_t *data_hva, *result_hva;
	int mem_access_count = 0;

	vm = vm_create_with_one_vcpu(&vcpu, guest_code);
	vmi_fd = vmi_create(vm);
	vmi_setup_ring(vmi_fd, 0, &ring);

	/* Map data page and result page */
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    DATA_GPA, 10, 1, 0);
	virt_map(vm, DATA_GPA, DATA_GPA, 1);
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    RESULT_GPA, 11, 1, 0);
	virt_map(vm, RESULT_GPA, RESULT_GPA, 1);

	data_hva = addr_gpa2hva(vm, DATA_GPA);
	result_hva = addr_gpa2hva(vm, RESULT_GPA);
	*data_hva = DATA_PATTERN;
	*result_hva = 0;

	/* Create one alternate view with full RWX default */
	view1_id = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);

	/* Set data page to no-read in view 1 (X-only traps reads) */
	vmi_set_mem_access(vmi_fd, view1_id, test_gfn, KVM_VMI_ACCESS_X);

	/* Enable mem_access event delivery */
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_MEM_ACCESS, 1);

	/* Switch vCPU to view 1 (where data page is protected) */
	vmi_switch_view(vmi_fd, view1_id);

	/* Start vCPU thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* Process ring events until guest completes */
	while (!targ.done) {
		ev = vmi_wait_event_timeout(&ring, 5000);
		if (ev == NULL)
			break;

		if (ev->type == KVM_VMI_EVENT_MEM_ACCESS) {
			mem_access_count++;

			TEST_ASSERT(ev->mem_access.gpa >> 12 == test_gfn,
				    "Expected GFN 0x%lx, got GPA 0x%llx",
				    (unsigned long)test_gfn,
				    (unsigned long long)ev->mem_access.gpa);

			/*
			 * Fast singlestep WITHOUT SWITCH_VIEW:
			 * kernel defaults to view 0 (host view, page
			 * accessible), steps one instruction, then
			 * auto-switches back to view 1.
			 */
			ev->response = KVM_VMI_RESPONSE_SINGLESTEP_FAST;
			vmi_ack_event(&ring, 0);
			continue;
		}

		TEST_FAIL("Unexpected ring event type %u", ev->type);
	}

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");

	TEST_ASSERT(mem_access_count == 2,
		    "Expected 2 mem_access events, got %d", mem_access_count);

	TEST_ASSERT(*result_hva == DATA_PATTERN,
		    "Guest read 0x%lx, expected 0x%lx",
		    (unsigned long)*result_hva,
		    (unsigned long)DATA_PATTERN);

	pr_info("PASS: fast singlestep default view 0: %d mem_access events, "
		"data=0x%lx\n", mem_access_count,
		(unsigned long)*result_hva);

	/* Cleanup */
	vmi_switch_view(vmi_fd, 0);
	vmi_destroy_view(vmi_fd, view1_id);
	vmi_teardown_ring(&ring);
	close(vmi_fd);
	kvm_vm_free(vm);
}

static void test_fast_singlestep_with_switch_view(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;
	uint32_t view1_id, view2_id;
	uint64_t test_gfn = DATA_GPA >> 12;
	uint64_t *data_hva, *result_hva;
	int mem_access_count = 0;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));

	vm = vm_create_with_one_vcpu(&vcpu, guest_code);
	vmi_fd = vmi_create(vm);
	vmi_setup_ring(vmi_fd, 0, &ring);

	/* Map data page and result page */
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    DATA_GPA, 10, 1, 0);
	virt_map(vm, DATA_GPA, DATA_GPA, 1);
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    RESULT_GPA, 11, 1, 0);
	virt_map(vm, RESULT_GPA, RESULT_GPA, 1);

	data_hva = addr_gpa2hva(vm, DATA_GPA);
	result_hva = addr_gpa2hva(vm, RESULT_GPA);
	*data_hva = DATA_PATTERN;
	*result_hva = 0;

	/* Create two alternate views with full RWX default */
	view1_id = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);
	view2_id = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);

	/* Set data page to no-read in view 1 only (X-only traps reads) */
	vmi_set_mem_access(vmi_fd, view1_id, test_gfn, KVM_VMI_ACCESS_X);
	/* View 2 keeps default RWX - page is accessible there */

	/* Enable mem_access event delivery (fast singlestep needs no event) */
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_MEM_ACCESS, 1);

	/* Switch vCPU to view 1 (where data page is protected) */
	vmi_switch_view(vmi_fd, view1_id);

	/* Start vCPU thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* Process ring events until guest completes */
	while (!targ.done) {
		ev = vmi_wait_event_timeout(&ring, 5000);
		if (ev == NULL)
			break;

		if (ev->type == KVM_VMI_EVENT_MEM_ACCESS) {
			mem_access_count++;

			TEST_ASSERT(ev->mem_access.gpa >> 12 == test_gfn,
				    "Expected GFN 0x%lx, got GPA 0x%llx",
				    (unsigned long)test_gfn,
				    (unsigned long long)ev->mem_access.gpa);

			/*
			 * Fast singlestep: switch to view 2 (page
			 * accessible there), step one instruction,
			 * then kernel switches back to view 1
			 * automatically without a singlestep event.
			 */
			ev->response = KVM_VMI_RESPONSE_SWITCH_VIEW |
				       KVM_VMI_RESPONSE_SINGLESTEP_FAST;
			ev->view_id = view2_id;
			vmi_ack_event(&ring, 0);
			continue;
		}

		TEST_FAIL("Unexpected ring event type %u", ev->type);
	}

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");

	/*
	 * Both reads should have triggered mem_access events.
	 * The second mem_access proves the vCPU was automatically
	 * switched back to view 1 after the first fast singlestep.
	 */
	TEST_ASSERT(mem_access_count == 2,
		    "Expected 2 mem_access events, got %d", mem_access_count);

	/* Guest should have read correct data via fast singlestep */
	TEST_ASSERT(*result_hva == DATA_PATTERN,
		    "Guest read 0x%lx, expected 0x%lx",
		    (unsigned long)*result_hva,
		    (unsigned long)DATA_PATTERN);

	pr_info("PASS: %d mem_access events, fast singlestep "
		"with view restore worked (no singlestep events), data=0x%lx\n",
		mem_access_count,
		(unsigned long)*result_hva);

	/* Cleanup */
	vmi_switch_view(vmi_fd, 0);
	vmi_destroy_view(vmi_fd, view2_id);
	vmi_destroy_view(vmi_fd, view1_id);
	vmi_teardown_ring(&ring);
	close(vmi_fd);
	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));

	test_fast_singlestep_default_view();
	test_fast_singlestep_with_switch_view();

	return 0;
}
