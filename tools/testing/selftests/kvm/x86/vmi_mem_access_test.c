// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI memory access permission test
 *
 * Tests that alternate views can have per-GFN R/W/X permissions
 * and that violations generate ring events.
 */
#include <linux/kvm.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

#define TEST_DATA_GPA	0x800000  /* 8MB - test data page */

/*
 * Guest writes to a volatile pointer to trigger a write access.
 */
static void guest_write_test(void)
{
	volatile uint64_t *ptr = (volatile uint64_t *)TEST_DATA_GPA;

	GUEST_SYNC(1); /* Signal ready */

	/* Write to the test page - will cause EPT violation if write-protected */
	*ptr = 0xdeadbeefcafeULL;

	GUEST_SYNC(2); /* Reached if write was allowed */
	GUEST_DONE();
}

/*
 * Test: Set a page to read-only in an alternate view, then verify
 * that a guest write to it generates a mem_access ring event.
 */
static void test_mem_access_write_protect(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;
	uint32_t view_id;
	uint64_t test_gfn = TEST_DATA_GPA >> 12;

	vm = vm_create_with_one_vcpu(&vcpu, guest_write_test);
	vmi_fd = vmi_create(vm);
	vmi_setup_ring(vmi_fd, 0, &ring);

	/* Map a test data page into guest physical memory */
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    TEST_DATA_GPA, 10, 1, 0);
	virt_map(vm, TEST_DATA_GPA, TEST_DATA_GPA, 1);

	/* Create an alternate view with full RWX default */
	view_id = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);

	/* Set the test page to read-only (R+X, no W) in this view */
	vmi_set_mem_access(vmi_fd, view_id, test_gfn,
			   KVM_VMI_ACCESS_R | KVM_VMI_ACCESS_X);

	/* Enable mem_access event delivery */
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_MEM_ACCESS, 1);

	/* Switch vCPU to the alternate view */
	vmi_switch_view(vmi_fd, view_id);

	/* Start vCPU thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* Guest writes to the read-only page -> EPT violation -> ring event */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL,
		    "Timeout waiting for mem_access event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_MEM_ACCESS,
		    "Expected mem_access event, got %u", ev->type);
	TEST_ASSERT(ev->mem_access.access & KVM_VMI_ACCESS_W,
		    "Expected write violation flag");
	TEST_ASSERT(ev->mem_access.gpa >> 12 == test_gfn,
		    "Expected GFN 0x%lx, got GPA 0x%llx",
		    (unsigned long)test_gfn,
		    (unsigned long long)ev->mem_access.gpa);

	/*
	 * Respond: grant write access so the write can proceed.
	 */
	vmi_set_mem_access(vmi_fd, view_id, test_gfn, KVM_VMI_ACCESS_RWX);

	ev->response = KVM_VMI_RESPONSE_CONTINUE;
	vmi_ack_event(&ring, 0);

	/* Guest should complete successfully */
	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");

	/* Cleanup */
	vmi_switch_view(vmi_fd, 0);
	vmi_destroy_view(vmi_fd, view_id);
	vmi_teardown_ring(&ring);
	close(vmi_fd);
	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	test_mem_access_write_protect();
	return 0;
}
