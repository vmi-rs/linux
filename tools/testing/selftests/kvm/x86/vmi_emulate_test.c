// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI emulation test
 *
 * Tests that RESPONSE_EMULATE correctly emulates instructions on
 * memory-access-protected pages without lifting EPT restrictions.
 *
 * Scenario:
 *   1. Create a VM with VMI enabled and an alternate view
 *   2. Map a data page with a known pattern, make it no-read in view
 *   3. Switch vCPU to the alternate view
 *   4. Guest reads from the data page -> mem_access ring event fires
 *   5. Host responds with EMULATE
 *   6. Guest receives the correct data (emulator read via host mapping)
 *   7. Verify the page is STILL protected (second read also triggers event)
 */
#include <linux/kvm.h>
#include <pthread.h>
#include <stdint.h>
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
	uint64_t val;

	GUEST_SYNC(1); /* About to do first read */

	/* First read: triggers mem_access, host emulates */
	val = *data;
	*result = val;
	GUEST_SYNC(2); /* First read done */

	/* Second read: page should STILL be protected */
	val = *data;
	*result = val;
	GUEST_SYNC(3); /* Second read done */

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
	uint32_t view_id;
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

	/* Write known pattern to data page */
	*data_hva = DATA_PATTERN;
	*result_hva = 0;

	/* Create alternate view with full RWX default */
	view_id = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);

	/* Set data page to no-read in the view (X-only traps reads) */
	vmi_set_mem_access(vmi_fd, view_id, test_gfn, KVM_VMI_ACCESS_X);

	/* Enable mem_access event delivery */
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_MEM_ACCESS, 1);

	/* Switch vCPU to the alternate view */
	vmi_switch_view(vmi_fd, view_id);

	/* Start vCPU thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* Process ring events until guest completes */
	while (!targ.done) {
		ev = vmi_wait_event_timeout(&ring, 5000);
		if (ev == NULL)
			break;

		TEST_ASSERT(ev->type == KVM_VMI_EVENT_MEM_ACCESS,
			    "Expected mem_access event, got %u", ev->type);
		TEST_ASSERT(ev->mem_access.gpa >> 12 == test_gfn,
			    "Expected GFN 0x%lx, got GPA 0x%llx",
			    (unsigned long)test_gfn,
			    (unsigned long long)ev->mem_access.gpa);

		mem_access_count++;

		/* Respond with EMULATE */
		ev->response = KVM_VMI_RESPONSE_EMULATE;
		vmi_ack_event(&ring, 0);
	}

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");

	/* Both reads should have triggered mem_access events */
	TEST_ASSERT(mem_access_count == 2,
		    "Expected 2 mem_access events, got %d",
		    mem_access_count);

	/* Guest should have read the correct pattern via emulation */
	TEST_ASSERT(*result_hva == DATA_PATTERN,
		    "Guest read 0x%lx, expected 0x%lx",
		    (unsigned long)*result_hva,
		    (unsigned long)DATA_PATTERN);

	pr_info("PASS: %d mem_access events, emulation returned correct "
		"data (0x%lx)\n", mem_access_count,
		(unsigned long)*result_hva);

	/* Cleanup */
	vmi_switch_view(vmi_fd, 0);
	vmi_destroy_view(vmi_fd, view_id);
	vmi_teardown_ring(&ring);
	close(vmi_fd);
	kvm_vm_free(vm);
	return 0;
}
