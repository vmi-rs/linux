// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI EPT paging-write (PW) permission test
 *
 * Tests the KVM_VMI_ACCESS_PW flag which allows CPU paging writes
 * (A/D bit updates) while still trapping software writes.
 *
 * test_ept_pw_not_supported:
 *   If EPT PW is not available (KVM_CAP_VMI_EPT_PW == 0), verify that
 *   setting KVM_VMI_ACCESS_PW returns EOPNOTSUPP.
 *
 * test_ept_pw_software_write_trapped:
 *   If EPT PW is available, verify that a page with R+PW (no W) still
 *   traps guest software writes while allowing CPU paging writes.
 *
 * test_page_walk_without_pw:
 *   Mark the L1 page-table page for a test GPA as R-only (no W, no PW).
 *   Guest reads from the GPA, triggering a page walk that tries to set
 *   the Accessed bit in the PTE - this is a write to the PT page and
 *   must cause an EPT W violation.
 *
 * test_page_walk_with_pw:
 *   Mark the same L1 PT page as R+PW.  The page walker's A-bit update
 *   is now permitted by the PW bit, so no EPT violation occurs and the
 *   guest completes without interruption.
 */
#include <linux/kvm.h>
#include <linux/kvm_vmi.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>

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
 * Guest reads from a volatile pointer to trigger a page walk without
 * performing a software write.  The page walker will try to set the
 * Accessed bit in the guest PTE, which is a write to the PT page GPA.
 */
static void guest_read_test(void)
{
	volatile uint64_t *ptr = (volatile uint64_t *)TEST_DATA_GPA;
	uint64_t val;

	/* Read the test page - triggers page walk + A-bit update */
	val = *ptr;
	(void)val;

	GUEST_DONE();
}

/*
 * Find the GPA of the L1 page-table page that contains the PTE for @gva.
 * Uses vm_get_page_table_entry() to get the HVA of the PTE, then converts back to GPA.
 */
static uint64_t get_pt_page_gfn(struct kvm_vm *vm, uint64_t gva)
{
	uint64_t *pte_hva;
	void *pt_page_hva;
	uint64_t pt_page_gpa;

	pte_hva = vm_get_page_table_entry(vm, gva);
	TEST_ASSERT(pte_hva != NULL, "vm_get_page_table_entry returned NULL for GVA 0x%lx",
		    (unsigned long)gva);

	/* Page-align the HVA to get the start of the PT page */
	pt_page_hva = (void *)((uintptr_t)pte_hva & ~0xFFFUL);
	pt_page_gpa = addr_hva2gpa(vm, pt_page_hva);

	return pt_page_gpa >> 12;
}

/*
 * Test: When EPT PW capability is NOT supported, setting KVM_VMI_ACCESS_PW
 * on a GFN must return -EOPNOTSUPP.
 */
static void test_ept_pw_not_supported(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	int vmi_fd;
	uint32_t view_id;
	uint64_t test_gfn = TEST_DATA_GPA >> 12;
	struct kvm_vmi_mem_access ma = {};
	int ret;

	if (kvm_has_cap(KVM_CAP_VMI_EPT_PW)) {
		pr_info("EPT PW supported, skipping not-supported test\n");
		return;
	}

	pr_info("EPT PW not supported, testing EOPNOTSUPP path\n");

	vm = vm_create_with_one_vcpu(&vcpu, guest_write_test);
	vmi_fd = vmi_create(vm);

	/* Map a test data page into guest physical memory */
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    TEST_DATA_GPA, 10, 1, 0);
	virt_map(vm, TEST_DATA_GPA, TEST_DATA_GPA, 1);

	/* Create an alternate view with full RWX default */
	view_id = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);

	/* Try setting PW on a GFN - should fail with EOPNOTSUPP */
	ma.view_id = view_id;
	ma.access = KVM_VMI_ACCESS_R | KVM_VMI_ACCESS_PW;
	ma.gfn = test_gfn;

	ret = ioctl(vmi_fd, KVM_VMI_SET_MEM_ACCESS, &ma);
	TEST_ASSERT(ret == -1 && errno == EOPNOTSUPP,
		    "Expected EOPNOTSUPP for PW on unsupported hw, got ret=%d errno=%d (%s)",
		    ret, errno, strerror(errno));

	pr_info("Correctly got EOPNOTSUPP for PW access on unsupported hw\n");

	/* Cleanup */
	vmi_destroy_view(vmi_fd, view_id);
	close(vmi_fd);
	kvm_vm_free(vm);
}

/*
 * Test: When EPT PW IS supported, a page with R+PW (no software W)
 * should still trap guest software writes as W violations.
 */
static void test_ept_pw_software_write_trapped(void)
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

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_EPT_PW));

	vm = vm_create_with_one_vcpu(&vcpu, guest_write_test);
	vmi_fd = vmi_create(vm);
	vmi_setup_ring(vmi_fd, 0, &ring);

	/* Map a test data page into guest physical memory */
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    TEST_DATA_GPA, 10, 1, 0);
	virt_map(vm, TEST_DATA_GPA, TEST_DATA_GPA, 1);

	/* Create an alternate view with full RWX default */
	view_id = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);

	/*
	 * Set test data page to R+PW (read + paging-write, NO software write).
	 * CPU paging writes (A/D updates) are allowed, but explicit MOV
	 * instructions to the page should still trap.
	 */
	vmi_set_mem_access(vmi_fd, view_id, test_gfn,
			   KVM_VMI_ACCESS_R | KVM_VMI_ACCESS_PW);

	/* Enable mem_access event delivery */
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_MEM_ACCESS, 1);

	/* Switch vCPU to the alternate view */
	vmi_switch_view(vmi_fd, view_id);

	/* Start vCPU thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* Guest writes to the page -> W violation (software writes trapped) */
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

	pr_info("Got expected W violation on R+PW page (software write trapped)\n");

	/* Grant full RWX so the write can proceed */
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

/*
 * Test: Page-table page is R-only (no PW).  Guest reads TEST_DATA_GPA,
 * triggering a page walk.  The CPU tries to set the Accessed bit in the
 * guest PTE - that is a write to the PT page GPA, and with R-only EPT
 * permissions it must cause an EPT W violation.
 */
static void test_page_walk_without_pw(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;
	uint32_t view_id;
	uint64_t pt_page_gfn;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_EPT_PW));

	vm = vm_create_with_one_vcpu(&vcpu, guest_read_test);
	vmi_fd = vmi_create(vm);
	vmi_setup_ring(vmi_fd, 0, &ring);

	/* Map a test data page into guest physical memory */
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    TEST_DATA_GPA, 10, 1, 0);
	virt_map(vm, TEST_DATA_GPA, TEST_DATA_GPA, 1);

	/* Find the L1 PT page that holds the PTE for TEST_DATA_GPA */
	pt_page_gfn = get_pt_page_gfn(vm, TEST_DATA_GPA);
	pr_info("PT page GFN for 0x%x: 0x%lx\n",
		TEST_DATA_GPA, (unsigned long)pt_page_gfn);

	/* Create view with RWX default - only the PT page will be restricted */
	view_id = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);

	/*
	 * Set PT page to R-only.  Without PW, the page walker's A-bit
	 * update is treated as a regular write -> EPT W violation.
	 */
	vmi_set_mem_access(vmi_fd, view_id, pt_page_gfn, KVM_VMI_ACCESS_R);

	/* Enable mem_access event delivery */
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_MEM_ACCESS, 1);

	/* Switch vCPU to the view */
	vmi_switch_view(vmi_fd, view_id);

	/* Start vCPU - guest reads TEST_DATA_GPA -> page walk -> W violation */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL,
		    "Timeout - expected W violation from page walker A-bit update");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_MEM_ACCESS,
		    "Expected mem_access event, got %u", ev->type);
	TEST_ASSERT(ev->mem_access.access & KVM_VMI_ACCESS_W,
		    "Expected W violation from page walker, got access=0x%x",
		    ev->mem_access.access);
	TEST_ASSERT(ev->mem_access.gpa >> 12 == pt_page_gfn,
		    "Expected PT page GFN 0x%lx, got GPA 0x%llx",
		    (unsigned long)pt_page_gfn,
		    (unsigned long long)ev->mem_access.gpa);

	pr_info("R-only PT page: got expected W violation from page walker\n");

	/* Grant RWX so the page walk can complete */
	vmi_set_mem_access(vmi_fd, view_id, pt_page_gfn, KVM_VMI_ACCESS_RWX);

	ev->response = KVM_VMI_RESPONSE_CONTINUE;
	vmi_ack_event(&ring, 0);

	/* Guest should complete */
	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");

	/* Cleanup */
	vmi_switch_view(vmi_fd, 0);
	vmi_destroy_view(vmi_fd, view_id);
	vmi_teardown_ring(&ring);
	close(vmi_fd);
	kvm_vm_free(vm);
}

/*
 * Test: Page-table page is R+PW.  Guest reads TEST_DATA_GPA, triggering
 * a page walk.  The CPU sets the Accessed bit in the PTE - this is a
 * paging write, permitted by the PW bit.  No EPT violation occurs and
 * the guest completes without any mem_access event.
 */
static void test_page_walk_with_pw(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;
	uint32_t view_id;
	uint64_t pt_page_gfn;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_EPT_PW));

	vm = vm_create_with_one_vcpu(&vcpu, guest_read_test);
	vmi_fd = vmi_create(vm);
	vmi_setup_ring(vmi_fd, 0, &ring);

	/* Map a test data page into guest physical memory */
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    TEST_DATA_GPA, 10, 1, 0);
	virt_map(vm, TEST_DATA_GPA, TEST_DATA_GPA, 1);

	/* Find the L1 PT page that holds the PTE for TEST_DATA_GPA */
	pt_page_gfn = get_pt_page_gfn(vm, TEST_DATA_GPA);
	pr_info("PT page GFN for 0x%x: 0x%lx\n",
		TEST_DATA_GPA, (unsigned long)pt_page_gfn);

	/* Create view with RWX default - only the PT page will be restricted */
	view_id = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);

	/*
	 * Set PT page to R+PW.  With PW, the page walker's A-bit update
	 * is allowed - no EPT violation should occur.
	 */
	vmi_set_mem_access(vmi_fd, view_id, pt_page_gfn,
			   KVM_VMI_ACCESS_R | KVM_VMI_ACCESS_PW);

	/* Enable mem_access event delivery */
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_MEM_ACCESS, 1);

	/* Switch vCPU to the view */
	vmi_switch_view(vmi_fd, view_id);

	/* Start vCPU - guest reads TEST_DATA_GPA -> page walk -> PW allows it */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/*
	 * Wait briefly - no event should arrive because the PW bit permits
	 * the page walker's A-bit update without an EPT violation.
	 */
	ev = vmi_wait_event_timeout(&ring, 2000);
	TEST_ASSERT(ev == NULL,
		    "Unexpected event on R+PW PT page - PW should have allowed page walker write");

	/* Guest should complete without any violations */
	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed without violations");

	pr_info("R+PW PT page: page walker A-bit update allowed, no violation\n");

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

	test_ept_pw_not_supported();
	test_ept_pw_software_write_trapped();
	test_page_walk_without_pw();
	test_page_walk_with_pw();

	return 0;
}
