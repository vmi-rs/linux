// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI huge page remap test
 *
 * Verifies that GFN remaps (change_gfn) are not bypassed by 2MB huge
 * page SPTEs.  When a GFN override exists in an alternate view, the
 * kernel must limit the page size to 4K for the entire 2MB block
 * containing the remap.  Otherwise, an adjacent GFN faulting first
 * could install a 2MB SPTE that covers the remapped GFN with its
 * original (non-shadow) mapping.
 *
 * The memslot is backed by THP (transparent huge pages) so that the
 * host provides a 2MB-aligned compound page.  Without THP backing,
 * host_pfn_mapping_level() returns PG_LEVEL_4K and KVM never attempts
 * a 2MB SPTE, making the test pass trivially regardless of the fix.
 *
 * Test plan:
 * 1. Allocate a full 2MB THP-backed region (512 pages)
 * 2. Write unique patterns to DATA (page 0) and NEIGHBOR (page 1)
 * 3. Allocate a shadow page at a separate GPA, write a different pattern
 * 4. Create an alt view, remap DATA_GFN -> shadow_gfn
 * 5. Switch vCPU to the alt view
 * 6. Guest reads NEIGHBOR first (could trigger 2MB SPTE without the fix)
 * 7. Guest reads DATA and reports the value
 * 8. Verify guest sees shadow pattern, not original
 */
#include <linux/kvm.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

/*
 * Full 2MB-aligned block backed by THP.  DATA at offset 0, NEIGHBOR
 * at offset 0x1000.  The entire 512-page block must be in one memslot
 * so the host can back it with a single 2MB transparent huge page.
 * SHADOW is at a separate GPA outside the block.
 */
#define BLOCK_GPA	0xA00000ULL
#define DATA_GPA	BLOCK_GPA
#define NEIGHBOR_GPA	(BLOCK_GPA + 0x1000ULL)
#define SHADOW_GPA	0xC00000ULL
#define BLOCK_SLOT	10
#define SHADOW_SLOT	11
#define BLOCK_PAGES	512	/* 2MB / 4K = 512 pages */

#define PATTERN_ORIGINAL	0xAA
#define PATTERN_NEIGHBOR	0xBB
#define PATTERN_SHADOW		0xCC

static void guest_main(void)
{
	volatile uint8_t *data_ptr = (volatile uint8_t *)DATA_GPA;
	volatile uint8_t *neighbor_ptr = (volatile uint8_t *)NEIGHBOR_GPA;
	uint8_t neighbor_val, data_val;

	GUEST_SYNC(1); /* Signal ready, wait for view switch */

	/*
	 * Read neighbor page FIRST.  Without the fix, this could
	 * cause KVM to install a 2MB SPTE covering both pages,
	 * mapping DATA_GPA to the original page instead of the shadow.
	 */
	neighbor_val = *neighbor_ptr;

	/* Now read the data page - should see shadow content */
	data_val = *data_ptr;

	/* Report both values to the test harness */
	GUEST_SYNC(data_val);
	GUEST_SYNC(neighbor_val);
	GUEST_DONE();
}

static void test_hugepage_remap(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	int vmi_fd;
	uint32_t view_id;
	void *data_hva, *neighbor_hva, *shadow_hva;
	uint64_t data_gfn = DATA_GPA >> 12;
	uint64_t shadow_gfn = SHADOW_GPA >> 12;
	struct ucall uc;
	uint8_t data_val, neighbor_val;

	vm = vm_create_with_one_vcpu(&vcpu, guest_main);
	vmi_fd = vmi_create(vm);
	vmi_setup_ring(vmi_fd, 0, &ring);

	/*
	 * Allocate a full 2MB block with THP backing.  This gives the
	 * host a 2MB compound page, so host_pfn_mapping_level() returns
	 * PG_LEVEL_2M and KVM will attempt to install a 2MB SPTE.
	 */
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS_THP,
				    BLOCK_GPA, BLOCK_SLOT, BLOCK_PAGES, 0);
	virt_map(vm, DATA_GPA, DATA_GPA, 1);
	virt_map(vm, NEIGHBOR_GPA, NEIGHBOR_GPA, 1);

	data_hva = addr_gpa2hva(vm, DATA_GPA);
	memset(data_hva, PATTERN_ORIGINAL, 4096);

	neighbor_hva = addr_gpa2hva(vm, NEIGHBOR_GPA);
	memset(neighbor_hva, PATTERN_NEIGHBOR, 4096);

	/* Shadow page at a separate GPA (not in the 2MB block) */
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    SHADOW_GPA, SHADOW_SLOT, 1, 0);
	shadow_hva = addr_gpa2hva(vm, SHADOW_GPA);
	memset(shadow_hva, PATTERN_SHADOW, 4096);

	/* Create alt view and remap DATA -> SHADOW */
	view_id = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);
	vmi_change_gfn(vmi_fd, view_id, data_gfn, shadow_gfn);
	vmi_switch_view(vmi_fd, view_id);

	/* Run vCPU: first GUEST_SYNC(1) = ready */
	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_IO);
	get_ucall(vcpu, &uc);
	TEST_ASSERT(uc.cmd == UCALL_SYNC && uc.args[1] == 1,
		    "Expected GUEST_SYNC(1), got cmd=%lu arg=%lu",
		    uc.cmd, uc.args[1]);

	/* Run vCPU: guest reads neighbor, then data, reports data_val */
	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_IO);
	get_ucall(vcpu, &uc);
	TEST_ASSERT(uc.cmd == UCALL_SYNC,
		    "Expected UCALL_SYNC for data_val, got %lu", uc.cmd);
	data_val = (uint8_t)uc.args[1];

	/* Run vCPU: guest reports neighbor_val */
	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_IO);
	get_ucall(vcpu, &uc);
	TEST_ASSERT(uc.cmd == UCALL_SYNC,
		    "Expected UCALL_SYNC for neighbor_val, got %lu", uc.cmd);
	neighbor_val = (uint8_t)uc.args[1];

	/* Run vCPU: GUEST_DONE */
	vcpu_run(vcpu);
	TEST_ASSERT_KVM_EXIT_REASON(vcpu, KVM_EXIT_IO);
	get_ucall(vcpu, &uc);
	TEST_ASSERT(uc.cmd == UCALL_DONE, "Expected UCALL_DONE");

	/*
	 * The critical check: guest must see shadow content (0xCC) at
	 * DATA_GPA, not original (0xAA).  If a 2MB SPTE was installed
	 * covering the remapped GFN, the guest would see 0xAA.
	 */
	TEST_ASSERT(data_val == PATTERN_SHADOW,
		    "Guest saw 0x%02x at DATA_GPA, expected shadow pattern 0x%02x "
		    "(got original 0x%02x means 2MB SPTE bypassed remap)",
		    data_val, PATTERN_SHADOW, PATTERN_ORIGINAL);

	TEST_ASSERT(neighbor_val == PATTERN_NEIGHBOR,
		    "Guest saw 0x%02x at NEIGHBOR_GPA, expected 0x%02x",
		    neighbor_val, PATTERN_NEIGHBOR);

	pr_info("PASS: data_val=0x%02x (shadow), neighbor_val=0x%02x\n",
		data_val, neighbor_val);

	/* Cleanup: switch back to view 0 before destroying the alt view */
	vmi_switch_view(vmi_fd, 0);
	vmi_change_gfn(vmi_fd, view_id, data_gfn, KVM_VMI_INVALID_GFN);
	vmi_destroy_view(vmi_fd, view_id);
	vmi_teardown_ring(&ring);
	close(vmi_fd);
	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(thp_configured());

	test_hugepage_remap();

	return 0;
}
