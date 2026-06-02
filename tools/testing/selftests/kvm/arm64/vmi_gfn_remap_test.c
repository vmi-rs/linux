// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI GFN remapping test (arm64, K9)
 *
 * change_gfn remaps a guest data GFN, in an alternate view, to a VMI shadow
 * page seeded with a distinct sentinel. A vCPU on the view reads the sentinel
 * (the override took effect via the stage-2 fault path); on view 0 it reads
 * the original contents. Revert restores the original. Also checks the EINVAL
 * (view 0) / ENOENT (unknown view) error paths.
 *
 * GFN math is host-page based (gfn = gpa / getpagesize()), matching the KVM
 * stage-2 GFN convention; never a hardcoded 4K shift.
 */
#include <errno.h>
#include <linux/kvm.h>
#include <linux/kvm_vmi.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

#define TEST_GPA	0x10000000ULL	/* 256 MB, 64K-aligned data page */
#define TEST_MEMSLOT	10
#define ORIG_VAL	0x1111111111111111ULL
#define SHADOW_VAL	0x2222222222222222ULL

/* Guest reads the page and reports what it sees, twice. */
static void guest_main(void)
{
	volatile uint64_t *ptr = (volatile uint64_t *)TEST_GPA;

	GUEST_SYNC(*ptr);	/* read #1 */
	GUEST_SYNC(*ptr);	/* read #2 */
	GUEST_DONE();
}

static uint64_t expect_sync_read(struct kvm_vcpu *vcpu)
{
	struct ucall uc;

	vcpu_run(vcpu);
	TEST_ASSERT(get_ucall(vcpu, &uc) == UCALL_SYNC,
		    "expected UCALL_SYNC");
	return uc.args[1];
}

int main(int argc, char *argv[])
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct ucall uc;
	size_t psz = getpagesize();
	uint64_t gfn = TEST_GPA / psz;
	uint64_t shadow_gfn, *shadow, val;
	uint32_t view_id;
	int vmi_fd, ret;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));

	vm = vm_create_with_one_vcpu(&vcpu, guest_main);
	vmi_fd = vmi_create(vm);

	/* One RWX data page seeded with ORIG_VAL. */
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, TEST_GPA,
				    TEST_MEMSLOT,
				    vm_calc_num_guest_pages(vm->mode, psz), 0);
	virt_map(vm, TEST_GPA, TEST_GPA, vm_calc_num_guest_pages(vm->mode, psz));
	*(uint64_t *)addr_gpa2hva(vm, TEST_GPA) = ORIG_VAL;

	/* Shadow page seeded with SHADOW_VAL via the vmi_fd mmap. */
	shadow_gfn = vmi_alloc_gfn(vmi_fd);
	shadow = mmap(NULL, psz, PROT_READ | PROT_WRITE, MAP_SHARED,
		      vmi_fd, shadow_gfn * psz);
	TEST_ASSERT(shadow != MAP_FAILED, "mmap shadow failed: %d", errno);
	shadow[0] = SHADOW_VAL;

	view_id = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);

	/* Error paths: remap in view 0 -> EINVAL; unknown view -> ENOENT. */
	ret = __vmi_change_gfn_err(vmi_fd, 0, gfn, shadow_gfn);
	TEST_ASSERT(ret == -EINVAL, "remap in view 0 should be EINVAL, got %d",
		    ret);
	ret = __vmi_change_gfn_err(vmi_fd, view_id + 999, gfn, shadow_gfn);
	TEST_ASSERT(ret == -ENOENT, "remap unknown view should be ENOENT, got %d",
		    ret);

	/* Remap gfn -> shadow page in the alt view. */
	vmi_change_gfn(vmi_fd, view_id, gfn, shadow_gfn);

	/* Read #1 on view 0: original contents. */
	val = expect_sync_read(vcpu);
	TEST_ASSERT(val == ORIG_VAL,
		    "view 0 read got 0x%lx, want ORIG", (unsigned long)val);

	/* Switch to the alt view: read #2 must see the shadow sentinel. */
	vmi_switch_view(vmi_fd, view_id);
	val = expect_sync_read(vcpu);
	TEST_ASSERT(val == SHADOW_VAL,
		    "alt-view read got 0x%lx, want SHADOW (remap ignored?)",
		    (unsigned long)val);

	vcpu_run(vcpu);
	TEST_ASSERT(get_ucall(vcpu, &uc) == UCALL_DONE, "expected DONE");

	/* Revert and confirm the override entry is gone (no fault crash). */
	vmi_switch_view(vmi_fd, 0);
	vmi_change_gfn(vmi_fd, view_id, gfn, KVM_VMI_INVALID_GFN);

	munmap(shadow, psz);
	vmi_destroy_view(vmi_fd, view_id);
	close(vmi_fd);
	kvm_vm_free(vm);

	pr_info("PASS: vmi_gfn_remap\n");
	return 0;
}
