// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI shadow page allocation test (arm64)
 *
 * Tests KVM_VMI_ALLOC_GFN / KVM_VMI_FREE_GFN: allocate kernel-backed
 * shadow pages at GFNs >= KVM_VMI_SHADOW_GFN_BASE, access them via the
 * vmi_fd mmap, free them, and exercise the free-while-remapped (EBUSY)
 * guard plus the EINVAL/ENOENT error paths.
 *
 * The full shadow-breakpoint workflow (x86's Test 4) is deferred to K13
 * (vmi_breakpoint_workflow): it needs breakpoint events, view-switch
 * response, and fast singlestep, none of which exist at K8.
 */
#include <linux/kvm.h>
#include <linux/kvm_vmi.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

static void guest_nop(void)
{
	GUEST_DONE();
}

/* Test 1: alloc, mmap, write/readback, munmap, free. */
static void test_alloc_free(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	int vmi_fd;
	uint64_t shadow_gfn;
	uint64_t *shadow;

	vm = vm_create_with_one_vcpu(&vcpu, guest_nop);
	vmi_fd = vmi_create(vm);

	shadow_gfn = vmi_alloc_gfn(vmi_fd);
	TEST_ASSERT(shadow_gfn >= KVM_VMI_SHADOW_GFN_BASE,
		    "Shadow GFN 0x%lx should be >= base 0x%lx",
		    (unsigned long)shadow_gfn,
		    (unsigned long)KVM_VMI_SHADOW_GFN_BASE);

	shadow = mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE,
		      MAP_SHARED, vmi_fd, shadow_gfn * getpagesize());
	TEST_ASSERT(shadow != MAP_FAILED,
		    "mmap shadow page failed: errno=%d", errno);

	shadow[0] = 0xDEADBEEFCAFEBABEULL;
	TEST_ASSERT(shadow[0] == 0xDEADBEEFCAFEBABEULL,
		    "Shadow page read-back mismatch");

	munmap(shadow, getpagesize());
	vmi_free_gfn(vmi_fd, shadow_gfn);

	close(vmi_fd);
	kvm_vm_free(vm);
	pr_info("PASS: test_alloc_free\n");
}

/* Test 2: free while remapped via change_gfn -> EBUSY; revert -> free ok. */
static void test_free_while_remapped(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	int vmi_fd, ret;
	uint64_t shadow_gfn;
	uint32_t view_id;
	struct kvm_vmi_free_gfn free_req;

	vm = vm_create_with_one_vcpu(&vcpu, guest_nop);
	vmi_fd = vmi_create(vm);

	shadow_gfn = vmi_alloc_gfn(vmi_fd);
	view_id = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);

	/* Remap guest GFN 0 to the shadow page (populates view->gfn_overrides). */
	vmi_change_gfn(vmi_fd, view_id, 0, shadow_gfn);

	/* Free must be refused while an override references the page. */
	free_req.gfn = shadow_gfn;
	ret = ioctl(vmi_fd, KVM_VMI_FREE_GFN, &free_req);
	TEST_ASSERT(ret == -1 && errno == EBUSY,
		    "FREE_GFN while remapped should fail EBUSY, got ret=%d errno=%d",
		    ret, errno);

	/* Revert the override, then free succeeds. */
	vmi_change_gfn(vmi_fd, view_id, 0, KVM_VMI_INVALID_GFN);
	vmi_free_gfn(vmi_fd, shadow_gfn);

	vmi_destroy_view(vmi_fd, view_id);
	close(vmi_fd);
	kvm_vm_free(vm);
	pr_info("PASS: test_free_while_remapped\n");
}

/* Test 3: session close auto-frees all shadow pages (no leak/crash). */
static void test_session_close_frees(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	int vmi_fd;

	vm = vm_create_with_one_vcpu(&vcpu, guest_nop);
	vmi_fd = vmi_create(vm);

	vmi_alloc_gfn(vmi_fd);
	vmi_alloc_gfn(vmi_fd);
	vmi_alloc_gfn(vmi_fd);

	close(vmi_fd);
	kvm_vm_free(vm);
	pr_info("PASS: test_session_close_frees\n");
}

/* Test 4: error paths (beyond the x86 reference). */
static void test_error_paths(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	int vmi_fd, ret;
	uint64_t gfn1, gfn2;
	struct kvm_vmi_free_gfn free_req;

	vm = vm_create_with_one_vcpu(&vcpu, guest_nop);
	vmi_fd = vmi_create(vm);

	/* Free below the shadow base -> EINVAL. */
	free_req.gfn = 0;
	ret = ioctl(vmi_fd, KVM_VMI_FREE_GFN, &free_req);
	TEST_ASSERT(ret == -1 && errno == EINVAL,
		    "FREE_GFN of gfn < base should fail EINVAL, got %d/%d",
		    ret, errno);

	/* Free an in-range but never-allocated shadow gfn -> ENOENT. */
	free_req.gfn = KVM_VMI_SHADOW_GFN_BASE + 0x1000;
	ret = ioctl(vmi_fd, KVM_VMI_FREE_GFN, &free_req);
	TEST_ASSERT(ret == -1 && errno == ENOENT,
		    "FREE_GFN of unallocated gfn should fail ENOENT, got %d/%d",
		    ret, errno);

	/* Consecutive allocations are distinct and monotonically increasing. */
	gfn1 = vmi_alloc_gfn(vmi_fd);
	gfn2 = vmi_alloc_gfn(vmi_fd);
	TEST_ASSERT(gfn2 > gfn1,
		    "Allocations should be monotonic: gfn1=0x%lx gfn2=0x%lx",
		    (unsigned long)gfn1, (unsigned long)gfn2);

	/* Double-free: first succeeds, second -> ENOENT. */
	vmi_free_gfn(vmi_fd, gfn1);
	free_req.gfn = gfn1;
	ret = ioctl(vmi_fd, KVM_VMI_FREE_GFN, &free_req);
	TEST_ASSERT(ret == -1 && errno == ENOENT,
		    "Double-free should fail ENOENT, got %d/%d", ret, errno);

	vmi_free_gfn(vmi_fd, gfn2);

	close(vmi_fd);
	kvm_vm_free(vm);
	pr_info("PASS: test_error_paths\n");
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_ALLOC_GFN));

	test_alloc_free();
	test_free_while_remapped();
	test_session_close_frees();
	test_error_paths();

	pr_info("PASS: vmi_alloc_gfn\n");
	return 0;
}
