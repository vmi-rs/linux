// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI shadow page allocation test
 *
 * Tests KVM_VMI_ALLOC_GFN / KVM_VMI_FREE_GFN ioctls and the shadow
 * page workflow: allocate, mmap, write, change_gfn remap, free.
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

static void guest_halt(void)
{
	for (;;)
		asm volatile("hlt");
}

/*
 * Test 1: Alloc, mmap, write, munmap, free - basic lifecycle.
 */
static void test_alloc_free(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	int vmi_fd;
	uint64_t shadow_gfn;
	uint64_t *shadow;

	vm = vm_create_with_one_vcpu(&vcpu, guest_halt);
	vmi_fd = vmi_create(vm);

	/* Allocate a shadow page */
	shadow_gfn = vmi_alloc_gfn(vmi_fd);
	TEST_ASSERT(shadow_gfn >= KVM_VMI_SHADOW_GFN_BASE,
		    "Shadow GFN 0x%lx should be >= base 0x%lx",
		    (unsigned long)shadow_gfn,
		    (unsigned long)KVM_VMI_SHADOW_GFN_BASE);

	/* mmap and write to it */
	shadow = mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE,
		      MAP_SHARED, vmi_fd, shadow_gfn * getpagesize());
	TEST_ASSERT(shadow != MAP_FAILED,
		    "mmap shadow page failed: errno=%d", errno);

	shadow[0] = 0xDEADBEEFCAFEBABEULL;
	TEST_ASSERT(shadow[0] == 0xDEADBEEFCAFEBABEULL,
		    "Shadow page read-back mismatch");

	/* munmap then free */
	munmap(shadow, getpagesize());
	vmi_free_gfn(vmi_fd, shadow_gfn);

	close(vmi_fd);
	kvm_vm_free(vm);
	pr_info("PASS: test_alloc_free\n");
}

/*
 * Test 2: Free while remapped via change_gfn should fail with EBUSY.
 */
static void test_free_while_remapped(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	int vmi_fd, ret;
	uint64_t shadow_gfn;
	uint32_t view_id;
	struct kvm_vmi_free_gfn free_req;

	vm = vm_create_with_one_vcpu(&vcpu, guest_halt);
	vmi_fd = vmi_create(vm);

	shadow_gfn = vmi_alloc_gfn(vmi_fd);
	view_id = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);

	/* Remap GFN 0 to our shadow page */
	vmi_change_gfn(vmi_fd, view_id, 0, shadow_gfn);

	/* Try to free - should fail */
	free_req.gfn = shadow_gfn;
	ret = ioctl(vmi_fd, KVM_VMI_FREE_GFN, &free_req);
	TEST_ASSERT(ret == -1 && errno == EBUSY,
		    "FREE_GFN while remapped should fail with EBUSY, "
		    "got ret=%d errno=%d", ret, errno);

	/* Revert the remap, then free should succeed */
	vmi_change_gfn(vmi_fd, view_id, 0, KVM_VMI_INVALID_GFN);
	vmi_free_gfn(vmi_fd, shadow_gfn);

	vmi_destroy_view(vmi_fd, view_id);
	close(vmi_fd);
	kvm_vm_free(vm);
	pr_info("PASS: test_free_while_remapped\n");
}

/*
 * Test 3: Session close auto-frees all shadow pages (no leak/crash).
 */
static void test_session_close_frees(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	int vmi_fd;

	vm = vm_create_with_one_vcpu(&vcpu, guest_halt);
	vmi_fd = vmi_create(vm);

	/* Allocate several shadow pages, don't free them */
	vmi_alloc_gfn(vmi_fd);
	vmi_alloc_gfn(vmi_fd);
	vmi_alloc_gfn(vmi_fd);

	/* Close session - kernel should free all without crash */
	close(vmi_fd);
	kvm_vm_free(vm);
	pr_info("PASS: test_session_close_frees\n");
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_ALLOC_GFN));

	test_alloc_free();
	test_free_while_remapped();
	test_session_close_frees();

	return 0;
}
