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

/*
 * Test 4: Full shadow breakpoint workflow using alloc_gfn.
 *
 * Equivalent to vmi_breakpoint_workflow_test but uses ALLOC_GFN
 * instead of vm_userspace_mem_region_add for the shadow page.
 */
#define FUNC_GPA	0x900000
#define COUNTER_GPA	0x901000

static const uint8_t func_code[] = {
	0x48, 0xFF, 0x04, 0x25,
	(COUNTER_GPA >>  0) & 0xFF,
	(COUNTER_GPA >>  8) & 0xFF,
	(COUNTER_GPA >> 16) & 0xFF,
	(COUNTER_GPA >> 24) & 0xFF,
	0xC3,
};

#define INT3_OPCODE 0xCC

static void guest_bp_code(void)
{
	typedef void (*func_t)(void);
	func_t fn = (func_t)FUNC_GPA;
	volatile uint64_t *counter = (volatile uint64_t *)COUNTER_GPA;

	GUEST_SYNC(1);

	fn();
	fn();

	GUEST_SYNC(*counter);
	GUEST_DONE();
}

static void test_shadow_breakpoint_workflow(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;
	uint32_t clean_view_id, trap_view_id;
	uint8_t *func_hva;
	uint64_t *counter_hva;
	uint64_t func_gfn = FUNC_GPA >> 12;
	uint64_t shadow_gfn;
	uint8_t *shadow_hva;
	int bp_count = 0;

	vm = vm_create_with_one_vcpu(&vcpu, guest_bp_code);
	vmi_fd = vmi_create(vm);
	vmi_setup_ring(vmi_fd, 0, &ring);

	/* Map function code and counter pages */
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    FUNC_GPA, 20, 1, 0);
	virt_map(vm, FUNC_GPA, FUNC_GPA, 1);
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    COUNTER_GPA, 21, 1, 0);
	virt_map(vm, COUNTER_GPA, COUNTER_GPA, 1);

	func_hva = addr_gpa2hva(vm, FUNC_GPA);
	counter_hva = addr_gpa2hva(vm, COUNTER_GPA);
	memcpy(func_hva, func_code, sizeof(func_code));
	*counter_hva = 0;

	/* Allocate shadow page via ALLOC_GFN (no memslot needed!) */
	shadow_gfn = vmi_alloc_gfn(vmi_fd);

	/* mmap shadow page, copy code, patch INT3 */
	shadow_hva = mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE,
			  MAP_SHARED, vmi_fd, shadow_gfn * getpagesize());
	TEST_ASSERT(shadow_hva != MAP_FAILED, "mmap shadow page failed");
	memcpy(shadow_hva, func_code, sizeof(func_code));
	shadow_hva[0] = INT3_OPCODE;
	munmap(shadow_hva, getpagesize());

	/* Create views and remap */
	clean_view_id = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);
	trap_view_id = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);
	vmi_change_gfn(vmi_fd, trap_view_id, func_gfn, shadow_gfn);

	vmi_control_event(vmi_fd, KVM_VMI_EVENT_BREAKPOINT, 1);
	vmi_switch_view(vmi_fd, trap_view_id);

	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	while (!targ.done) {
		ev = vmi_wait_event_timeout(&ring, 5000);
		if (ev == NULL)
			break;
		TEST_ASSERT(ev->type == KVM_VMI_EVENT_BREAKPOINT,
			    "Expected breakpoint, got %u", ev->type);
		bp_count++;
		ev->response = KVM_VMI_RESPONSE_SWITCH_VIEW |
			       KVM_VMI_RESPONSE_SINGLESTEP_FAST;
		ev->view_id = clean_view_id;
		vmi_ack_event(&ring, 0);
	}

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");
	TEST_ASSERT(bp_count == 2, "Expected 2 breakpoints, got %d", bp_count);
	TEST_ASSERT(*counter_hva == 2, "Counter=%lu, expected 2",
		    (unsigned long)*counter_hva);

	/* Clean up: revert remap, free shadow, destroy views */
	vmi_change_gfn(vmi_fd, trap_view_id, func_gfn, KVM_VMI_INVALID_GFN);
	vmi_free_gfn(vmi_fd, shadow_gfn);
	vmi_switch_view(vmi_fd, 0);
	vmi_destroy_view(vmi_fd, trap_view_id);
	vmi_destroy_view(vmi_fd, clean_view_id);
	vmi_teardown_ring(&ring);
	close(vmi_fd);
	kvm_vm_free(vm);
	pr_info("PASS: test_shadow_breakpoint_workflow\n");
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_ALLOC_GFN));

	test_alloc_free();
	test_free_while_remapped();
	test_session_close_frees();
	test_shadow_breakpoint_workflow();

	return 0;
}
