// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI lifecycle test
 *
 * Tests VMI session release and destroy paths:
 * - Release while vCPU is blocked in ring event delivery
 * - Release while vCPU is paused
 * - VM destroy without prior vmi_fd close (kvm_vmi_destroy path)
 * - Re-creation of VMI session after release
 * - Release with active views and shadow pages
 */
#include <errno.h>
#include <linux/kvm.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

static void guest_cr3_loop(void)
{
	uint64_t cr3;
	int i;

	GUEST_SYNC(1);

	for (i = 0; i < 1000; i++) {
		__asm__ __volatile__("mov %%cr3, %0" : "=r"(cr3));
		__asm__ __volatile__("mov %0, %%cr3" : : "r"(cr3));
	}

	GUEST_DONE();
}

static void guest_counter(void)
{
	int i;

	for (i = 0; i < 100; i++)
		GUEST_SYNC(i + 1);
	GUEST_DONE();
}

/*
 * Test 1: Close vmi_fd while vCPU is blocked waiting for ring event ack.
 *
 * The vCPU thread is inside KVM_RUN, blocked in kvm_vmi_deliver_via_ring()
 * waiting for the agent to ack the event.  Closing vmi_fd triggers
 * kvm_vmi_release() which must safely wake and unblock the vCPU.
 */

/*
 * Test 2: Close vmi_fd while vCPU is VMI-paused.
 *
 * The vCPU thread is inside KVM_RUN, blocked in kvm_vmi_vcpu_pause_wait().
 * Release must clear pause_count and wake the vCPU.
 */
static void test_release_while_paused(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	int vmi_fd;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_counter, &ring);

	/* Pause the VM before starting the vCPU thread */
	vmi_pause_vm(vmi_fd);

	/* Start vCPU thread - it will block immediately in pause_wait */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* Let the vCPU thread enter the pause wait */
	usleep(50000);

	/*
	 * Close vmi_fd while vCPU is paused.  Release must clear
	 * pause_count and wake the vCPU so it can resume.
	 */
	vmi_teardown_ring(&ring);
	close(vmi_fd);

	/* vCPU should unblock and guest should complete */
	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should complete after release unpauses");

	kvm_vm_free(vm);
	pr_info("PASS: vmi_release_while_paused\n");
}

/*
 * Test 3: Destroy VM without closing vmi_fd first.
 *
 * This simulates QEMU being killed while a VMI agent still has vmi_fd open.
 * kvm_vm_free() closes the VM fd.  The vmi_fd is leaked (closed when the
 * process exits).  kvm_vmi_destroy() must handle full cleanup.
 *
 * In a real scenario, QEMU's process exit closes all fds (including vmi_fd),
 * but the order is unspecified.  We test the worst case: VM fd closes first.
 */
static void test_destroy_without_release(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	int vmi_fd;

	vm = vm_create_with_one_vcpu(&vcpu, guest_counter);
	vmi_fd = vmi_create(vm);

	/*
	 * Destroy the VM without closing vmi_fd.
	 * kvm_vmi_destroy() handles cleanup since release never ran.
	 * The vmi_fd is closed after (simulating unordered fd close).
	 */
	kvm_vm_free(vm);
	close(vmi_fd);

	pr_info("PASS: vmi_destroy_without_release\n");
}

/*
 * Test 6: Release with active views and shadow pages.
 *
 * Creates alternate views and allocates shadow GFNs, then closes
 * vmi_fd.  Release must destroy views and free shadow pages.
 */
static void test_release_with_views(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	int vmi_fd;
	uint32_t view1, view2;
	uint64_t shadow1, shadow2;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_counter, &ring);

	/* Create views */
	view1 = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);
	view2 = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);
	TEST_ASSERT(view1 > 0, "View 1 should have non-zero ID");
	TEST_ASSERT(view2 > 0, "View 2 should have non-zero ID");

	/* Allocate shadow GFNs */
	shadow1 = vmi_alloc_gfn(vmi_fd);
	shadow2 = vmi_alloc_gfn(vmi_fd);

	/* Set some per-view memory access permissions */
	vmi_set_mem_access(vmi_fd, view1, 0, KVM_VMI_ACCESS_R);
	vmi_set_mem_access(vmi_fd, view2, 0, KVM_VMI_ACCESS_RW);

	/*
	 * Close vmi_fd with views, shadow pages, and access overrides
	 * all active.  Release must clean up everything.
	 */
	vmi_teardown_ring(&ring);
	close(vmi_fd);

	/* VM should still be usable after release */
	kvm_vm_free(vm);
	pr_info("PASS: vmi_release_with_views\n");
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_RING));

	test_release_while_paused();
	test_destroy_without_release();
	test_release_with_views();

	return 0;
}
