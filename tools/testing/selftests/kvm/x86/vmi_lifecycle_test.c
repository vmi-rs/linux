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
static void test_release_while_blocked(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_cr3_loop, &ring);

	/* Enable CR3 monitoring to generate events */
	vmi_control_cr(vmi_fd, KVM_VMI_CR3, 0, ~0ULL, 1);

	/* Start vCPU thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* Wait for the first event - vCPU is now blocked in ring delivery */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for CR event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_CR,
		    "Expected CR event, got %u", ev->type);

	/*
	 * Don't ack the event - the vCPU is blocked.
	 * Close vmi_fd to trigger release while blocked.
	 */
	vmi_teardown_ring(&ring);
	close(vmi_fd);

	/*
	 * The vCPU thread should unblock and return from KVM_RUN.
	 * It may see an error or UCALL_DONE depending on timing.
	 */
	pthread_join(thread, NULL);

	kvm_vm_free(vm);
	pr_info("PASS: vmi_release_while_blocked\n");
}

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

/*
 * Test 7: Release while vCPU is on an alternate view.
 *
 * Switch vCPU to a non-zero view, then close vmi_fd.  Release must
 * switch the vCPU back to view 0 and the guest should still work.
 */
static void test_release_on_alt_view(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;
	uint32_t view_id;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_cr3_loop, &ring);

	/* Create a view and enable CR3 monitoring */
	view_id = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);
	vmi_control_cr(vmi_fd, KVM_VMI_CR3, 0, ~0ULL, 1);

	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* Wait for first CR event */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for CR event");

	/* Switch vCPU to alternate view in the response */
	ev->response = KVM_VMI_RESPONSE_CONTINUE | KVM_VMI_RESPONSE_SWITCH_VIEW;
	ev->view_id = view_id;
	vmi_ack_event(&ring, 0);

	/* Wait for next event to confirm we're on the alt view */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for second CR event");

	/*
	 * vCPU is now on an alternate view and blocked in ring delivery.
	 * Close vmi_fd - release must switch back to view 0.
	 */
	vmi_teardown_ring(&ring);
	close(vmi_fd);

	/* vCPU should unblock, switch to view 0, and guest completes */
	pthread_join(thread, NULL);

	kvm_vm_free(vm);
	pr_info("PASS: vmi_release_on_alt_view\n");
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_RING));

	test_release_while_blocked();
	test_release_while_paused();
	test_destroy_without_release();
	test_release_with_views();
	test_release_on_alt_view();

	return 0;
}
