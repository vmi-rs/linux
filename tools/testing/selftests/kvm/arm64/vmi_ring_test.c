// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI ring-based event delivery test (arm64)
 *
 * Exercises the ring transport with HVC as the producer: ring setup
 * (num_slots > 0), end-to-end delivery of a HYPERCALL event, and that
 * tearing down the session wakes a vCPU blocked on event delivery.
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

/* Issue an HVC with a known (unrecognized) SMCCC function id. */
static uint64_t guest_hvc(uint64_t fid)
{
	register uint64_t x0 asm("x0") = fid;

	asm volatile("hvc #0"
		     : "+r"(x0)
		     :
		     : "memory", "x1", "x2", "x3", "x4", "x5", "x6", "x7");
	return x0;
}

#define TEST_FID 0xdeadbeefUL

static void guest_one_hvc(void)
{
	GUEST_SYNC(1);
	guest_hvc(TEST_FID);
	GUEST_DONE();
}

static void test_ring_setup(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	int vmi_fd;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_one_hvc, &ring);

	TEST_ASSERT(ring.ring->num_slots > 0,
		    "Ring header num_slots should be > 0, got %u",
		    ring.ring->num_slots);

	vmi_test_teardown(vm, vmi_fd, &ring);
	pr_info("PASS: test_ring_setup\n");
}

static void test_ring_event_delivery(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_one_hvc, &ring);
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_HYPERCALL, 1);

	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for HVC event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_HYPERCALL,
		    "Expected HYPERCALL event, got %u", ev->type);
	TEST_ASSERT(ev->vcpu_id == 0, "Expected vcpu_id 0, got %u",
		    ev->vcpu_id);

	ev->response = KVM_VMI_RESPONSE_CONTINUE;
	vmi_ack_event(&ring, 0);

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");

	vmi_test_teardown(vm, vmi_fd, &ring);
	pr_info("PASS: test_ring_event_delivery\n");
}

static void guest_block_hvc(void)
{
	guest_hvc(TEST_FID);
	GUEST_DONE();
}

static void test_session_close_wakes_vcpu(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_block_hvc, &ring);
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_HYPERCALL, 1);

	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* Wait until the vCPU is blocked in the ring delivery. */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for HVC event");

	/*
	 * Tear down the session while the vCPU is blocked in ring delivery.
	 * vmi_teardown_ring() only frees the userspace ring mapping/fds; it is
	 * close(vmi_fd) that drives the kernel teardown (kvm_vmi_release),
	 * which sets teardown=true and wakes the blocked vCPU so the guest
	 * runs to completion. (This differs from vmi_test_teardown(), which is
	 * not usable here because the session fd is being closed directly.)
	 */
	vmi_teardown_ring(&ring);
	close(vmi_fd);

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should complete after session close");

	kvm_vm_free(vm);
	pr_info("PASS: test_session_close_wakes_vcpu\n");
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_RING));

	test_ring_setup();
	test_ring_event_delivery();
	test_session_close_wakes_vcpu();

	return 0;
}
