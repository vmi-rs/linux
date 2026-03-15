// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI hypercall monitoring test
 *
 * Tests guest hypercall (VMCALL/VMMCALL) interception via ring-based
 * event delivery.
 */
#include <linux/kvm.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

#define TEST_HC_NR	0xdeadbeef
#define TEST_HC_A0	0x1111
#define TEST_HC_A1	0x2222
#define TEST_HC_A2	0x3333

static void guest_hypercall(void)
{
	GUEST_SYNC(1);

	/* Issue a hypercall with known arguments */
	kvm_hypercall(TEST_HC_NR, TEST_HC_A0, TEST_HC_A1, TEST_HC_A2, 0);

	GUEST_SYNC(2);

	/* Issue a second hypercall with different number */
	kvm_hypercall(0x42, 0, 0, 0, 0);

	GUEST_SYNC(3);

	GUEST_DONE();
}

static void test_hypercall_basic(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_hypercall, &ring);

	/* Enable hypercall monitoring */
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_HYPERCALL, 1);

	/* Start vCPU thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* First hypercall */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for first hypercall event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_HYPERCALL,
		    "Expected HYPERCALL event, got %u", ev->type);
	TEST_ASSERT(ev->regs.rax == TEST_HC_NR,
		    "Expected nr 0x%x, got 0x%llx",
		    TEST_HC_NR, ev->regs.rax);
	TEST_ASSERT(ev->regs.rbx == TEST_HC_A0,
		    "Expected a0 0x%x, got 0x%llx",
		    TEST_HC_A0, ev->regs.rbx);
	TEST_ASSERT(ev->regs.rcx == TEST_HC_A1,
		    "Expected a1 0x%x, got 0x%llx",
		    TEST_HC_A1, ev->regs.rcx);
	TEST_ASSERT(ev->regs.rdx == TEST_HC_A2,
		    "Expected a2 0x%x, got 0x%llx",
		    TEST_HC_A2, ev->regs.rdx);

	/* EMULATE: let normal hypercall handling proceed */
	ev->response = KVM_VMI_RESPONSE_EMULATE;
	vmi_ack_event(&ring, 0);

	/* Second hypercall */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for second hypercall event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_HYPERCALL,
		    "Expected HYPERCALL event");
	TEST_ASSERT(ev->regs.rax == 0x42,
		    "Expected nr 0x42, got 0x%llx", ev->regs.rax);

	ev->response = KVM_VMI_RESPONSE_EMULATE;
	vmi_ack_event(&ring, 0);

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");

	vmi_test_teardown(vm, vmi_fd, &ring);
}

static void guest_hypercall_deny(void)
{
	GUEST_SYNC(1);

	/*
	 * Issue a hypercall - agent will DENY it.
	 * The VMCALL instruction is skipped without executing.
	 */
	kvm_hypercall(TEST_HC_NR, 0, 0, 0, 0);

	GUEST_SYNC(2);

	GUEST_DONE();
}

static void test_hypercall_deny(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_hypercall_deny, &ring);

	vmi_control_event(vmi_fd, KVM_VMI_EVENT_HYPERCALL, 1);

	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for hypercall event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_HYPERCALL,
		    "Expected HYPERCALL event");

	/* DENY: skip the instruction without executing it */
	ev->response = KVM_VMI_RESPONSE_DENY;
	vmi_ack_event(&ring, 0);

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");

	vmi_test_teardown(vm, vmi_fd, &ring);
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));

	test_hypercall_basic();
	test_hypercall_deny();

	return 0;
}
