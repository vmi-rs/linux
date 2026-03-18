// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI breakpoint (INT3) monitoring test
 *
 * Tests INT3 software breakpoint interception via ring-based event delivery.
 */
#include <linux/kvm.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

static void guest_int3(void)
{
	GUEST_SYNC(1);

	/* Execute INT3 */
	__asm__ __volatile__("int3");

	GUEST_SYNC(2);

	/* Execute another INT3 */
	__asm__ __volatile__("int3");

	GUEST_SYNC(3);

	GUEST_DONE();
}

static void test_int3_basic(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_int3, &ring);

	/* Enable breakpoint monitoring */
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_BREAKPOINT, 1);

	/* Start vCPU thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* First INT3 */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for first INT3 event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_BREAKPOINT,
		    "Expected breakpoint event, got %u", ev->type);
	TEST_ASSERT(ev->insn_len == 1,
		    "INT3 is 1 byte, got %u", ev->insn_len);

	/* Skip past INT3 via SET_REGS (kernel never auto-skips) */
	ev->regs.rip += ev->insn_len;
	ev->response = KVM_VMI_RESPONSE_SET_REGS;
	vmi_ack_event(&ring, 0);

	/* Second INT3 */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for second INT3 event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_BREAKPOINT,
		    "Expected breakpoint event, got %u", ev->type);
	TEST_ASSERT(ev->insn_len == 1,
		    "INT3 is 1 byte, got %u", ev->insn_len);

	ev->regs.rip += ev->insn_len;
	ev->response = KVM_VMI_RESPONSE_SET_REGS;
	vmi_ack_event(&ring, 0);

	/* Wait for guest completion */
	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");

	vmi_test_teardown(vm, vmi_fd, &ring);
}

/*
 * Guest #BP handler: skip past INT3 (1 byte) when VMI monitoring
 * is disabled and the exception is delivered to the guest.
 */
static void guest_bp_handler(struct ex_regs *regs)
{
	regs->rip += 1; /* INT3 is 1 byte (0xCC) */
}

static void test_int3_disable(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_int3, &ring);

	/*
	 * Install a guest #BP handler so the second INT3 (after monitoring
	 * is disabled) doesn't cause an unhandled exception crash.
	 */
	vm_install_exception_handler(vm, BP_VECTOR, guest_bp_handler);

	/* Enable breakpoint monitoring */
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_BREAKPOINT, 1);

	/* Start vCPU thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* First INT3 - should trigger event */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for INT3 event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_BREAKPOINT,
		    "Expected breakpoint event");

	ev->regs.rip += ev->insn_len;
	ev->response = KVM_VMI_RESPONSE_SET_REGS;
	vmi_ack_event(&ring, 0);

	/* Disable breakpoint monitoring */
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_BREAKPOINT, 0);

	/*
	 * Second INT3 without VMI monitoring is delivered to the guest
	 * as a real #BP exception. The guest handler skips past it
	 * and the guest completes normally.
	 */
	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should complete after disabling BP monitoring");

	vmi_test_teardown(vm, vmi_fd, &ring);
}

/*
 * Test REINJECT response: VMI intercepts INT3, then reinjecting
 * causes the guest's own #BP IDT handler to fire.
 */
static void test_int3_reinject(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_int3, &ring);

	/*
	 * Install a guest #BP handler. When REINJECT is used, the guest
	 * receives a real #BP exception and this handler skips past INT3.
	 */
	vm_install_exception_handler(vm, BP_VECTOR, guest_bp_handler);

	/* Enable breakpoint monitoring */
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_BREAKPOINT, 1);

	/* Start vCPU thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* First INT3 - reinject to guest */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for first INT3 event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_BREAKPOINT,
		    "Expected breakpoint event, got %u", ev->type);

	ev->response = KVM_VMI_RESPONSE_REINJECT;
	vmi_ack_event(&ring, 0);

	/* Second INT3 - also reinject */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for second INT3 event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_BREAKPOINT,
		    "Expected breakpoint event, got %u", ev->type);

	ev->response = KVM_VMI_RESPONSE_REINJECT;
	vmi_ack_event(&ring, 0);

	/* Guest #BP handler skips both INT3s, guest completes */
	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should complete with reinjected #BP");

	vmi_test_teardown(vm, vmi_fd, &ring);
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));

	test_int3_basic();
	test_int3_disable();
	test_int3_reinject();

	return 0;
}
