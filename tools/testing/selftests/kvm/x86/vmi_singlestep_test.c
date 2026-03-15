// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI singlestep (MTF) monitoring test
 *
 * Tests MTF-based single-instruction stepping via ring-based event delivery.
 * Singlestep is initiated from a breakpoint event response (not a separate
 * ioctl) - the agent catches a breakpoint, responds with SINGLESTEP, and
 * then receives singlestep events for each subsequent instruction.
 */
#include <linux/kvm.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

static void guest_bp_then_nops(void)
{
	GUEST_SYNC(1);

	/* INT3 triggers breakpoint event; NOPs are singlestepped */
	__asm__ __volatile__(
		"int3\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
	);

	GUEST_SYNC(2);

	GUEST_DONE();
}

static void test_singlestep_count(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;
	int ss_count = 0;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_bp_then_nops, &ring);

	/* Enable breakpoint and singlestep event delivery */
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_BREAKPOINT, 1);
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_SINGLESTEP, 1);

	/* Start vCPU thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* Wait for INT3 breakpoint event */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for breakpoint event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_BREAKPOINT,
		    "Expected breakpoint event, got %u", ev->type);

	/* Skip past INT3 and start stepping through NOPs */
	ev->regs.rip += ev->insn_len;
	ev->response = KVM_VMI_RESPONSE_SET_REGS | KVM_VMI_RESPONSE_SINGLESTEP;
	vmi_ack_event(&ring, 0);

	/*
	 * Count singlestep events. Keep responding with SINGLESTEP flag
	 * to continue stepping. After enough events, stop stepping.
	 */
	while (!targ.done) {
		ev = vmi_wait_event_timeout(&ring, 5000);
		if (ev == NULL)
			break;

		TEST_ASSERT(ev->type == KVM_VMI_EVENT_SINGLESTEP,
			    "Expected singlestep event, got %u", ev->type);
		ss_count++;

		if (ss_count >= 5) {
			/* Stop singlestepping */
			ev->response = KVM_VMI_RESPONSE_CONTINUE;
			vmi_ack_event(&ring, 0);
			break;
		}

		/* Keep singlestepping */
		ev->response = KVM_VMI_RESPONSE_SINGLESTEP;
		vmi_ack_event(&ring, 0);
	}

	TEST_ASSERT(ss_count >= 5,
		    "Expected at least 5 singlestep events, got %d", ss_count);

	pthread_join(thread, NULL);

	vmi_test_teardown(vm, vmi_fd, &ring);
}

static void test_singlestep_disable(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_bp_then_nops, &ring);

	/* Enable breakpoint and singlestep event delivery */
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_BREAKPOINT, 1);
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_SINGLESTEP, 1);

	/* Start vCPU thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* Wait for INT3 breakpoint event */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for breakpoint event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_BREAKPOINT,
		    "Expected breakpoint event, got %u", ev->type);

	/* Skip past INT3 and start one singlestep */
	ev->regs.rip += ev->insn_len;
	ev->response = KVM_VMI_RESPONSE_SET_REGS | KVM_VMI_RESPONSE_SINGLESTEP;
	vmi_ack_event(&ring, 0);

	/* Get the one singlestep event */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for singlestep event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_SINGLESTEP,
		    "Expected singlestep event, got %u", ev->type);

	/* Respond WITHOUT singlestep flag - should stop stepping */
	ev->response = KVM_VMI_RESPONSE_CONTINUE;
	vmi_ack_event(&ring, 0);

	/* No more events should arrive (MTF auto-disabled after one-shot) */
	ev = vmi_wait_event_timeout(&ring, 500);
	TEST_ASSERT(ev == NULL,
		    "Should not get more singlestep events after one-shot");

	pthread_join(thread, NULL);

	vmi_test_teardown(vm, vmi_fd, &ring);
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));

	test_singlestep_count();
	test_singlestep_disable();

	return 0;
}
