// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI debug exception monitoring test
 *
 * Tests #DB debug exception interception via ring-based event delivery.
 */
#include <linux/kvm.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

static void guest_debug_exception(void)
{
	GUEST_SYNC(1);

	/*
	 * Set hardware breakpoint on DR0 = address of a NOP,
	 * then execute that NOP to trigger #DB.
	 * DR7 bit 0 enables DR0, bits 16-17 = 00 (execute), bits 18-19 = 00 (1 byte).
	 * Bit 10 is reserved and must be 1.
	 */
	__asm__ __volatile__(
		"lea 1f(%%rip), %%rax\n\t"
		"mov %%rax, %%dr0\n\t"
		"mov $0x401, %%rax\n\t"  /* DR7: enable DR0, local exact */
		"mov %%rax, %%dr7\n\t"
		"1: nop\n\t"
		"xor %%rax, %%rax\n\t"
		"mov %%rax, %%dr7\n\t"  /* Disable DR0 */
		: : : "rax"
	);

	GUEST_SYNC(2);
	GUEST_DONE();
}

static void test_debug_exception_basic(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_debug_exception, &ring);

	/* Enable debug event monitoring */
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_DEBUG, 1);

	/* Start vCPU thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* #DB from hardware breakpoint */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for debug event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_DEBUG,
		    "Expected debug event, got %u", ev->type);

	/* Continue */
	ev->response = KVM_VMI_RESPONSE_CONTINUE;
	vmi_ack_event(&ring, 0);

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");

	vmi_test_teardown(vm, vmi_fd, &ring);
}

/*
 * Guest #DB handler for reinject test: disable DR0 so the breakpoint
 * doesn't re-trigger, then return.  The RF flag set by the CPU on
 * #DB delivery also suppresses re-triggering for one instruction.
 */
static void guest_db_handler(struct ex_regs *regs)
{
	/* Disable all hardware breakpoints */
	__asm__ __volatile__("xor %%rax, %%rax\n\t"
			     "mov %%rax, %%dr7\n\t" : : : "rax");
}

static void guest_debug_reinject(void)
{
	GUEST_SYNC(1);

	/*
	 * Set hardware breakpoint on DR0 = address of a NOP,
	 * then execute that NOP to trigger #DB.
	 * DR7: bit 0 = enable DR0, bit 10 = reserved (must be 1).
	 */
	__asm__ __volatile__(
		"lea 1f(%%rip), %%rax\n\t"
		"mov %%rax, %%dr0\n\t"
		"mov $0x401, %%rax\n\t"
		"mov %%rax, %%dr7\n\t"
		"1: nop\n\t"
		: : : "rax"
	);

	/* If #DB was reinjected, guest handler cleared DR7 and we get here */
	GUEST_SYNC(2);
	GUEST_DONE();
}

static void test_debug_reinject(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_debug_reinject, &ring);

	/* Install guest #DB handler */
	vm_install_exception_handler(vm, DB_VECTOR, guest_db_handler);

	/* Enable debug event monitoring */
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_DEBUG, 1);

	/* Start vCPU thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* Wait for #DB event */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for debug event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_DEBUG,
		    "Expected debug event, got %u", ev->type);
	TEST_ASSERT(ev->arch.debug.pending_dbg != 0,
		    "DR6 should indicate a debug condition");

	/* Reinject #DB to guest */
	ev->response = KVM_VMI_RESPONSE_REINJECT;
	vmi_ack_event(&ring, 0);

	/* Guest #DB handler fires, clears DR7, guest completes */
	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done,
		    "Guest should complete after reinjected #DB");

	vmi_test_teardown(vm, vmi_fd, &ring);
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));

	test_debug_exception_basic();
	test_debug_reinject();

	return 0;
}
