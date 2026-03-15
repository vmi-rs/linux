// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI MSR monitoring test
 *
 * Tests MSR write interception via ring-based event delivery.
 */
#include <linux/kvm.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

#define TEST_MSR	MSR_IA32_SYSENTER_EIP  /* 0x176 */

static void guest_msr_write(void)
{
	GUEST_SYNC(1);

	/* Write to SYSENTER_EIP */
	wrmsr(TEST_MSR, 0xdeadbeef);

	GUEST_SYNC(2);

	/* Write same value again */
	wrmsr(TEST_MSR, 0xdeadbeef);

	GUEST_SYNC(3);

	GUEST_DONE();
}

static void test_msr_basic(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_msr_write, &ring);

	/* Enable MSR monitoring for SYSENTER_EIP, onchangeonly=0 */
	vmi_control_msr(vmi_fd, TEST_MSR, 0, 1);

	/* Start vCPU thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* First MSR write: 0xdeadbeef */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for first MSR event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_MSR,
		    "Expected MSR event, got %u", ev->type);
	TEST_ASSERT(ev->arch.msr.index == TEST_MSR,
		    "Expected MSR index 0x%x, got 0x%x",
		    TEST_MSR, ev->arch.msr.index);
	TEST_ASSERT(ev->arch.msr.new_value == 0xdeadbeef,
		    "Expected new_value 0xdeadbeef, got 0x%llx",
		    (unsigned long long)ev->arch.msr.new_value);

	ev->response = KVM_VMI_RESPONSE_CONTINUE;
	vmi_ack_event(&ring, 0);

	/* Second MSR write: same value (onchangeonly=0 so it still triggers) */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for second MSR event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_MSR,
		    "Expected MSR event for same-value write");
	TEST_ASSERT(ev->arch.msr.old_value == ev->arch.msr.new_value,
		    "Expected old == new for same-value write");

	ev->response = KVM_VMI_RESPONSE_CONTINUE;
	vmi_ack_event(&ring, 0);

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");

	vmi_test_teardown(vm, vmi_fd, &ring);
}

static void guest_msr_deny(void)
{
	uint64_t val;

	GUEST_SYNC(1);

	/* Write to SYSENTER_EIP */
	wrmsr(TEST_MSR, 0xcafebabe);

	/* Read it back */
	val = rdmsr(TEST_MSR);

	/* If DENY worked, value should not be 0xcafebabe */
	GUEST_ASSERT(val != 0xcafebabe);

	GUEST_DONE();
}

static void test_msr_deny(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_msr_deny, &ring);

	/* Enable MSR monitoring */
	vmi_control_msr(vmi_fd, TEST_MSR, 0, 1);

	/* Start vCPU thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* Guest tries WRMSR */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for MSR event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_MSR,
		    "Expected MSR event");
	TEST_ASSERT(ev->arch.msr.index == TEST_MSR,
		    "Expected MSR 0x%x", TEST_MSR);

	/* DENY the write */
	ev->response = KVM_VMI_RESPONSE_DENY;
	vmi_ack_event(&ring, 0);

	/* Guest reads back MSR, asserts unchanged, then DONE */
	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");

	vmi_test_teardown(vm, vmi_fd, &ring);
}

static void guest_msr_onchangeonly(void)
{
	GUEST_SYNC(1);

	/* Write to SYSENTER_EIP - first write always changes value */
	wrmsr(TEST_MSR, 0x11111111);

	GUEST_SYNC(2);

	/* Write same value again - should be filtered with onchangeonly */
	wrmsr(TEST_MSR, 0x11111111);

	GUEST_SYNC(3);

	/* Write different value - should trigger */
	wrmsr(TEST_MSR, 0x22222222);

	GUEST_SYNC(4);

	GUEST_DONE();
}

static void test_msr_onchangeonly(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_msr_onchangeonly, &ring);

	/* Enable MSR monitoring with onchangeonly=1 */
	vmi_control_msr(vmi_fd, TEST_MSR, 1, 1);

	/* Start vCPU thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* First write to 0x11111111 - should trigger (value changes from 0) */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for first MSR event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_MSR,
		    "Expected MSR event for first write");

	ev->response = KVM_VMI_RESPONSE_CONTINUE;
	vmi_ack_event(&ring, 0);

	/*
	 * Same-value write should be skipped with onchangeonly=1.
	 * Next event should be the different-value write (0x22222222).
	 */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for changed MSR event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_MSR,
		    "Expected MSR event for changed write");

	ev->response = KVM_VMI_RESPONSE_CONTINUE;
	vmi_ack_event(&ring, 0);

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");

	vmi_test_teardown(vm, vmi_fd, &ring);
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));

	test_msr_basic();
	test_msr_deny();
	test_msr_onchangeonly();

	return 0;
}
