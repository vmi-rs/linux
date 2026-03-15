// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI CPUID monitoring test
 *
 * Tests CPUID instruction interception via ring-based event delivery.
 */
#include <linux/kvm.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

static void guest_cpuid(void)
{
	uint32_t eax, ebx, ecx, edx;

	GUEST_SYNC(1);

	/* Execute CPUID leaf 0x1 (processor info) */
	__cpuid(0x1, 0, &eax, &ebx, &ecx, &edx);

	GUEST_SYNC(2);

	/* Execute CPUID leaf 0x80000001 (extended features) */
	__cpuid(0x80000001, 0, &eax, &ebx, &ecx, &edx);

	GUEST_SYNC(3);

	GUEST_DONE();
}

static void test_cpuid_basic(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_cpuid, &ring);

	/* Enable CPUID monitoring */
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_CPUID, 1);

	/* Start vCPU thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* CPUID leaf 0x1 */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for first CPUID event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_CPUID,
		    "Expected CPUID event, got %u", ev->type);
	TEST_ASSERT(ev->arch.cpuid.leaf == 0x1,
		    "Expected leaf 0x1, got 0x%x", ev->arch.cpuid.leaf);
	TEST_ASSERT(ev->arch.cpuid.subleaf == 0,
		    "Expected subleaf 0");

	ev->response = KVM_VMI_RESPONSE_EMULATE;
	vmi_ack_event(&ring, 0);

	/* CPUID leaf 0x80000001 */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for second CPUID event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_CPUID,
		    "Expected CPUID event");
	TEST_ASSERT(ev->arch.cpuid.leaf == 0x80000001,
		    "Expected leaf 0x80000001, got 0x%x", ev->arch.cpuid.leaf);

	ev->response = KVM_VMI_RESPONSE_EMULATE;
	vmi_ack_event(&ring, 0);

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");

	vmi_test_teardown(vm, vmi_fd, &ring);
}

static void guest_cpuid_modify(void)
{
	uint32_t eax, ebx, ecx, edx;

	GUEST_SYNC(1);

	/* CPUID leaf 0 - get max leaf */
	__cpuid(0, 0, &eax, &ebx, &ecx, &edx);

	/* If userspace modified EAX via SET_REGS, guest sees the modified value */
	GUEST_ASSERT(eax == 0x42);

	GUEST_DONE();
}

static void test_cpuid_modify_regs(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_cpuid_modify, &ring);

	/* Enable CPUID monitoring */
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_CPUID, 1);

	/* Start vCPU thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* CPUID intercept for leaf 0 */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for CPUID event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_CPUID,
		    "Expected CPUID event");
	TEST_ASSERT(ev->arch.cpuid.leaf == 0,
		    "Expected leaf 0");

	/*
	 * Modify RAX to 0x42 in the ring event registers.
	 * With SET_REGS, the agent controls everything - must advance
	 * RIP past the CPUID instruction manually.
	 */
	ev->regs.rax = 0x42;
	ev->regs.rip += ev->insn_len;
	ev->response = KVM_VMI_RESPONSE_SET_REGS;
	vmi_ack_event(&ring, 0);

	/* Guest should see RAX=0x42 and assert success, then DONE */
	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");

	vmi_test_teardown(vm, vmi_fd, &ring);
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));

	test_cpuid_basic();
	test_cpuid_modify_regs();

	return 0;
}
