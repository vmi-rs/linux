// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI CPUID interception test (simplified)
 *
 * Originally tested exception injection via RESP_INJECT_EXCEPTION in the
 * Layer 1 kvm_run response. The ring-based API does not support inline
 * exception injection in the response; injection is done via a separate
 * KVM_VMI_INJECT_EVENT ioctl. For now, this test verifies basic CPUID
 * interception via the ring: two CPUID instructions are intercepted and
 * their leaf values verified.
 *
 * TODO: Add exception injection test using KVM_VMI_INJECT_EVENT ioctl.
 */
#include <linux/kvm.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

static void guest_code(void)
{
	uint32_t eax, ebx, ecx, edx;

	GUEST_SYNC(1); /* Ready */

	/* First CPUID: leaf 0 */
	__asm__ __volatile__(
		"cpuid"
		: "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
		: "a"(0), "c"(0)
	);

	GUEST_SYNC(2);

	/* Second CPUID: leaf 1 */
	__asm__ __volatile__(
		"cpuid"
		: "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
		: "a"(1), "c"(0)
	);

	GUEST_SYNC(3);

	GUEST_DONE();
}

int main(int argc, char *argv[])
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;
	int cpuid_events = 0;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_code, &ring);

	/* Enable CPUID monitoring */
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_CPUID, 1);

	/* Start vCPU thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* First CPUID event: leaf 0 */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for first CPUID event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_CPUID,
		    "Expected CPUID event, got %u", ev->type);
	TEST_ASSERT(ev->arch.cpuid.leaf == 0,
		    "Expected leaf 0, got 0x%x", ev->arch.cpuid.leaf);
	cpuid_events++;

	ev->response = KVM_VMI_RESPONSE_EMULATE;
	vmi_ack_event(&ring, 0);

	/* Second CPUID event: leaf 1 */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for second CPUID event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_CPUID,
		    "Expected CPUID event, got %u", ev->type);
	TEST_ASSERT(ev->arch.cpuid.leaf == 1,
		    "Expected leaf 1, got 0x%x", ev->arch.cpuid.leaf);
	cpuid_events++;

	ev->response = KVM_VMI_RESPONSE_EMULATE;
	vmi_ack_event(&ring, 0);

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");

	TEST_ASSERT(cpuid_events == 2,
		    "Expected 2 CPUID events, got %d", cpuid_events);

	pr_info("PASS: %d CPUID events intercepted via ring.\n",
		cpuid_events);

	vmi_test_teardown(vm, vmi_fd, &ring);
	return 0;
}
