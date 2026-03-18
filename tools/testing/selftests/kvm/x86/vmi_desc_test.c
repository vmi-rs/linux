// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI descriptor access monitoring test
 *
 * Tests descriptor table register access interception via ring-based
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

/* Descriptor table pseudo-descriptor (used by SGDT/SIDT) */
struct desc_ptr_guest {
	uint16_t limit;
	uint64_t base;
} __attribute__((packed));

static void guest_desc_access(void)
{
	struct desc_ptr_guest gdtr, idtr;

	GUEST_SYNC(1);

	/* SGDT - reads GDTR (descriptor access, store/read) */
	__asm__ __volatile__("sgdt %0" : "=m"(gdtr));

	GUEST_SYNC(2);

	/* SIDT - reads IDTR (descriptor access, store/read) */
	__asm__ __volatile__("sidt %0" : "=m"(idtr));

	GUEST_SYNC(3);

	GUEST_DONE();
}

static void test_desc_access_basic(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_desc_access, &ring);

	/* Enable descriptor access monitoring */
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_DESC_ACCESS, 1);

	/* Start vCPU thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* SGDT event */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for SGDT event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_DESC_ACCESS,
		    "Expected desc_access event, got %u", ev->type);
	TEST_ASSERT(ev->arch.desc_access.descriptor == KVM_VMI_DESC_GDTR,
		    "Expected GDTR descriptor, got %u",
		    ev->arch.desc_access.descriptor);
	TEST_ASSERT(ev->arch.desc_access.is_write == 0,
		    "SGDT is a read (store), not a write (load)");

	ev->response = KVM_VMI_RESPONSE_EMULATE;
	vmi_ack_event(&ring, 0);

	/* SIDT event */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for SIDT event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_DESC_ACCESS,
		    "Expected desc_access event");
	TEST_ASSERT(ev->arch.desc_access.descriptor == KVM_VMI_DESC_IDTR,
		    "Expected IDTR descriptor, got %u",
		    ev->arch.desc_access.descriptor);
	TEST_ASSERT(ev->arch.desc_access.is_write == 0,
		    "SIDT is a read (store)");

	ev->response = KVM_VMI_RESPONSE_EMULATE;
	vmi_ack_event(&ring, 0);

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");

	vmi_test_teardown(vm, vmi_fd, &ring);
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));

	test_desc_access_basic();

	return 0;
}
