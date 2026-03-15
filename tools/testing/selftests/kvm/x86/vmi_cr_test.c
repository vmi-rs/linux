// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI CR monitoring test
 *
 * Tests CR write interception via ring-based event delivery.
 */
#include <linux/kvm.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

/* Guest writes to CR3, then signals done */
static void guest_cr3_write(void)
{
	uint64_t cr3;

	GUEST_SYNC(1);

	/* Read current CR3, then write it back (same value) */
	__asm__ __volatile__("mov %%cr3, %0" : "=r"(cr3));
	__asm__ __volatile__("mov %0, %%cr3" : : "r"(cr3));

	GUEST_SYNC(2);

	/* Write a different CR3 value (toggle PCD bit 4, safe cache flag) */
	__asm__ __volatile__("mov %0, %%cr3" : : "r"(cr3 ^ (1ULL << 4)));

	GUEST_SYNC(3);

	GUEST_DONE();
}

static void test_cr3_basic(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;
	int cr_count = 0;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_cr3_write, &ring);

	/* Enable CR3 monitoring - all writes, even same-value */
	vmi_control_cr(vmi_fd, KVM_VMI_CR3, 0, ~0ULL, 1);

	/* Start vCPU thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* First CR3 write event (same value) */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for first CR event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_CR,
		    "Expected CR event, got %u", ev->type);
	TEST_ASSERT(ev->arch.cr.index == KVM_VMI_CR3,
		    "Expected CR3 index, got %u", ev->arch.cr.index);
	/* Same-value write: old == new */
	TEST_ASSERT(ev->arch.cr.old_value == ev->arch.cr.new_value,
		    "Expected same old/new for same-value CR3 write");
	cr_count++;
	ev->response = KVM_VMI_RESPONSE_CONTINUE;
	vmi_ack_event(&ring, 0);

	/* Second CR3 write event (different value) */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for second CR event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_CR,
		    "Expected CR event, got %u", ev->type);
	TEST_ASSERT(ev->arch.cr.index == KVM_VMI_CR3, "Expected CR3");
	TEST_ASSERT(ev->arch.cr.old_value != ev->arch.cr.new_value,
		    "Expected different old/new for changed CR3");
	cr_count++;
	ev->response = KVM_VMI_RESPONSE_CONTINUE;
	vmi_ack_event(&ring, 0);

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");
	TEST_ASSERT(cr_count == 2, "Expected 2 CR events, got %d", cr_count);

	vmi_test_teardown(vm, vmi_fd, &ring);
}

static void guest_cr3_deny(void)
{
	uint64_t cr3, cr3_after;

	GUEST_SYNC(1);

	/* Save CR3, attempt to change it (toggle PCD bit 4) */
	__asm__ __volatile__("mov %%cr3, %0" : "=r"(cr3));
	__asm__ __volatile__("mov %0, %%cr3" : : "r"(cr3 ^ (1ULL << 4)));

	/* Read CR3 back to see if it changed */
	__asm__ __volatile__("mov %%cr3, %0" : "=r"(cr3_after));

	/* If DENY worked, CR3 should still be the original value */
	GUEST_ASSERT(cr3_after == cr3);

	GUEST_DONE();
}

static void test_cr3_deny(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_cr3_deny, &ring);

	/* Enable CR3 monitoring with onchangeonly=1 */
	vmi_control_cr(vmi_fd, KVM_VMI_CR3, 1, ~0ULL, 1);

	/* Start vCPU thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* Guest tries to change CR3 */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for CR event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_CR, "Expected CR event");
	TEST_ASSERT(ev->arch.cr.index == KVM_VMI_CR3, "Expected CR3");

	/* DENY the write */
	ev->response = KVM_VMI_RESPONSE_DENY;
	vmi_ack_event(&ring, 0);

	/* Guest reads back CR3, asserts it's unchanged, then DONE */
	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");

	vmi_test_teardown(vm, vmi_fd, &ring);
}

static void test_cr3_onchangeonly(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_cr3_write, &ring);

	/* Enable CR3 monitoring with onchangeonly=1 (skip same-value writes) */
	vmi_control_cr(vmi_fd, KVM_VMI_CR3, 1, ~0ULL, 1);

	/* Start vCPU thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/*
	 * With onchangeonly=1, the same-value CR3 write should be skipped.
	 * We should only get the event for the different-value write.
	 */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for CR event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_CR, "Expected CR event");
	TEST_ASSERT(ev->arch.cr.index == KVM_VMI_CR3, "Expected CR3");
	TEST_ASSERT(ev->arch.cr.old_value != ev->arch.cr.new_value,
		    "With onchangeonly, should only see changed CR3 write");

	ev->response = KVM_VMI_RESPONSE_CONTINUE;
	vmi_ack_event(&ring, 0);

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");

	vmi_test_teardown(vm, vmi_fd, &ring);
}

static void guest_cr0_write(void)
{
	uint64_t cr0;

	GUEST_SYNC(1);

	/* Toggle CR0.WP (bit 16) */
	__asm__ __volatile__("mov %%cr0, %0" : "=r"(cr0));
	__asm__ __volatile__("mov %0, %%cr0" : : "r"(cr0 ^ (1ULL << 16)));

	GUEST_SYNC(2);

	/* Toggle CR0.NE (bit 5) - should NOT trigger event with WP-only bitmask */
	__asm__ __volatile__("mov %%cr0, %0" : "=r"(cr0));
	__asm__ __volatile__("mov %0, %%cr0" : : "r"(cr0 ^ (1ULL << 5)));

	GUEST_SYNC(3);

	GUEST_DONE();
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));

	test_cr3_basic();
	test_cr3_deny();
	test_cr3_onchangeonly();
	/*
	 * CR0 bitmask test is deferred: CR0.WP is guest-owned with EPT,
	 * so writes don't cause VM-exits without additional VMCS changes.
	 */

	return 0;
}
