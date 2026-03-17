// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI ring-based delivery infrastructure test
 *
 * Tests session creation, ring setup, event delivery via ring,
 * session teardown semantics, and ring teardown.
 */
#include <errno.h>
#include <linux/kvm.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

static void guest_halt(void)
{
	for (;;)
		asm volatile("hlt");
}

/*
 * Test 1: Create a VMI session. Verify vmi_fd >= 0.
 */
static void test_session_create(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	int vmi_fd;

	vm = vm_create_with_one_vcpu(&vcpu, guest_halt);

	vmi_fd = __vm_ioctl(vm, KVM_CREATE_VMI, NULL);
	TEST_ASSERT(vmi_fd >= 0,
		    "KVM_CREATE_VMI should return fd >= 0, got %d (errno=%d)",
		    vmi_fd, errno);

	close(vmi_fd);
	kvm_vm_free(vm);
	pr_info("PASS: test_session_create\n");
}

/*
 * Test 2: Creating a second session should fail with EBUSY.
 */
static void test_session_only_one(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	int vmi_fd, vmi_fd2;

	vm = vm_create_with_one_vcpu(&vcpu, guest_halt);

	vmi_fd = __vm_ioctl(vm, KVM_CREATE_VMI, NULL);
	TEST_ASSERT(vmi_fd >= 0,
		    "First KVM_CREATE_VMI should succeed, got %d", vmi_fd);

	vmi_fd2 = __vm_ioctl(vm, KVM_CREATE_VMI, NULL);
	TEST_ASSERT(vmi_fd2 < 0 && errno == EBUSY,
		    "Second KVM_CREATE_VMI should fail with EBUSY, got fd=%d errno=%d",
		    vmi_fd2, errno);

	close(vmi_fd);
	kvm_vm_free(vm);
	pr_info("PASS: test_session_only_one\n");
}

/*
 * Test 3: Setup ring for a vCPU. Verify ring_fd, mmap, and header.
 */
static void test_ring_setup(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	int vmi_fd;

	vm = vm_create_with_one_vcpu(&vcpu, guest_halt);
	vmi_fd = vmi_create(vm);

	vmi_setup_ring(vmi_fd, 0, &ring);

	TEST_ASSERT(ring.ring_fd >= 0,
		    "ring_fd should be >= 0, got %d", ring.ring_fd);
	TEST_ASSERT(ring.ring != NULL && ring.ring != MAP_FAILED,
		    "Ring mmap should succeed");
	TEST_ASSERT(ring.ring->num_slots > 0,
		    "Ring header num_slots should be > 0, got %u",
		    ring.ring->num_slots);

	vmi_teardown_ring(&ring);
	close(vmi_fd);
	kvm_vm_free(vm);
	pr_info("PASS: test_ring_setup\n");
}

/*
 * Test 6: Setup ring, then teardown via KVM_VMI_TEARDOWN_RING ioctl.
 */
static void test_ring_teardown(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	int vmi_fd, ret;
	__u32 vcpu_id = 0;

	vm = vm_create_with_one_vcpu(&vcpu, guest_halt);
	vmi_fd = vmi_create(vm);
	vmi_setup_ring(vmi_fd, 0, &ring);

	/* Unmap the ring before teardown ioctl */
	if (ring.ring && ring.ring != MAP_FAILED)
		munmap(ring.ring, getpagesize());
	ring.ring = NULL;

	/* Teardown via ioctl */
	ret = ioctl(vmi_fd, KVM_VMI_TEARDOWN_RING, &vcpu_id);
	TEST_ASSERT(ret == 0,
		    "KVM_VMI_TEARDOWN_RING should succeed, got %d (errno=%d)",
		    ret, errno);

	/* Clean up remaining fds (ring_fd was invalidated by teardown) */
	if (ring.ring_fd >= 0)
		close(ring.ring_fd);
	if (ring.event_fd >= 0)
		close(ring.event_fd);
	if (ring.ack_fd >= 0)
		close(ring.ack_fd);

	close(vmi_fd);
	kvm_vm_free(vm);
	pr_info("PASS: test_ring_teardown\n");
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_RING));

	test_session_create();
	test_session_only_one();
	test_ring_setup();
	test_ring_teardown();

	return 0;
}
