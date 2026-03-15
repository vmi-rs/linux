// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI (Virtual Machine Introspection) basic tests
 *
 * Tests for:
 * - KVM_CAP_VMI capability detection
 * - KVM_CREATE_VMI ioctl (create VMI session)
 * - KVM_VMI_CONTROL_EVENT basic validation via vmi_fd
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

/*
 * Simple guest code: just halt.
 * We don't run it in most tests; these are ioctl-level tests.
 */
static void guest_code(void)
{
	for (;;)
		asm volatile("hlt");
}

/*
 * Test 1: KVM_CAP_VMI capability is reported
 */
static void test_cap_vmi(void)
{
	int r;

	r = kvm_check_cap(KVM_CAP_VMI);
	TEST_ASSERT(r > 0,
		    "KVM_CAP_VMI should be supported, got %d", r);
	pr_info("PASS: KVM_CAP_VMI is supported (value=%d)\n", r);
}

/*
 * Test 2: Sub-capabilities are reported
 */
static void test_sub_caps(void)
{
	TEST_ASSERT(kvm_check_cap(KVM_CAP_VMI_RING) > 0,
		    "KVM_CAP_VMI_RING should be supported");
	TEST_ASSERT(kvm_check_cap(KVM_CAP_VMI_GUEST_MMAP) > 0,
		    "KVM_CAP_VMI_GUEST_MMAP should be supported");
	TEST_ASSERT(kvm_check_cap(KVM_CAP_VMI_PAUSE) > 0,
		    "KVM_CAP_VMI_PAUSE should be supported");
	TEST_ASSERT(kvm_check_cap(KVM_CAP_VMI_INJECT) > 0,
		    "KVM_CAP_VMI_INJECT should be supported");
	pr_info("PASS: All VMI sub-capabilities are supported\n");
}

/*
 * Test 3: KVM_CREATE_VMI succeeds on a fresh VM and returns fd >= 0
 */
static void test_vmi_create(void)
{
	struct kvm_vm *vm;
	int fd;

	vm = vm_create_barebones();
	fd = __vm_ioctl(vm, KVM_CREATE_VMI, NULL);
	TEST_ASSERT(fd >= 0,
		    "KVM_CREATE_VMI should return fd >= 0 on fresh VM, got %d (errno=%d)",
		    fd, errno);

	close(fd);
	kvm_vm_free(vm);
	pr_info("PASS: KVM_CREATE_VMI succeeds on fresh VM\n");
}

/*
 * Test 4: Second KVM_CREATE_VMI fails with -EBUSY while session is active
 */
static void test_vmi_create_twice(void)
{
	struct kvm_vm *vm;
	int fd, fd2;

	vm = vm_create_barebones();
	fd = __vm_ioctl(vm, KVM_CREATE_VMI, NULL);
	TEST_ASSERT(fd >= 0,
		    "First KVM_CREATE_VMI should succeed, got %d", fd);

	fd2 = __vm_ioctl(vm, KVM_CREATE_VMI, NULL);
	TEST_ASSERT(fd2 == -1 && errno == EBUSY,
		    "Second KVM_CREATE_VMI should fail with EBUSY, got fd2=%d errno=%d",
		    fd2, errno);

	close(fd);
	kvm_vm_free(vm);
	pr_info("PASS: KVM_CREATE_VMI correctly fails on second call\n");
}

/*
 * Test 5: Close vmi_fd, then KVM_CREATE_VMI again (re-create after cleanup)
 */
static void test_vmi_create_close_recreate(void)
{
	struct kvm_vm *vm;
	int fd;

	vm = vm_create_barebones();

	/* First session */
	fd = __vm_ioctl(vm, KVM_CREATE_VMI, NULL);
	TEST_ASSERT(fd >= 0,
		    "First KVM_CREATE_VMI should succeed, got %d", fd);
	close(fd);

	/* After close, should be able to create again */
	fd = __vm_ioctl(vm, KVM_CREATE_VMI, NULL);
	TEST_ASSERT(fd >= 0,
		    "KVM_CREATE_VMI after close should succeed, got %d (errno=%d)",
		    fd, errno);
	close(fd);

	kvm_vm_free(vm);
	pr_info("PASS: KVM_CREATE_VMI succeeds after close (re-create)\n");
}

/*
 * Test 6: KVM_VMI_CONTROL_EVENT validates event type
 */
static void test_control_event_invalid(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	int vmi_fd, r;

	vm = vm_create_with_one_vcpu(&vcpu, guest_code);
	vmi_fd = vmi_create(vm);

	/* Invalid event type should fail */
	r = vmi_control_event_err(vmi_fd, KVM_VMI_NUM_EVENTS, 1);
	TEST_ASSERT(r == -1 && errno == EINVAL,
		    "Invalid event type should fail with EINVAL, got r=%d errno=%d",
		    r, errno);

	close(vmi_fd);
	kvm_vm_free(vm);
	pr_info("PASS: Invalid event type correctly rejected\n");
}

/*
 * Test 7: KVM_VMI_CONTROL_EVENT enable/disable CR monitoring
 */
static void test_control_event_cr(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	int vmi_fd;

	vm = vm_create_with_one_vcpu(&vcpu, guest_code);
	vmi_fd = vmi_create(vm);

	/* Enable CR3 monitoring */
	vmi_control_cr(vmi_fd, KVM_VMI_CR3, 0, ~0ULL, 1);

	/* Disable CR3 monitoring */
	vmi_control_cr(vmi_fd, KVM_VMI_CR3, 0, ~0ULL, 0);

	close(vmi_fd);
	kvm_vm_free(vm);
	pr_info("PASS: CR3 event enable/disable works\n");
}

/*
 * Test 8: KVM_VMI_CONTROL_EVENT with invalid CR index
 */
static void test_control_event_cr_invalid_index(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct kvm_vmi_control_event ctl = {};
	int vmi_fd, r;

	vm = vm_create_with_one_vcpu(&vcpu, guest_code);
	vmi_fd = vmi_create(vm);

	/* Invalid CR index (e.g., CR2 is not monitorable) */
	ctl.event = KVM_VMI_EVENT_CR;
	ctl.enable = 1;
	ctl.arch.cr.index = 2; /* CR2 -- not a valid VMI CR index */
	ctl.arch.cr.bitmask = ~0ULL;

	r = ioctl(vmi_fd, KVM_VMI_CONTROL_EVENT, &ctl);
	TEST_ASSERT(r == -1 && errno == EINVAL,
		    "Invalid CR index should fail with EINVAL, got r=%d errno=%d",
		    r, errno);

	close(vmi_fd);
	kvm_vm_free(vm);
	pr_info("PASS: Invalid CR index correctly rejected\n");
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));

	test_cap_vmi();
	test_sub_caps();
	test_vmi_create();
	test_vmi_create_twice();
	test_vmi_create_close_recreate();
	test_control_event_invalid();
	test_control_event_cr();
	test_control_event_cr_invalid_index();

	return 0;
}
