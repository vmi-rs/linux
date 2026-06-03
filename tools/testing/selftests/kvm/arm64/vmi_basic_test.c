// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI (Virtual Machine Introspection) basic tests (arm64)
 *
 * Tests for:
 * - KVM_CAP_VMI capability detection
 * - KVM_CREATE_VMI ioctl (create VMI session, EBUSY, recreate)
 * - KVM_VMI_CONTROL_EVENT event-type validation via vmi_fd
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
 * Simple guest code: spin. These are ioctl-level tests; the guest is
 * not run.
 */
static void guest_code(void)
{
	for (;;)
		asm volatile("wfi");
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
 * Test 2: KVM_CREATE_VMI succeeds on a fresh VM and returns fd >= 0
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
 * Test 3: Second KVM_CREATE_VMI fails with -EBUSY while session is active
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
 * Test 4: Close vmi_fd, then KVM_CREATE_VMI again (re-create after cleanup)
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
 * Test 5: KVM_VMI_CONTROL_EVENT validates event type
 */
static void test_control_event_invalid(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	int vmi_fd, r;

	vm = vm_create_with_one_vcpu(&vcpu, guest_code);
	vmi_fd = vmi_create(vm);

	/* Out-of-range event type should fail with EINVAL */
	r = vmi_control_event_err(vmi_fd, KVM_VMI_NUM_EVENTS, 1);
	TEST_ASSERT(r == -1 && errno == EINVAL,
		    "Invalid event type should fail with EINVAL, got r=%d errno=%d",
		    r, errno);

	close(vmi_fd);
	kvm_vm_free(vm);
	pr_info("PASS: Invalid event type correctly rejected\n");
}

int main(int argc, char *argv[])
{
	vmi_force_el1_guests();
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));

	test_cap_vmi();
	test_vmi_create();
	test_vmi_create_twice();
	test_vmi_create_close_recreate();
	test_control_event_invalid();

	return 0;
}
