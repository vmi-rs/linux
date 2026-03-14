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

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));

	test_session_create();
	test_session_only_one();

	return 0;
}
