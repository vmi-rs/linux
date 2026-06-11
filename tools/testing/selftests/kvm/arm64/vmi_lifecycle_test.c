// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI lifecycle test (arm64)
 *
 * Tests the VMI session create / release / destroy paths:
 * - Create then close vmi_fd (kvm_vmi_release)
 * - Destroy the VM without closing vmi_fd first (kvm_vmi_destroy)
 * - Same, with a vCPU so there is per-vCPU state to clean up
 * - Re-create a session after release
 *
 * This is the K1 subset: it exercises only lifecycle. Ring/event,
 * pause, and view coverage is added by later commits as those features
 * land.
 */
#include <errno.h>
#include <linux/kvm.h>
#include <unistd.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

static void guest_code(void)
{
	for (;;)
		asm volatile("wfi");
}

/*
 * Test 1: Create a session, close vmi_fd (release), VM still usable.
 */
static void test_create_release(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	int vmi_fd;

	vm = vm_create_with_one_vcpu(&vcpu, guest_code);
	vmi_fd = vmi_create(vm);

	/* Release the session by closing the fd. */
	close(vmi_fd);

	/* VM must still be usable after release. */
	kvm_vm_free(vm);
	pr_info("PASS: vmi_create_release\n");
}

/*
 * Test 2: Destroy the VM without closing vmi_fd first.
 *
 * Simulates the VMM exiting while a VMI agent still holds vmi_fd.
 * kvm_vm_free() closes the VM fd; kvm_vmi_destroy() must perform full
 * cleanup since kvm_vmi_release() never ran. The vmi_fd is closed after
 * (unordered fd close, worst case: VM fd first).
 */
static void test_destroy_without_release(void)
{
	struct kvm_vm *vm;
	int vmi_fd;

	vm = vm_create_barebones();
	vmi_fd = __vm_ioctl(vm, KVM_CREATE_VMI, NULL);
	TEST_ASSERT(vmi_fd >= 0, "KVM_CREATE_VMI failed: %d (errno=%d)",
		    vmi_fd, errno);

	kvm_vm_free(vm);
	close(vmi_fd);

	pr_info("PASS: vmi_destroy_without_release\n");
}

/*
 * Test 3: Destroy VM without release, with a vCPU present.
 *
 * Like test 2 but with a vCPU, so kvm_vmi_destroy() has per-vCPU VMI
 * state to tear down.
 */
static void test_destroy_without_release_with_vcpu(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	int vmi_fd;

	vm = vm_create_with_one_vcpu(&vcpu, guest_code);
	vmi_fd = vmi_create(vm);

	kvm_vm_free(vm);
	close(vmi_fd);

	pr_info("PASS: vmi_destroy_without_release_with_vcpu\n");
}

/*
 * Test 4: Re-create a session after release.
 *
 * Create a session, close it, then create a second session on the same
 * VM and verify it succeeds. Confirms release fully detaches VM-wide and
 * per-vCPU state so a new session can attach.
 */
static void test_recreate_after_release(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	int vmi_fd, fd2;

	vm = vm_create_with_one_vcpu(&vcpu, guest_code);

	vmi_fd = vmi_create(vm);
	close(vmi_fd);

	fd2 = __vm_ioctl(vm, KVM_CREATE_VMI, NULL);
	TEST_ASSERT(fd2 >= 0,
		    "Second KVM_CREATE_VMI after release should succeed, got %d (errno=%d)",
		    fd2, errno);
	close(fd2);

	kvm_vm_free(vm);
	pr_info("PASS: vmi_recreate_after_release\n");
}

int main(int argc, char *argv[])
{
	vmi_force_el1_guests();
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));

	test_create_release();
	test_destroy_without_release();
	test_destroy_without_release_with_vcpu();
	test_recreate_after_release();

	return 0;
}
