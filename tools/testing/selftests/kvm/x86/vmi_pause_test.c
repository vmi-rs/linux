// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI pause/unpause test
 *
 * Tests refcounted VM and vCPU pause via vmi_fd.
 * Pause prevents the vCPU from running; unpause resumes it.
 * Pause is refcounted: N pauses require N unpauses to resume.
 */
#include <errno.h>
#include <linux/kvm.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

static void guest_counter(void)
{
	int i;

	for (i = 0; i < 100; i++)
		GUEST_SYNC(i + 1);
	GUEST_DONE();
}

/*
 * Test 1: Pause and unpause the entire VM.
 * The guest should still complete after being unpaused.
 */
static void test_pause_vm(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	int vmi_fd, ret;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_counter, &ring);

	/* Start vCPU thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* Give the vCPU a moment to start running */
	usleep(10000);

	/* Pause the VM */
	ret = ioctl(vmi_fd, KVM_VMI_PAUSE_VM, 0);
	TEST_ASSERT(ret == 0,
		    "KVM_VMI_PAUSE_VM should succeed, got %d (errno=%d)",
		    ret, errno);

	/* Sleep briefly while paused */
	usleep(100000);

	/* Unpause the VM */
	ret = ioctl(vmi_fd, KVM_VMI_UNPAUSE_VM, 0);
	TEST_ASSERT(ret == 0,
		    "KVM_VMI_UNPAUSE_VM should succeed, got %d (errno=%d)",
		    ret, errno);

	/* Guest should complete */
	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed after unpause");

	vmi_test_teardown(vm, vmi_fd, &ring);
	pr_info("PASS: test_pause_vm\n");
}

/*
 * Test 2: Pause and unpause a specific vCPU.
 */
static void test_pause_vcpu(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_vcpu pv = { .vcpu_id = 0 };
	int vmi_fd, ret;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_counter, &ring);

	/* Start vCPU thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* Give the vCPU a moment to start running */
	usleep(10000);

	/* Pause vCPU 0 */
	ret = ioctl(vmi_fd, KVM_VMI_PAUSE_VCPU, &pv);
	TEST_ASSERT(ret == 0,
		    "KVM_VMI_PAUSE_VCPU should succeed, got %d (errno=%d)",
		    ret, errno);

	/* Sleep briefly while paused */
	usleep(100000);

	/* Unpause vCPU 0 */
	ret = ioctl(vmi_fd, KVM_VMI_UNPAUSE_VCPU, &pv);
	TEST_ASSERT(ret == 0,
		    "KVM_VMI_UNPAUSE_VCPU should succeed, got %d (errno=%d)",
		    ret, errno);

	/* Guest should complete */
	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done,
		    "Guest should have completed after vCPU unpause");

	vmi_test_teardown(vm, vmi_fd, &ring);
	pr_info("PASS: test_pause_vcpu\n");
}

/*
 * Test 3: Verify refcounted pause behavior.
 * Pause twice, unpause once -> still paused.
 * Unpause again -> resumed.
 */
static void test_pause_refcount(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	int vmi_fd, ret;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_counter, &ring);

	/* Pause VM twice */
	ret = ioctl(vmi_fd, KVM_VMI_PAUSE_VM, 0);
	TEST_ASSERT(ret == 0, "First KVM_VMI_PAUSE_VM failed: %d", ret);

	ret = ioctl(vmi_fd, KVM_VMI_PAUSE_VM, 0);
	TEST_ASSERT(ret == 0, "Second KVM_VMI_PAUSE_VM failed: %d", ret);

	/* Start vCPU thread (should be paused and not make progress) */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* Unpause once - VM should still be paused (refcount=1) */
	ret = ioctl(vmi_fd, KVM_VMI_UNPAUSE_VM, 0);
	TEST_ASSERT(ret == 0, "First KVM_VMI_UNPAUSE_VM failed: %d", ret);

	/* Brief sleep to verify it is still paused */
	usleep(50000);

	/* Unpause again - VM should now be fully resumed (refcount=0) */
	ret = ioctl(vmi_fd, KVM_VMI_UNPAUSE_VM, 0);
	TEST_ASSERT(ret == 0, "Second KVM_VMI_UNPAUSE_VM failed: %d", ret);

	/* Guest should complete */
	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done,
		    "Guest should have completed after full unpause");

	vmi_test_teardown(vm, vmi_fd, &ring);
	pr_info("PASS: test_pause_refcount\n");
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_PAUSE));

	test_pause_vm();
	test_pause_vcpu();
	test_pause_refcount();

	return 0;
}
