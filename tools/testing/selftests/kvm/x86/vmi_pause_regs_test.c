// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI pause + KVM_GET_REGS test
 *
 * Tests that after pausing a multi-vCPU VM via VMI, KVM_GET_REGS
 * can be called on each vCPU without deadlocking.  KVM_VMI_PAUSE_VM
 * is synchronous (uses KVM_REQ_OUTSIDE_GUEST_MODE), so no sleep is
 * needed between pause and register access.
 */
#include <errno.h>
#include <linux/kvm.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

#define NR_VCPUS 2

static void guest_busy_loop(void)
{
	for (;;)
		GUEST_SYNC(1);
}

struct vcpu_thread_arg {
	struct kvm_vcpu *vcpu;
	volatile int stop;
};

static void *vcpu_thread(void *arg)
{
	struct vcpu_thread_arg *ta = arg;
	struct ucall uc;
	int ret;

	while (!ta->stop) {
		ret = _vcpu_run(ta->vcpu);
		if (ret) {
			if (errno == EINTR)
				continue;
			break;
		}
		switch (get_ucall(ta->vcpu, &uc)) {
		case UCALL_DONE:
			return NULL;
		case UCALL_ABORT:
			REPORT_GUEST_ASSERT(uc);
			return NULL;
		case UCALL_SYNC:
			break;
		default:
			break;
		}
	}
	return NULL;
}

/*
 * Test: pause VM, call KVM_GET_REGS on each vCPU, unpause.
 * This must not deadlock.
 */
static void test_pause_get_regs(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpus[NR_VCPUS];
	struct vmi_test_ring rings[NR_VCPUS];
	struct vcpu_thread_arg targs[NR_VCPUS];
	pthread_t threads[NR_VCPUS];
	struct kvm_regs regs;
	int vmi_fd, i, ret;

	vm = vm_create(NR_VCPUS);
	for (i = 0; i < NR_VCPUS; i++)
		vcpus[i] = vm_vcpu_add(vm, i, guest_busy_loop);

	vmi_fd = vmi_create(vm);

	for (i = 0; i < NR_VCPUS; i++)
		vmi_setup_ring(vmi_fd, i, &rings[i]);

	/* Start vCPU threads */
	for (i = 0; i < NR_VCPUS; i++) {
		targs[i].vcpu = vcpus[i];
		targs[i].stop = 0;
		pthread_create(&threads[i], NULL, vcpu_thread, &targs[i]);
	}

	/* Let vCPUs enter guest mode */
	usleep(50000);

	/*
	 * Pause the VM.  This is synchronous - all vCPUs have exited
	 * guest mode when it returns, so KVM_GET_REGS won't block.
	 */
	vmi_pause_vm(vmi_fd);

	for (i = 0; i < NR_VCPUS; i++) {
		ret = __vcpu_ioctl(vcpus[i], KVM_GET_REGS, &regs);
		TEST_ASSERT(ret == 0,
			    "KVM_GET_REGS on vCPU %d failed: %d (errno=%d)",
			    i, ret, errno);
	}

	/* Unpause and stop vCPU threads */
	for (i = 0; i < NR_VCPUS; i++)
		targs[i].stop = 1;
	vmi_unpause_vm(vmi_fd);

	for (i = 0; i < NR_VCPUS; i++)
		pthread_join(threads[i], NULL);

	for (i = 0; i < NR_VCPUS; i++)
		vmi_teardown_ring(&rings[i]);

	close(vmi_fd);
	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_PAUSE));

	test_pause_get_regs();
	return 0;
}
