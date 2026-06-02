// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI pause + register-read test (arm64)
 *
 * Tests that after pausing a multi-vCPU VM via VMI, the agent can read
 * each vCPU's registers without deadlocking.  KVM_VMI_PAUSE_VM is
 * synchronous (KVM_REQ_OUTSIDE_GUEST_MODE), so all vCPUs are out of guest
 * mode on return and the reads cannot block.
 *
 * arm64 has no KVM_GET_REGS (it returns -EINVAL); registers are read via
 * the ONE_REG API (KVM_GET_ONE_REG) and the register list is fetched via
 * KVM_GET_REG_LIST.  The reads completing (no hang) is the assertion.
 */
#include <errno.h>
#include <linux/kvm.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
 * Test: pause VM, read each vCPU's registers via ONE_REG + REG_LIST,
 * unpause.  This must not deadlock.
 */
static void test_pause_get_regs(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpus[NR_VCPUS];
	struct vmi_test_ring rings[NR_VCPUS];
	struct vcpu_thread_arg targs[NR_VCPUS];
	pthread_t threads[NR_VCPUS];
	struct kvm_reg_list *reg_list;
	uint64_t pc, x0;
	int vmi_fd, i;

	/*
	 * Use vm_create_with_vcpus(): on arm64 it adds all vCPUs and then
	 * finalizes them, which initializes the default in-kernel GICv3.
	 * Building the VM with vm_create() + vm_vcpu_add() would skip that
	 * finalize step, leaving the VGIC uninitialized, so the first vCPU
	 * run fails VGIC resource mapping (-EBUSY) and kills the VM.
	 */
	vm = vm_create_with_vcpus(NR_VCPUS, guest_busy_loop, vcpus);

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
	 * guest mode when it returns, so the reads below won't block.
	 */
	vmi_pause_vm(vmi_fd);

	for (i = 0; i < NR_VCPUS; i++) {
		/* KVM_GET_ONE_REG on core regs - returning is the proof. */
		pc = vcpu_get_reg(vcpus[i], ARM64_CORE_REG(regs.pc));
		x0 = vcpu_get_reg(vcpus[i], ARM64_CORE_REG(regs.regs[0]));
		(void)pc;
		(void)x0;

		/* KVM_GET_REG_LIST must return a non-empty list. */
		reg_list = vcpu_get_reg_list(vcpus[i]);
		TEST_ASSERT(reg_list->n > 0,
			    "KVM_GET_REG_LIST on vCPU %d returned empty list", i);
		free(reg_list);
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
	pr_info("PASS: test_pause_get_regs\n");
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_PAUSE));

	test_pause_get_regs();
	return 0;
}
