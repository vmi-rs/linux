// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI teardown race test (arm64)
 *
 * Closing vmi_fd while vCPUs are actively faulting on an empty alternate
 * view must not crash the kernel. Exercises the race between
 * kvm_vmi_release() (resetting vCPUs to view 0, freeing each view's
 * kvm_s2_mmu under mmu_lock) and vCPU stage-2 fault handlers populating
 * the view. Pass = the run completes with no crash/hang.
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

#define NR_VCPUS	4
#define NR_TOUCH_PAGES	512
#define NR_ROUNDS	200
#define TOUCH_GPA	0x40000000ULL	/* 1 GiB - well clear of low mappings */
#define TOUCH_SLOT	10

static void guest_touch_pages(void)
{
	volatile uint8_t *ptr;
	uint8_t sink;
	int round, i;

	for (round = 0; round < NR_ROUNDS; round++) {
		for (i = 0; i < NR_TOUCH_PAGES; i++) {
			ptr = (volatile uint8_t *)(TOUCH_GPA +
						   (uint64_t)i * 4096);
			sink = *ptr;
			(void)sink;
		}
		GUEST_SYNC(0);
	}
	GUEST_DONE();
}

struct vcpu_thread_arg {
	struct kvm_vcpu *vcpu;
};

static void *vcpu_thread_fn(void *arg)
{
	struct vcpu_thread_arg *ta = arg;
	struct kvm_vcpu *vcpu = ta->vcpu;
	struct ucall uc;
	int ret;

	for (;;) {
		ret = _vcpu_run(vcpu);
		if (ret)
			break;	/* kicked / fd torn down: stop, no assert */
		if (vcpu->run->exit_reason != KVM_EXIT_IO)
			break;
		switch (get_ucall(vcpu, &uc)) {
		case UCALL_SYNC:
			continue;
		case UCALL_DONE:
			goto done;
		case UCALL_ABORT:
			REPORT_GUEST_ASSERT(uc);
			goto done;
		default:
			goto done;
		}
	}
done:
	return NULL;
}

static void test_teardown_while_faulting(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpus[NR_VCPUS];
	struct vcpu_thread_arg targs[NR_VCPUS] = {};
	pthread_t threads[NR_VCPUS];
	uint32_t view_id;
	int vmi_fd, i;

	vm = vm_create_with_vcpus(NR_VCPUS, guest_touch_pages, vcpus);

	/* Back the touched range with a memslot and map it into the guest. */
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, TOUCH_GPA,
				    TOUCH_SLOT, NR_TOUCH_PAGES, 0);
	virt_map(vm, TOUCH_GPA, TOUCH_GPA, NR_TOUCH_PAGES);

	vmi_fd = vmi_create(vm);
	view_id = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);

	/* Put every vCPU on the empty alternate view. */
	vmi_switch_view(vmi_fd, view_id);

	for (i = 0; i < NR_VCPUS; i++) {
		targs[i].vcpu = vcpus[i];
		pthread_create(&threads[i], NULL, vcpu_thread_fn, &targs[i]);
	}

	/* Let them fault for a bit, then tear the session down underneath. */
	usleep(20000);
	close(vmi_fd);

	for (i = 0; i < NR_VCPUS; i++)
		pthread_join(threads[i], NULL);

	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	vmi_force_el1_guests();
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	test_teardown_while_faulting();
	pr_info("PASS: vmi_teardown_race (no crash)\n");
	return 0;
}
