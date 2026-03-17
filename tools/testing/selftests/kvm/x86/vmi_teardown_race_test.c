// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI teardown race test
 *
 * Tests that closing vmi_fd while vCPUs are actively running on an
 * alternate view does not cause a kernel crash.  This exercises the
 * race between kvm_vmi_release() (destroying views, freeing tdp_root)
 * and vCPU page fault handlers (reading current_view->arch.tdp_root).
 *
 * The bug: vmx_vmi_destroy_view() freed tdp_root under mmu_lock(write)
 * but set view->arch.tdp_root = NULL after releasing the lock.  A vCPU
 * in a page fault could read a stale current_view pointer and get a
 * NULL or dangling tdp_root, causing a NULL pointer dereference in
 * kvm_tdp_mmu_map().
 *
 * Test plan:
 * 1. Create VM with multiple vCPUs
 * 2. Create VMI session, ring, alternate view with GFN remap
 * 3. Switch all vCPUs to the alt view
 * 4. Run guest code that touches many pages (generating page faults
 *    as the empty alt EPT gets populated)
 * 5. Close vmi_fd while vCPUs are actively faulting
 * 6. Test passes if no kernel crash occurs
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
#define NR_ITERATIONS	5
#define NR_TOUCH_PAGES	512
#define TOUCH_GPA	0x800000ULL
#define TOUCH_SLOT	10

/*
 * Guest touches many pages to generate continuous EPT violations
 * in the empty alternate view.  Each 4K page access causes an EPT
 * miss that must walk the view's EPT root.
 *
 * These pages must be explicitly mapped (both memslot and page table)
 * to generate EPT violations rather than guest #PFs.
 */
static void guest_touch_pages(void)
{
	volatile uint8_t *ptr;
	uint8_t sink;
	int i;

	GUEST_SYNC(1); /* Ready */

	for (i = 0; i < NR_TOUCH_PAGES; i++) {
		ptr = (volatile uint8_t *)(TOUCH_GPA + (i * 4096));
		sink = *ptr;
		(void)sink;
	}

	GUEST_DONE();
}

struct vcpu_thread_arg {
	struct kvm_vcpu *vcpu;
	volatile int done;
};

static void *vcpu_thread_fn(void *arg)
{
	struct vcpu_thread_arg *ta = arg;
	struct kvm_vcpu *vcpu = ta->vcpu;
	struct ucall uc;
	int ret;

	for (;;) {
		ret = _vcpu_run(vcpu);
		if (ret == -1)
			break;

		/*
		 * During teardown, the vCPU may get kicked and exit
		 * with various reasons.  Only process IO exits (ucalls).
		 */
		if (vcpu->run->exit_reason != KVM_EXIT_IO)
			break;
		if (get_ucall(vcpu, &uc) == UCALL_DONE)
			break;
		if (uc.cmd == UCALL_ABORT)
			break;
		/* UCALL_SYNC - continue */
	}

	ta->done = 1;
	return NULL;
}

/*
 * Test: Close vmi_fd while vCPUs are actively faulting on alt view.
 *
 * This is the stress scenario that triggers the NULL root crash
 * if the teardown synchronization is broken.
 */
static void test_teardown_while_faulting(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpus[NR_VCPUS];
	struct vmi_test_ring rings[NR_VCPUS];
	struct vcpu_thread_arg targs[NR_VCPUS];
	pthread_t threads[NR_VCPUS];
	int vmi_fd;
	uint32_t view_id;
	int i;

	vm = vm_create_with_one_vcpu(&vcpus[0], guest_touch_pages);
	for (i = 1; i < NR_VCPUS; i++)
		vcpus[i] = vm_vcpu_add(vm, i, guest_touch_pages);

	/* Add memory and page table entries for the pages the guest touches */
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    TOUCH_GPA, TOUCH_SLOT, NR_TOUCH_PAGES, 0);
	for (i = 0; i < NR_TOUCH_PAGES; i++)
		virt_map(vm, TOUCH_GPA + i * 4096, TOUCH_GPA + i * 4096, 1);

	vmi_fd = vmi_create(vm);

	/* Setup rings for all vCPUs */
	for (i = 0; i < NR_VCPUS; i++)
		vmi_setup_ring(vmi_fd, i, &rings[i]);

	/* Create alt view */
	view_id = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);

	/* Switch all vCPUs to alt view (switches entire VM) */
	vmi_switch_view(vmi_fd, view_id);

	/* Start all vCPU threads */
	for (i = 0; i < NR_VCPUS; i++) {
		targs[i].vcpu = vcpus[i];
		targs[i].done = 0;
		pthread_create(&threads[i], NULL, vcpu_thread_fn, &targs[i]);
	}

	/*
	 * Let the vCPUs run briefly to start generating page faults
	 * in the empty alt EPT.  This is the critical window where
	 * the teardown race can trigger.
	 */
	usleep(10000); /* 10ms */

	/*
	 * Close vmi_fd while vCPUs are actively faulting.
	 * kvm_vmi_release() must:
	 * - NULL current_view on all vCPUs
	 * - Wait for in-flight page faults (mmu_lock barrier)
	 * - Then destroy views safely
	 *
	 * If the synchronization is broken, this causes a NULL
	 * pointer dereference in kvm_tdp_mmu_map().
	 */
	for (i = 0; i < NR_VCPUS; i++)
		vmi_teardown_ring(&rings[i]);
	close(vmi_fd);

	/* All vCPU threads should exit cleanly */
	for (i = 0; i < NR_VCPUS; i++)
		pthread_join(threads[i], NULL);

	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	int i;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_RING));

	/*
	 * Run multiple iterations to increase the chance of hitting
	 * the teardown race window.  The bug is timing-dependent.
	 */
	for (i = 0; i < NR_ITERATIONS; i++) {
		test_teardown_while_faulting();
	}

	pr_info("PASS: %d iterations of teardown race tests completed\n",
		NR_ITERATIONS);

	return 0;
}
