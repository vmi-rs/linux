// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI multi-vCPU view stress test
 *
 * Verifies that multiple vCPUs can run concurrently on alternate views
 * and that VM-wide view switching between execution rounds is safe.
 *
 * Flow:
 *   1. Create VM with 2 vCPUs, each running a loop of GUEST_SYNCs
 *   2. Create 2 alternate views with RWX default access
 *   3. For each iteration:
 *      a. Switch all vCPUs to an alternate view (VM-wide ioctl)
 *      b. Run all vCPUs concurrently until each does a GUEST_SYNC
 *      c. Switch all vCPUs back to view 0
 *      d. Run all vCPUs concurrently until each does a GUEST_SYNC
 *   4. Verify all vCPUs completed without errors
 */
#include <linux/kvm.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

#define NR_VCPUS	2
#define NR_VIEWS	2
#define NR_ITERS	10

static void guest_workload(void)
{
	int i;

	for (i = 0; i < NR_ITERS * 2; i++) {
		GUEST_SYNC(i + 1);
		__asm__ __volatile__("nop; nop; nop; nop");
	}
	GUEST_DONE();
}

struct vcpu_thread_data {
	struct kvm_vcpu *vcpu;
	pthread_barrier_t *barrier;
	int errors;
	int syncs;
};

/*
 * vCPU thread: run until GUEST_SYNC, signal barrier, repeat.
 * The main thread switches views between barriers.
 */
static void *vcpu_thread(void *arg)
{
	struct vcpu_thread_data *data = arg;
	struct kvm_vcpu *vcpu = data->vcpu;
	struct ucall uc;

	data->errors = 0;
	data->syncs = 0;

	/* First barrier: signal ready */
	pthread_barrier_wait(data->barrier);

	for (;;) {
		vcpu_run(vcpu);
		switch (get_ucall(vcpu, &uc)) {
		case UCALL_DONE:
			goto done;
		case UCALL_SYNC:
			data->syncs++;
			break;
		case UCALL_ABORT:
			REPORT_GUEST_ASSERT(uc);
			goto done;
		default:
			pr_info("vcpu %u: unexpected ucall %lu\n",
				vcpu->id,
				(unsigned long)get_ucall(vcpu, &uc));
			data->errors++;
			goto done;
		}

		/* Signal that this vCPU completed a SYNC */
		pthread_barrier_wait(data->barrier);
		/* Wait for main thread to finish view switch */
		pthread_barrier_wait(data->barrier);
	}
done:
	return NULL;
}

static void test_multi_vcpu_views(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpus[NR_VCPUS];
	uint32_t view_ids[NR_VIEWS];
	struct vcpu_thread_data thread_data[NR_VCPUS] = {};
	pthread_t threads[NR_VCPUS];
	pthread_barrier_t barrier;
	int vmi_fd, i, iter;

	vm = vm_create_with_vcpus(NR_VCPUS, guest_workload, vcpus);
	vmi_fd = vmi_create(vm);

	/* Create alternate views */
	for (i = 0; i < NR_VIEWS; i++)
		view_ids[i] = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);

	/* barrier for NR_VCPUS threads + main thread */
	pthread_barrier_init(&barrier, NULL, NR_VCPUS + 1);

	/* Launch vCPU threads */
	for (i = 0; i < NR_VCPUS; i++) {
		thread_data[i].vcpu = vcpus[i];
		thread_data[i].barrier = &barrier;
		pthread_create(&threads[i], NULL, vcpu_thread, &thread_data[i]);
	}

	/* Wait for all threads to be ready */
	pthread_barrier_wait(&barrier);

	for (iter = 0; iter < NR_ITERS; iter++) {
		/* Switch all vCPUs to an alternate view */
		vmi_switch_view(vmi_fd, view_ids[iter % NR_VIEWS]);

		/* Let vCPU threads run until SYNC */
		pthread_barrier_wait(&barrier);
		/* vCPU threads are now waiting at second barrier */

		/* Switch back to view 0 */
		vmi_switch_view(vmi_fd, 0);

		/* Let vCPU threads resume */
		pthread_barrier_wait(&barrier);

		/* Wait for next SYNC from all vCPUs */
		pthread_barrier_wait(&barrier);
		/* All vCPUs completed another SYNC */

		/* Let vCPU threads resume for the next iteration */
		pthread_barrier_wait(&barrier);
	}

	/* Wait for all threads */
	for (i = 0; i < NR_VCPUS; i++) {
		pthread_join(threads[i], NULL);
		pr_info("vCPU %d completed %d syncs, errors=%d\n", i,
			thread_data[i].syncs, thread_data[i].errors);
	}

	for (i = 0; i < NR_VCPUS; i++) {
		TEST_ASSERT(thread_data[i].errors == 0,
			    "vCPU %d encountered errors", i);
	}

	/* Cleanup */
	for (i = 0; i < NR_VIEWS; i++)
		vmi_destroy_view(vmi_fd, view_ids[i]);

	pthread_barrier_destroy(&barrier);
	close(vmi_fd);
	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	test_multi_vcpu_views();
	return 0;
}
