// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI multi-vCPU view stress test (arm64)
 *
 * Two vCPUs run concurrently while the controlling thread switches the
 * VM-wide view between execution rounds. Verifies concurrent runs on
 * alternate views and that view switching between rounds is safe.
 */
#include <linux/kvm.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

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
		asm volatile("nop; nop; nop; nop");
	}
	GUEST_DONE();
}

struct vcpu_thread_data {
	struct kvm_vcpu *vcpu;
	pthread_barrier_t *barrier;
	int errors;
	int syncs;
};

static void *vcpu_thread(void *arg)
{
	struct vcpu_thread_data *data = arg;
	struct kvm_vcpu *vcpu = data->vcpu;
	struct ucall uc;

	data->errors = 0;
	data->syncs = 0;

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
			data->errors++;
			goto done;
		}

		pthread_barrier_wait(data->barrier);
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

	for (i = 0; i < NR_VIEWS; i++)
		view_ids[i] = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);

	pthread_barrier_init(&barrier, NULL, NR_VCPUS + 1);

	for (i = 0; i < NR_VCPUS; i++) {
		thread_data[i].vcpu = vcpus[i];
		thread_data[i].barrier = &barrier;
		pthread_create(&threads[i], NULL, vcpu_thread, &thread_data[i]);
	}

	pthread_barrier_wait(&barrier);

	for (iter = 0; iter < NR_ITERS; iter++) {
		vmi_switch_view(vmi_fd, view_ids[iter % NR_VIEWS]);
		pthread_barrier_wait(&barrier);

		vmi_switch_view(vmi_fd, 0);
		pthread_barrier_wait(&barrier);

		pthread_barrier_wait(&barrier);
		pthread_barrier_wait(&barrier);
	}

	for (i = 0; i < NR_VCPUS; i++) {
		pthread_join(threads[i], NULL);
		pr_info("vCPU %d completed %d syncs, errors=%d\n", i,
			thread_data[i].syncs, thread_data[i].errors);
	}

	for (i = 0; i < NR_VCPUS; i++)
		TEST_ASSERT(thread_data[i].errors == 0,
			    "vCPU %d encountered errors", i);

	for (i = 0; i < NR_VIEWS; i++)
		vmi_destroy_view(vmi_fd, view_ids[i]);

	pthread_barrier_destroy(&barrier);
	close(vmi_fd);
	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	vmi_force_el1_guests();
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	test_multi_vcpu_views();
	pr_info("PASS: vmi_view_stress\n");
	return 0;
}
