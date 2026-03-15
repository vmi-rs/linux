// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI multi-event monitoring test
 *
 * Enables CR3 + CPUID + breakpoint monitoring simultaneously.
 * Guest writes CR3, executes CPUID, and hits INT3 in a loop.
 * Host verifies correct event types are delivered via ring.
 * Then repeats with 2 vCPUs doing the same thing concurrently.
 */
#include <linux/kvm.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

#define NUM_ITERATIONS	5
#define NUM_VCPUS	2
#define EVENTS_PER_ITERATION	3  /* CR3 + CPUID + INT3 */

static void guest_code_multi(void)
{
	uint64_t cr3;
	uint32_t eax, ebx, ecx, edx;
	int i;

	GUEST_SYNC(1); /* Ready */

	for (i = 0; i < NUM_ITERATIONS; i++) {
		/* 1. Write CR3 (reload current value) */
		cr3 = get_cr3();
		__asm__ __volatile__("mov %0, %%cr3" : : "r"(cr3));

		/* 2. Execute CPUID */
		eax = 0;
		ecx = 0;
		__asm__ __volatile__("cpuid"
				     : "+a"(eax), "=b"(ebx),
				       "+c"(ecx), "=d"(edx));

		/* 3. Execute INT3 */
		__asm__ __volatile__("int3");
	}

	GUEST_DONE();
}

struct vcpu_event_stats {
	int cr_events;
	int cpuid_events;
	int bp_events;
	int total_events;
	int errors;
};

/*
 * Ring event handler thread: reads ring events, counts by type,
 * responds ALLOW. Runs until the done flag is set.
 */
struct ring_handler_args {
	struct vmi_test_ring *ring;
	struct vcpu_event_stats stats;
	volatile int *done;
	uint32_t vcpu_id;
};

static void *ring_handler_fn(void *arg)
{
	struct ring_handler_args *rh = arg;
	struct kvm_vmi_ring_event *ev;

	memset(&rh->stats, 0, sizeof(rh->stats));

	while (!*rh->done) {
		ev = vmi_wait_event_timeout(rh->ring, 1000);
		if (ev == NULL)
			continue;

		rh->stats.total_events++;
		ev->response = KVM_VMI_RESPONSE_CONTINUE;

		switch (ev->type) {
		case KVM_VMI_EVENT_CR:
			ev->response = KVM_VMI_RESPONSE_CONTINUE;
			rh->stats.cr_events++;
			if (ev->arch.cr.index != KVM_VMI_CR3) {
				pr_info("WARNING: CR event for "
					"index %u, expected 3\n",
					ev->arch.cr.index);
				rh->stats.errors++;
			}
			break;
		case KVM_VMI_EVENT_CPUID:
			rh->stats.cpuid_events++;
			ev->response = KVM_VMI_RESPONSE_EMULATE;
			break;
		case KVM_VMI_EVENT_BREAKPOINT:
			rh->stats.bp_events++;
			/* Kernel never auto-skips INT3; advance RIP manually */
			ev->regs.rip += ev->insn_len;
			ev->response = KVM_VMI_RESPONSE_SET_REGS;
			break;
		default:
			pr_info("WARNING: unexpected event type %u\n",
				ev->type);
			rh->stats.errors++;
			break;
		}

		vmi_ack_event(rh->ring, rh->vcpu_id);
	}

	return NULL;
}

static void verify_stats(const char *label,
			 struct vcpu_event_stats *stats)
{
	pr_info("  %s: CR=%d CPUID=%d BP=%d total=%d errors=%d\n",
		label,
		stats->cr_events, stats->cpuid_events,
		stats->bp_events, stats->total_events,
		stats->errors);

	TEST_ASSERT(stats->cr_events == NUM_ITERATIONS,
		    "%s: expected %d CR events, got %d",
		    label, NUM_ITERATIONS, stats->cr_events);

	TEST_ASSERT(stats->cpuid_events == NUM_ITERATIONS,
		    "%s: expected %d CPUID events, got %d",
		    label, NUM_ITERATIONS, stats->cpuid_events);

	TEST_ASSERT(stats->bp_events == NUM_ITERATIONS,
		    "%s: expected %d BP events, got %d",
		    label, NUM_ITERATIONS, stats->bp_events);

	TEST_ASSERT(stats->total_events ==
		    NUM_ITERATIONS * EVENTS_PER_ITERATION,
		    "%s: expected %d total events, got %d",
		    label, NUM_ITERATIONS * EVENTS_PER_ITERATION,
		    stats->total_events);

	TEST_ASSERT(stats->errors == 0,
		    "%s: had %d errors", label, stats->errors);
}

/* Test 1: Single vCPU with multiple event types */
static void test_single_vcpu(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	struct ring_handler_args rh;
	pthread_t vcpu_thread, ring_thread;
	int vmi_fd;

	pr_info("--- Test 1: Single vCPU, multi-event ---\n");

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_code_multi, &ring);

	/* Enable CR3 + CPUID + BP monitoring */
	vmi_control_cr(vmi_fd, KVM_VMI_CR3, 0, ~0ULL, 1);
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_CPUID, 1);
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_BREAKPOINT, 1);

	/* Start ring handler thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	rh.ring = &ring;
	rh.done = &targ.done;
	rh.vcpu_id = 0;
	pthread_create(&ring_thread, NULL, ring_handler_fn, &rh);

	/* Start vCPU thread */
	pthread_create(&vcpu_thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* Wait for guest completion */
	pthread_join(vcpu_thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");

	/* Let ring handler drain any remaining events */
	pthread_join(ring_thread, NULL);

	verify_stats("vCPU 0", &rh.stats);

	vmi_test_teardown(vm, vmi_fd, &ring);
	pr_info("--- Test 1: PASS ---\n\n");
}

/* Test 2: Two vCPUs with multiple event types running concurrently */
static void test_multi_vcpu(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpus[NUM_VCPUS];
	struct vmi_test_ring rings[NUM_VCPUS];
	struct vmi_vcpu_thread_arg targs[NUM_VCPUS];
	struct ring_handler_args rhs[NUM_VCPUS];
	pthread_t vcpu_threads[NUM_VCPUS];
	pthread_t ring_threads[NUM_VCPUS];
	char label[32];
	int vmi_fd, i;

	pr_info("--- Test 2: %d vCPUs, multi-event, concurrent ---\n",
		NUM_VCPUS);

	vm = vm_create_with_vcpus(NUM_VCPUS, guest_code_multi, vcpus);
	vmi_fd = vmi_create(vm);

	/* Enable events VM-wide (monitoring config is shared) */
	vmi_control_cr(vmi_fd, KVM_VMI_CR3, 0, ~0ULL, 1);
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_CPUID, 1);
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_BREAKPOINT, 1);

	for (i = 0; i < NUM_VCPUS; i++) {
		/* Setup per-vCPU ring */
		vmi_setup_ring(vmi_fd, i, &rings[i]);

		targs[i].vcpu = vcpus[i];
		targs[i].done = 0;
		rhs[i].ring = &rings[i];
		rhs[i].done = &targs[i].done;
		rhs[i].vcpu_id = i;
	}

	/* Launch ring handler threads */
	for (i = 0; i < NUM_VCPUS; i++)
		pthread_create(&ring_threads[i], NULL, ring_handler_fn, &rhs[i]);

	/* Launch vCPU threads */
	for (i = 0; i < NUM_VCPUS; i++)
		pthread_create(&vcpu_threads[i], NULL, vmi_vcpu_thread_fn, &targs[i]);

	/* Wait for all to complete */
	for (i = 0; i < NUM_VCPUS; i++) {
		pthread_join(vcpu_threads[i], NULL);
		TEST_ASSERT(targs[i].done, "vCPU %d should have completed", i);
	}

	for (i = 0; i < NUM_VCPUS; i++)
		pthread_join(ring_threads[i], NULL);

	/* Verify per-vCPU stats */
	for (i = 0; i < NUM_VCPUS; i++) {
		snprintf(label, sizeof(label), "vCPU %d", i);
		verify_stats(label, &rhs[i].stats);
	}

	/* Cleanup */
	for (i = 0; i < NUM_VCPUS; i++)
		vmi_teardown_ring(&rings[i]);

	close(vmi_fd);
	kvm_vm_free(vm);
	pr_info("--- Test 2: PASS ---\n\n");
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));

	test_single_vcpu();
	test_multi_vcpu();

	pr_info("PASS: Multi-event monitoring test\n");
	return 0;
}
