// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI fast singlestep test (arm64, K13)
 *
 * Fast singlestep composes view-switch + single-step in the kernel: answering
 * an event with KVM_VMI_RESPONSE_SINGLESTEP_FAST (optionally OR-ed with
 * SWITCH_VIEW) switches the vCPU to a target view, steps exactly one
 * instruction, then auto-switches back to the view the vCPU was on - with NO
 * singlestep event delivered.
 *
 * mem_access scenario: an alternate view marks a data page execute-only
 * (KVM_VMI_ACCESS_X), so a guest READ permission-faults -> MEM_ACCESS. The
 * agent responds SINGLESTEP_FAST [+ SWITCH_VIEW(permissive view)]: the read is
 * stepped where the page is readable, then the vCPU returns to the protected
 * view. A second read re-traps - proving the view was restored.
 *
 * GFN math is host-page based (gfn = gpa / getpagesize()); never a 4K shift.
 */
#include <errno.h>
#include <linux/kvm.h>
#include <linux/kvm_vmi.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

#define DATA_GPA	0x10000000ULL	/* 256 MB, 16K-aligned */
#define RESULT_GPA	0x10004000ULL	/* DATA_GPA + one 16K host page */
#define DATA_MEMSLOT	10
#define RESULT_MEMSLOT	11
#define DATA_PATTERN	0xDEADBEEFCAFEBABEULL

static void guest_code(void)
{
	volatile uint64_t *data   = (volatile uint64_t *)DATA_GPA;
	volatile uint64_t *result = (volatile uint64_t *)RESULT_GPA;

	GUEST_SYNC(1);
	*result = *data;	/* read #1: LDR faults -> MEM_ACCESS -> fast step */
	GUEST_SYNC(2);
	*result = *data;	/* read #2: page still protected (back on view 1) */
	GUEST_SYNC(3);
	GUEST_DONE();
}

/*
 * @use_switch_view false: respond SINGLESTEP_FAST only -> kernel steps in view 0
 *                         (the default target) then auto-returns to view 1.
 * @use_switch_view true:  respond SWITCH_VIEW(view 2) | SINGLESTEP_FAST -> steps
 *                         in view 2 (permissive) then auto-returns to view 1.
 * Either way the second read must re-trap (mem_access_count == 2).
 */
static void run_fast_singlestep(bool use_switch_view)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	size_t psz = getpagesize();
	uint64_t data_gfn = DATA_GPA / psz;
	uint64_t *data_hva, *result_hva;
	uint32_t view1, view2 = 0;
	int vmi_fd, mem_access_count = 0;

	vm = vm_create_with_one_vcpu(&vcpu, guest_code);
	vmi_fd = vmi_create(vm);
	vmi_setup_ring(vmi_fd, 0, &ring);

	/* Data page (read-protected in view 1) and result page (always writable). */
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, DATA_GPA, DATA_MEMSLOT,
				    vm_calc_num_guest_pages(vm->mode, psz), 0);
	virt_map(vm, DATA_GPA, DATA_GPA, vm_calc_num_guest_pages(vm->mode, psz));
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, RESULT_GPA,
				    RESULT_MEMSLOT,
				    vm_calc_num_guest_pages(vm->mode, psz), 0);
	virt_map(vm, RESULT_GPA, RESULT_GPA, vm_calc_num_guest_pages(vm->mode, psz));

	data_hva = addr_gpa2hva(vm, DATA_GPA);
	result_hva = addr_gpa2hva(vm, RESULT_GPA);
	*data_hva = DATA_PATTERN;
	*result_hva = 0;

	view1 = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);
	if (use_switch_view)
		view2 = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);

	/* Execute-only in view 1 (S2AP=00): a data READ permission-faults. */
	vmi_set_mem_access(vmi_fd, view1, data_gfn, KVM_VMI_ACCESS_X);

	vmi_control_event(vmi_fd, KVM_VMI_EVENT_MEM_ACCESS, 1);
	vmi_switch_view(vmi_fd, view1);

	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	while (!targ.done) {
		ev = vmi_wait_event_timeout(&ring, 5000);
		if (ev == NULL)
			break;

		TEST_ASSERT(ev->type == KVM_VMI_EVENT_MEM_ACCESS,
			    "Unexpected event type %u (no SINGLESTEP must leak)",
			    ev->type);
		mem_access_count++;
		TEST_ASSERT(ev->mem_access.gpa / psz == data_gfn,
			    "Expected GFN 0x%lx, got GPA 0x%llx",
			    (unsigned long)data_gfn,
			    (unsigned long long)ev->mem_access.gpa);

		if (use_switch_view) {
			ev->response = KVM_VMI_RESPONSE_SWITCH_VIEW |
				       KVM_VMI_RESPONSE_SINGLESTEP_FAST;
			ev->view_id = view2;
		} else {
			ev->response = KVM_VMI_RESPONSE_SINGLESTEP_FAST;
		}
		vmi_ack_event(&ring, 0);
	}

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");

	/* The SECOND mem_access proves the vCPU auto-returned to view 1. */
	TEST_ASSERT(mem_access_count == 2,
		    "Expected 2 mem_access events, got %d", mem_access_count);
	TEST_ASSERT(*result_hva == DATA_PATTERN,
		    "Guest read 0x%lx, expected 0x%lx",
		    (unsigned long)*result_hva, (unsigned long)DATA_PATTERN);

	pr_info("PASS: fast singlestep (%s): 2 mem_access events, data=0x%lx\n",
		use_switch_view ? "switch-view" : "default view 0",
		(unsigned long)*result_hva);

	vmi_switch_view(vmi_fd, 0);
	if (use_switch_view)
		vmi_destroy_view(vmi_fd, view2);
	vmi_destroy_view(vmi_fd, view1);
	vmi_teardown_ring(&ring);
	close(vmi_fd);
	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_RING));

	run_fast_singlestep(false);	/* SINGLESTEP_FAST only -> target view 0 */
	run_fast_singlestep(true);	/* SWITCH_VIEW(view2) + SINGLESTEP_FAST */

	return 0;
}
