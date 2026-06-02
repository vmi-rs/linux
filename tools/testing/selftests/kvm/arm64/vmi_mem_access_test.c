// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI per-GFN memory access test (arm64, K7)
 *
 * Verifies that an alternate stage-2 view enforces per-GFN R/W/X and that a
 * violating guest access raises a KVM_VMI_EVENT_MEM_ACCESS ring event with the
 * attempted access bit set at the right GFN. Then exercises both agent
 * responses:
 *   - CONTINUE (after widening perms via KVM_VMI_SET_MEM_ACCESS): the access
 *     completes and no further event fires.
 *   - DENY: the kernel injects a data abort the guest takes and records.
 *
 * GFN math is host-page based (gfn = gpa / getpagesize()), matching the KVM
 * stage-2 GFN convention used by the vmi_fd mmap path; never a hardcoded 4K
 * shift. Test GPAs are 64K-aligned so they are valid for any guest granule and
 * fit the 36-bit IPA seen in a nested L1.
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

#define TEST_GPA	0x10000000ULL	/* 256MB - RO page, CONTINUE case */
#define TEST_GPA2	0x10100000ULL	/* RO page, DENY case */
#define TEST_MEMSLOT	10
#define TEST_MEMSLOT2	11

#define WRITE_VAL	0xdeadbeefcafeULL

/* Guest captures an abort taken on the DENY case so the host can verify it. */
static volatile uint64_t g_esr;
static volatile uint64_t g_far;
static volatile int g_handled;

static void sync_handler(struct ex_regs *regs)
{
	g_esr = read_sysreg(esr_el1);
	g_far = read_sysreg(far_el1);
	g_handled = 1;
	/* Skip the faulting store so the guest makes forward progress. */
	regs->pc += 4;
}

static void guest_main(void)
{
	volatile uint64_t *ptr = (volatile uint64_t *)TEST_GPA;
	volatile uint64_t *ptr2 = (volatile uint64_t *)TEST_GPA2;

	/*
	 * Phase 1: write to a RO view page. Agent observes the W violation,
	 * grants RWX and CONTINUEs; the write then completes.
	 */
	*ptr = WRITE_VAL;
	GUEST_ASSERT_EQ(*ptr, WRITE_VAL);
	GUEST_SYNC(1);

	/*
	 * Phase 2: write to a second RO view page. Agent DENYs -> data abort
	 * injected into the guest. The handler records ESR/FAR and skips the
	 * store. The page must therefore be unchanged.
	 */
	g_handled = 0;
	*ptr2 = WRITE_VAL;
	GUEST_ASSERT(g_handled);
	GUEST_ASSERT_EQ(ESR_ELx_EC(g_esr), ESR_ELx_EC_DABT_CUR);
	GUEST_ASSERT(g_esr & ESR_ELx_WNR);
	GUEST_ASSERT_EQ(*ptr2, 0);

	GUEST_DONE();
}

int main(int argc, char *argv[])
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	size_t psz = getpagesize();
	uint64_t gfn = TEST_GPA / psz;
	uint64_t gfn2 = TEST_GPA2 / psz;
	uint32_t view_id;
	int vmi_fd;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_RING));

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_main, &ring);

	/* Exception handlers for the DENY-injected data abort. */
	vm_init_descriptor_tables(vm);
	vcpu_init_descriptor_tables(vcpu);
	vm_install_sync_handler(vm, VECTOR_SYNC_CURRENT,
				ESR_ELx_EC_DABT_CUR, sync_handler);

	/* Two RWX data pages, then made read-only in the view per-GFN. */
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, TEST_GPA,
				    TEST_MEMSLOT,
				    vm_calc_num_guest_pages(vm->mode, psz), 0);
	virt_map(vm, TEST_GPA, TEST_GPA, vm_calc_num_guest_pages(vm->mode, psz));
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, TEST_GPA2,
				    TEST_MEMSLOT2,
				    vm_calc_num_guest_pages(vm->mode, psz), 0);
	virt_map(vm, TEST_GPA2, TEST_GPA2,
		 vm_calc_num_guest_pages(vm->mode, psz));

	view_id = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);
	vmi_set_mem_access(vmi_fd, view_id, gfn, KVM_VMI_ACCESS_R);
	vmi_set_mem_access(vmi_fd, view_id, gfn2, KVM_VMI_ACCESS_R);

	/* mem_access is implicitly enabled; just need a ring + view switch. */
	vmi_switch_view(vmi_fd, view_id);

	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* Phase 1: expect a W violation at gfn, grant RWX, CONTINUE. */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for first mem_access event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_MEM_ACCESS,
		    "Expected MEM_ACCESS, got %u", ev->type);
	TEST_ASSERT(ev->mem_access.access & KVM_VMI_ACCESS_W,
		    "Expected W violation flag, got access 0x%x",
		    ev->mem_access.access);
	TEST_ASSERT(ev->mem_access.gpa / psz == gfn,
		    "Expected GFN 0x%lx, got GPA 0x%llx",
		    (unsigned long)gfn, ev->mem_access.gpa);

	vmi_set_mem_access(vmi_fd, view_id, gfn, KVM_VMI_ACCESS_RWX);
	ev->response = KVM_VMI_RESPONSE_CONTINUE;
	vmi_ack_event(&ring, 0);

	/*
	 * Phase 2: the guest's write to gfn2 traps; DENY it. The guest takes
	 * an injected data abort. No further MEM_ACCESS for gfn should fire
	 * (it was widened to RWX); the next event is the gfn2 violation.
	 */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for second mem_access event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_MEM_ACCESS,
		    "Expected MEM_ACCESS, got %u", ev->type);
	TEST_ASSERT(ev->mem_access.access & KVM_VMI_ACCESS_W,
		    "Expected W violation flag, got access 0x%x",
		    ev->mem_access.access);
	TEST_ASSERT(ev->mem_access.gpa / psz == gfn2,
		    "Expected GFN 0x%lx, got GPA 0x%llx",
		    (unsigned long)gfn2, ev->mem_access.gpa);

	ev->response = KVM_VMI_RESPONSE_DENY;
	vmi_ack_event(&ring, 0);

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");

	vmi_switch_view(vmi_fd, 0);
	vmi_destroy_view(vmi_fd, view_id);
	vmi_test_teardown(vm, vmi_fd, &ring);
	pr_info("PASS: vmi_mem_access\n");

	return 0;
}
