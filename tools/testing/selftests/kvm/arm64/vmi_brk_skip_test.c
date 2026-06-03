// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI breakpoint PC-integrity test (arm64)
 *
 * Verifies the kernel never auto-advances PC past BRK; the agent owns PC.
 * The agent catches a BRK and redirects PC to func_b via SET_REGS. func_b's
 * FIRST instruction stores MAGIC to RESULT; if the kernel wrongly added 4 to
 * the agent's PC, execution would start at func_b's SECOND instruction (ret)
 * and RESULT would keep its sentinel value. arm64 is fixed-width (4 bytes),
 * so this two-instruction sentinel replaces the x86 REX.W-prefix trick.
 */
#include <linux/kvm.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

/*
 * Host-page-aligned, well-spaced GPAs (>= getpagesize() apart). On a 16K-page
 * host a memslot must be a whole host page, so the x86 4K-spacing would make
 * 16K regions overlap; mirror the other arm64 VMI tests and use 256MB + 1MB
 * steps, sized via vm_calc_num_guest_pages(getpagesize()).
 */
#define FUNC_A_GPA	0x10000000ULL	/* 256MB - BRK + RET trampoline */
#define FUNC_B_GPA	0x10100000ULL	/* +1MB  - str x1,[x0]; ret    */
#define RESULT_GPA	0x10200000ULL	/* +2MB  - result location     */

#define SENTINEL	0xCCCCCCCCCCCCCCCCULL
#define MAGIC		0xDEADBEEF00000042ULL

/* func_a: brk #0; ret  (the BRK site the agent catches) */
static const uint32_t func_a_code[] = {
	0xd4200000,	/* brk #0 */
	0xd65f03c0,	/* ret    */
};

/*
 * func_b:
 *   [0] str x1, [x0]   -> 0xf9000001   (store MAGIC to RESULT)
 *   [1] ret            -> 0xd65f03c0
 * If PC is wrongly advanced by 4, execution starts at ret and RESULT
 * keeps SENTINEL.
 */
static const uint32_t func_b_code[] = {
	0xf9000001,	/* str x1, [x0] */
	0xd65f03c0,	/* ret          */
};

static void guest_redirect(void)
{
	typedef void (*func_t)(void);
	func_t fn = (func_t)FUNC_A_GPA;
	volatile uint64_t *result = (volatile uint64_t *)RESULT_GPA;

	*result = SENTINEL;
	GUEST_SYNC(1);
	fn();	/* BRK in func_a -> agent redirects PC to func_b */
	GUEST_DONE();
}

static void test_brk_set_regs_no_skip(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	uint32_t *func_a_hva, *func_b_hva;
	uint64_t *result_hva;
	size_t psz = getpagesize();
	int vmi_fd;

	vm = vm_create_with_one_vcpu(&vcpu, guest_redirect);
	vmi_fd = vmi_create(vm);
	vmi_setup_ring(vmi_fd, 0, &ring);

	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, FUNC_A_GPA, 20,
				    vm_calc_num_guest_pages(vm->mode, psz), 0);
	virt_map(vm, FUNC_A_GPA, FUNC_A_GPA, vm_calc_num_guest_pages(vm->mode, psz));
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, FUNC_B_GPA, 21,
				    vm_calc_num_guest_pages(vm->mode, psz), 0);
	virt_map(vm, FUNC_B_GPA, FUNC_B_GPA, vm_calc_num_guest_pages(vm->mode, psz));
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, RESULT_GPA, 22,
				    vm_calc_num_guest_pages(vm->mode, psz), 0);
	virt_map(vm, RESULT_GPA, RESULT_GPA, vm_calc_num_guest_pages(vm->mode, psz));

	func_a_hva = addr_gpa2hva(vm, FUNC_A_GPA);
	func_b_hva = addr_gpa2hva(vm, FUNC_B_GPA);
	result_hva = addr_gpa2hva(vm, RESULT_GPA);
	memcpy(func_a_hva, func_a_code, sizeof(func_a_code));
	memcpy(func_b_hva, func_b_code, sizeof(func_b_code));
	*result_hva = SENTINEL;

	vmi_control_event(vmi_fd, KVM_VMI_EVENT_BREAKPOINT, 1);

	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for BRK");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_BREAKPOINT, "Expected breakpoint");

	/* Redirect PC to func_b, x0=RESULT, x1=MAGIC. Kernel must use PC as-is. */
	ev->regs.pc = FUNC_B_GPA;
	ev->regs.regs[0] = RESULT_GPA;
	ev->regs.regs[1] = MAGIC;
	ev->response = KVM_VMI_RESPONSE_SET_REGS;
	vmi_ack_event(&ring, 0);

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");
	TEST_ASSERT(*result_hva == MAGIC,
		    "RESULT=0x%lx expected 0x%lx (0x%lx => PC was wrongly +4)",
		    (unsigned long)*result_hva, (unsigned long)MAGIC,
		    (unsigned long)SENTINEL);

	pr_info("PASS: vmi_brk_skip - PC not corrupted, result=0x%lx\n",
		(unsigned long)*result_hva);

	vmi_teardown_ring(&ring);
	close(vmi_fd);
	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	vmi_force_el1_guests();
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_RING));

	test_brk_set_regs_no_skip();

	return 0;
}
