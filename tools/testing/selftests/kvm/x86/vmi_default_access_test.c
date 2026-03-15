// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI default view access test
 *
 * Tests that a view's default_access is enforced for lazily-populated pages.
 * Creates a view with R-only default, executes code spanning two pages,
 * and verifies X violations are generated for each new code page.
 *
 * Flow:
 *   1. Create view with default_access = R (no X, no W)
 *   2. Place machine code on two separate pages (JMP page1->page2, RET)
 *   3. Switch vCPU to the view, start executing
 *   4. Each new code page triggers an X violation (lazily populated)
 *   5. Agent grants RWX per-page, guest proceeds
 *   6. Verify both code pages caused X violations
 */
#include <linux/kvm.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

#define CODE_PAGE1_GPA	0x800000  /* 8MB - first code page */
#define CODE_PAGE2_GPA	0x801000  /* 8MB + 4KB - second code page */
#define CODE_PAGE1_GFN	(CODE_PAGE1_GPA >> 12)
#define CODE_PAGE2_GFN	(CODE_PAGE2_GPA >> 12)

/*
 * Guest calls a function at CODE_PAGE1_GPA.
 * That function jumps to CODE_PAGE2_GPA, which returns.
 * Both pages use the view's default_access (R-only), so each
 * instruction fetch triggers an X violation.
 */
static void guest_exec_two_pages(void)
{
	typedef void (*fn_t)(void);
	fn_t fn = (fn_t)CODE_PAGE1_GPA;

	fn();

	GUEST_DONE();
}

/*
 * Write machine code into the two code pages:
 *   Page 1 (0x800000): JMP rel32 to 0x801000
 *   Page 2 (0x801000): RET
 */
static void setup_code_pages(struct kvm_vm *vm)
{
	uint8_t *page1, *page2;

	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    CODE_PAGE1_GPA, 10, 2, 0);
	virt_map(vm, CODE_PAGE1_GPA, CODE_PAGE1_GPA, 2);

	/* Page 1: jmp rel32 to CODE_PAGE2_GPA */
	page1 = addr_gpa2hva(vm, CODE_PAGE1_GPA);
	page1[0] = 0xe9;  /* JMP rel32 */
	/* offset = 0x801000 - (0x800000 + 5) = 0xffb */
	page1[1] = 0xfb;
	page1[2] = 0x0f;
	page1[3] = 0x00;
	page1[4] = 0x00;

	/* Page 2: ret */
	page2 = addr_gpa2hva(vm, CODE_PAGE2_GPA);
	page2[0] = 0xc3;  /* RET */
}

/*
 * Test: Create a view with R-only default access (no X), verify that
 * executing code triggers X violations as each new page is lazily
 * populated with the view's default permissions.
 */
static void test_default_access_exec_violation(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;
	uint32_t view_id;
	int code1_seen = 0, code2_seen = 0;
	int violation_count = 0;
	uint64_t gfn;

	vm = vm_create_with_one_vcpu(&vcpu, guest_exec_two_pages);
	vmi_fd = vmi_create(vm);
	vmi_setup_ring(vmi_fd, 0, &ring);

	setup_code_pages(vm);

	/* Create view with R-only default - no execute permission */
	view_id = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_R);

	/* Enable mem_access event delivery */
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_MEM_ACCESS, 1);

	/* Switch vCPU to the R-only view */
	vmi_switch_view(vmi_fd, view_id);

	/* Start vCPU - first instruction fetch will fault */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/*
	 * Handle mem_access violations until the guest completes.
	 * With default_access = R, both W and X violations occur:
	 * - W violations from stack pushes, dirty bit updates, etc.
	 * - X violations from instruction fetches on each new code page
	 * We grant RWX per-page and track which code pages saw X violations.
	 */
	while (!targ.done) {
		ev = vmi_wait_event_timeout(&ring, 5000);
		if (!ev)
			break;

		TEST_ASSERT(ev->type == KVM_VMI_EVENT_MEM_ACCESS,
			    "Expected mem_access event, got %u", ev->type);

		gfn = ev->mem_access.gpa >> 12;

		if (gfn == CODE_PAGE1_GFN &&
		    (ev->mem_access.access & KVM_VMI_ACCESS_X))
			code1_seen = 1;
		if (gfn == CODE_PAGE2_GFN &&
		    (ev->mem_access.access & KVM_VMI_ACCESS_X))
			code2_seen = 1;

		/* Grant RWX so execution can proceed to the next page */
		vmi_set_mem_access(vmi_fd, view_id, gfn, KVM_VMI_ACCESS_RWX);

		ev->response = KVM_VMI_RESPONSE_CONTINUE;
		vmi_ack_event(&ring, 0);
		violation_count++;
	}

	pthread_join(thread, NULL);

	pr_info("Total X violations from default_access=R: %d\n",
		violation_count);

	TEST_ASSERT(violation_count >= 2,
		    "Expected at least 2 X violations, got %d",
		    violation_count);
	TEST_ASSERT(code1_seen,
		    "Expected X violation on CODE_PAGE1 (GFN 0x%lx)",
		    (unsigned long)CODE_PAGE1_GFN);
	TEST_ASSERT(code2_seen,
		    "Expected X violation on CODE_PAGE2 (GFN 0x%lx)",
		    (unsigned long)CODE_PAGE2_GFN);
	TEST_ASSERT(targ.done, "Guest should have completed");

	/* Cleanup */
	vmi_switch_view(vmi_fd, 0);
	vmi_destroy_view(vmi_fd, view_id);
	vmi_teardown_ring(&ring);
	close(vmi_fd);
	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));

	test_default_access_exec_violation();

	return 0;
}
