// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI default view access test (arm64, K7)
 *
 * Verifies that a view's default_access is enforced for lazily-populated
 * entries with no per-GFN override. The view default is RW (no X); the guest
 * calls a stub on a dedicated code page, so the instruction fetch faults with
 * an X violation. The agent grants X and CONTINUEs, after which the stub
 * executes and the guest progresses.
 *
 * GFN math is host-page based (gfn = gpa / getpagesize()); never a hardcoded
 * 4K shift. The code GPA is 64K-aligned, valid for any guest granule.
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

#define CODE_GPA	0x10000000ULL	/* 256MB - dedicated code page */
#define CODE_MEMSLOT	10

#define AARCH64_RET	0xd65f03c0U	/* "ret" */

/*
 * Guest calls the stub at CODE_GPA. The stub is a bare "ret", so the call
 * (a branch with link) plus the fetch of the stub trigger an X violation on
 * the code page under the RW-only view default. After the agent grants X the
 * call returns normally and the guest reaches GUEST_DONE.
 */
static void guest_main(void)
{
	void (*fn)(void) = (void (*)(void))CODE_GPA;

	fn();
	GUEST_SYNC(1);
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
	uint64_t code_gfn = CODE_GPA / psz;
	uint32_t view_id;
	uint32_t *code;
	int vmi_fd;
	int x_seen = 0;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_RING));

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_main, &ring);

	/* Map an executable code page and emit a single "ret". */
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, CODE_GPA,
				    CODE_MEMSLOT,
				    vm_calc_num_guest_pages(vm->mode, psz), 0);
	virt_map(vm, CODE_GPA, CODE_GPA, vm_calc_num_guest_pages(vm->mode, psz));
	code = (uint32_t *)addr_gpa2hva(vm, CODE_GPA);
	code[0] = AARCH64_RET;

	/* View default RW (no X), no per-GFN override on the code page. */
	view_id = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RW);
	vmi_switch_view(vmi_fd, view_id);

	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/*
	 * Drain mem_access events until the guest finishes. Under a RW-only
	 * default, code pages lazily populate without X and fault on fetch.
	 * We grant X on the code page (assert the X violation is seen there)
	 * and RWX elsewhere so the guest can run.
	 */
	while (!targ.done) {
		ev = vmi_wait_event_timeout(&ring, 5000);
		if (!ev)
			break;

		TEST_ASSERT(ev->type == KVM_VMI_EVENT_MEM_ACCESS,
			    "Expected MEM_ACCESS, got %u", ev->type);

		if (ev->mem_access.gpa / psz == code_gfn &&
		    (ev->mem_access.access & KVM_VMI_ACCESS_X))
			x_seen = 1;

		vmi_set_mem_access(vmi_fd, view_id, ev->mem_access.gpa / psz,
				   KVM_VMI_ACCESS_RWX);
		ev->response = KVM_VMI_RESPONSE_CONTINUE;
		vmi_ack_event(&ring, 0);
	}

	pthread_join(thread, NULL);

	TEST_ASSERT(x_seen,
		    "Expected an X violation on the code page (GFN 0x%lx)",
		    (unsigned long)code_gfn);
	TEST_ASSERT(targ.done, "Guest should have completed");

	vmi_switch_view(vmi_fd, 0);
	vmi_destroy_view(vmi_fd, view_id);
	vmi_test_teardown(vm, vmi_fd, &ring);
	pr_info("PASS: vmi_default_access\n");

	return 0;
}
