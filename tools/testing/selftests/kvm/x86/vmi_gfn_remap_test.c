// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI GFN remapping test
 *
 * Tests the core VMI use case: shadow page breakpoints via CHANGE_GFN
 * with ring-based event delivery.
 *
 * Workflow:
 * 1. Create a code page and a shadow page in guest memory
 * 2. Copy code to shadow, patch shadow with INT3 (0xCC)
 * 3. Create an alternate view, remap code_gfn -> shadow_gfn
 * 4. Guest runs in the view, hits INT3 on the shadow page
 * 5. Verify breakpoint ring event at the correct address
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
 * Guest memory layout:
 * 0x800000 (CODE_GPA)   - page containing target function (via call)
 * 0x801000 (SHADOW_GPA) - shadow copy with INT3 patched in
 */
#define CODE_GPA	0x800000ULL
#define SHADOW_GPA	0x801000ULL
#define CODE_SLOT	10
#define SHADOW_SLOT	11

/*
 * The guest calls a function pointer to CODE_GPA.
 * When running on the trap view, CODE_GPA actually maps to the shadow page,
 * which has INT3 at byte 0.
 */
static void guest_main(void)
{
	void (*fn)(void) = (void (*)(void))CODE_GPA;

	GUEST_SYNC(1); /* Signal ready */

	/* Call the function at CODE_GPA */
	fn();

	/* If we get here, the INT3 was handled (or we're on original code) */
	GUEST_SYNC(2);
	GUEST_DONE();
}

/*
 * A simple function to copy into the code page.
 * It's just a RET so we can call it without side effects.
 */
static const uint8_t target_code[] = {
	0xC3,	/* RET */
};

static void test_gfn_remap(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;
	uint32_t view_id;
	void *code_hva, *shadow_hva;
	uint64_t code_gfn = CODE_GPA >> 12;
	uint64_t shadow_gfn = SHADOW_GPA >> 12;

	vm = vm_create_with_one_vcpu(&vcpu, guest_main);
	vmi_fd = vmi_create(vm);
	vmi_setup_ring(vmi_fd, 0, &ring);

	/* Map code page and shadow page into guest physical memory */
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    CODE_GPA, CODE_SLOT, 1, 0);
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    SHADOW_GPA, SHADOW_SLOT, 1, 0);

	/* Create guest virtual mapping for the code page */
	virt_map(vm, CODE_GPA, CODE_GPA, 1);
	/* Shadow page doesn't need a virtual mapping - only used via EPT remap */

	/* Write a simple RET into the code page */
	code_hva = addr_gpa2hva(vm, CODE_GPA);
	memcpy(code_hva, target_code, sizeof(target_code));

	/* Copy code to shadow, then patch byte 0 with INT3 */
	shadow_hva = addr_gpa2hva(vm, SHADOW_GPA);
	memcpy(shadow_hva, code_hva, 4096);
	((uint8_t *)shadow_hva)[0] = 0xCC; /* INT3 */

	/* Create an alternate view */
	view_id = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);

	/* Remap: in this view, code_gfn -> shadow page's physical backing */
	vmi_change_gfn(vmi_fd, view_id, code_gfn, shadow_gfn);

	/* Enable breakpoint monitoring */
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_BREAKPOINT, 1);

	/* Switch to the trap view */
	vmi_switch_view(vmi_fd, view_id);

	/* Start vCPU thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* Guest calls fn() -> hits INT3 on shadow page */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for breakpoint event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_BREAKPOINT,
		    "Expected breakpoint event, got %u", ev->type);

	/*
	 * Respond: switch to host view (view 0) and re-execute from same RIP.
	 * On view 0, byte 0 of the code page is RET (0xC3), not INT3.
	 */
	ev->response = KVM_VMI_RESPONSE_SWITCH_VIEW;
	ev->view_id = 0;
	vmi_ack_event(&ring, 0);

	/*
	 * Guest re-executes at RIP 0x800000 on view 0, hits RET,
	 * returns to caller, continues to GUEST_SYNC(2), then DONE.
	 */
	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");

	/* Revert the remapping */
	vmi_change_gfn(vmi_fd, view_id, code_gfn, KVM_VMI_INVALID_GFN);

	/* Cleanup */
	vmi_destroy_view(vmi_fd, view_id);
	vmi_teardown_ring(&ring);
	close(vmi_fd);
	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	test_gfn_remap();
	return 0;
}
