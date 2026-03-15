// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI view switching test
 *
 * Tests that a vCPU can run on an alternate view with
 * lazy EPT population from the host EPT.
 * Uses vmi_fd helpers for view creation and switching.
 */
#include <linux/kvm.h>
#include <stdint.h>
#include <string.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

static void guest_simple(void)
{
	int i;

	for (i = 0; i < 5; i++) {
		GUEST_SYNC(i + 1);
		__asm__ __volatile__("nop");
	}
	GUEST_DONE();
}

static void test_view_switch_basic(void)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	struct ucall uc;
	uint32_t view_id;
	int vmi_fd;

	vm = vm_create_with_one_vcpu(&vcpu, guest_simple);
	vmi_fd = vmi_create(vm);

	/* Create an alternate view with full RWX access */
	view_id = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);

	/* Run one iteration on view 0 */
	vcpu_run(vcpu);
	TEST_ASSERT(get_ucall(vcpu, &uc) == UCALL_SYNC && uc.args[1] == 1,
		    "Expected SYNC(1)");

	/* Switch to alternate view */
	vmi_switch_view(vmi_fd, view_id);

	/* Run guest on alternate view - EPT pages lazily populated */
	vcpu_run(vcpu);
	TEST_ASSERT(get_ucall(vcpu, &uc) == UCALL_SYNC && uc.args[1] == 2,
		    "Expected SYNC(2) on alternate view");

	/* Switch back to view 0 */
	vmi_switch_view(vmi_fd, 0);

	/* Continue running on view 0 */
	vcpu_run(vcpu);
	TEST_ASSERT(get_ucall(vcpu, &uc) == UCALL_SYNC && uc.args[1] == 3,
		    "Expected SYNC(3) on view 0");

	/* Run to completion */
	vcpu_run(vcpu);
	TEST_ASSERT(get_ucall(vcpu, &uc) == UCALL_SYNC && uc.args[1] == 4,
		    "Expected SYNC(4)");
	vcpu_run(vcpu);
	TEST_ASSERT(get_ucall(vcpu, &uc) == UCALL_SYNC && uc.args[1] == 5,
		    "Expected SYNC(5)");
	vcpu_run(vcpu);
	TEST_ASSERT(get_ucall(vcpu, &uc) == UCALL_DONE, "Expected DONE");

	/* Cleanup */
	vmi_destroy_view(vmi_fd, view_id);
	close(vmi_fd);
	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	test_view_switch_basic();
	return 0;
}
