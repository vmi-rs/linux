// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI view switching test (arm64)
 *
 * A vCPU runs on view 0, switches to an alternate (empty) view that is
 * lazily populated from the host stage-2 via the fault path, then switches
 * back. Exercises kvm_arch_vmi_switch_view + the VTTBR_EL2 reload in
 * kvm_vmi_apply_state.
 */
#include <linux/kvm.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

static void guest_simple(void)
{
	int i;

	for (i = 0; i < 5; i++) {
		GUEST_SYNC(i + 1);
		asm volatile("nop");
	}
	GUEST_DONE();
}

static void expect_sync(struct kvm_vcpu *vcpu, uint64_t want)
{
	struct ucall uc;

	vcpu_run(vcpu);
	TEST_ASSERT(get_ucall(vcpu, &uc) == UCALL_SYNC && uc.args[1] == want,
		    "Expected SYNC(%lu)", (unsigned long)want);
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

	view_id = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);

	/* Run on view 0 */
	expect_sync(vcpu, 1);

	/* Switch to the alternate view; guest faults populate it lazily */
	vmi_switch_view(vmi_fd, view_id);
	expect_sync(vcpu, 2);

	/* Switch back to view 0 */
	vmi_switch_view(vmi_fd, 0);
	expect_sync(vcpu, 3);
	expect_sync(vcpu, 4);
	expect_sync(vcpu, 5);

	vcpu_run(vcpu);
	TEST_ASSERT(get_ucall(vcpu, &uc) == UCALL_DONE, "Expected DONE");

	vmi_destroy_view(vmi_fd, view_id);
	close(vmi_fd);
	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	test_view_switch_basic();
	pr_info("PASS: vmi_view_switch\n");
	return 0;
}
