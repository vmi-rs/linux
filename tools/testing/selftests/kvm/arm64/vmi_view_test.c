// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI alternate memory view lifecycle test (arm64)
 *
 * Tests view creation, destruction, and error handling via vmi_fd.
 */
#include <linux/kvm.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

#define NR_VIEWS	20

static void guest_nop(void)
{
	GUEST_DONE();
}

static void test_view_create_destroy(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	uint32_t view_id;
	int vmi_fd, ret;

	vm = vm_create_with_one_vcpu(&vcpu, guest_nop);
	vmi_fd = vmi_create(vm);

	view_id = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);

	vmi_destroy_view(vmi_fd, view_id);

	/* Double destroy - should fail with ENOENT */
	ret = vmi_destroy_view_err(vmi_fd, view_id);
	TEST_ASSERT(ret < 0 && errno == ENOENT,
		    "Double destroy should fail with ENOENT, got %d/%d",
		    ret, errno);

	/* Destroying view 0 (host view) is rejected with EINVAL */
	ret = vmi_destroy_view_err(vmi_fd, 0);
	TEST_ASSERT(ret < 0 && errno == EINVAL,
		    "Destroy view 0 should fail with EINVAL, got %d/%d",
		    ret, errno);

	close(vmi_fd);
	kvm_vm_free(vm);
}

static void test_view_create_many(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	uint32_t view_ids[NR_VIEWS];
	int vmi_fd, i, j;

	vm = vm_create_with_one_vcpu(&vcpu, guest_nop);
	vmi_fd = vmi_create(vm);

	for (i = 0; i < NR_VIEWS; i++)
		view_ids[i] = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);

	for (i = 0; i < NR_VIEWS; i++)
		for (j = i + 1; j < NR_VIEWS; j++)
			TEST_ASSERT(view_ids[i] != view_ids[j],
				    "Duplicate view IDs: %u", view_ids[i]);

	for (i = 0; i < NR_VIEWS; i++)
		vmi_destroy_view(vmi_fd, view_ids[i]);

	close(vmi_fd);
	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	vmi_force_el1_guests();
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));

	test_view_create_destroy();
	test_view_create_many();

	pr_info("PASS: vmi_view\n");
	return 0;
}
