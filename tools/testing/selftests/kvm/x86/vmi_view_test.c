// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI alternate memory view lifecycle test
 *
 * Tests view creation, destruction, and error handling via vmi_fd.
 */
#include <linux/kvm.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

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

	/* Create a view */
	view_id = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);

	/* Destroy it */
	vmi_destroy_view(vmi_fd, view_id);

	/* Destroy again - should fail with ENOENT */
	ret = vmi_destroy_view_err(vmi_fd, view_id);
	TEST_ASSERT(ret < 0 && errno == ENOENT,
		    "Double destroy should fail with ENOENT, got %d/%d",
		    ret, errno);

	close(vmi_fd);
	kvm_vm_free(vm);
}

static void test_view_create_many(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	uint32_t view_ids[20];
	int vmi_fd, i, j;

	vm = vm_create_with_one_vcpu(&vcpu, guest_nop);
	vmi_fd = vmi_create(vm);

	/* Create 20 views - verify dynamic allocation works */
	for (i = 0; i < 20; i++)
		view_ids[i] = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);

	/* Verify all IDs are unique */
	for (i = 0; i < 20; i++) {
		for (j = i + 1; j < 20; j++) {
			TEST_ASSERT(view_ids[i] != view_ids[j],
				    "Duplicate view IDs: %u", view_ids[i]);
		}
	}

	/* Destroy all */
	for (i = 0; i < 20; i++)
		vmi_destroy_view(vmi_fd, view_ids[i]);

	close(vmi_fd);
	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));

	test_view_create_destroy();
	test_view_create_many();

	return 0;
}
