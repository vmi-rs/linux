// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI guest RAM extent test (arm64)
 *
 * Tests KVM_VMI_GET_MEM_INFO: the agent learns the guest RAM extent (the
 * maximum of base_gfn + npages over all memslots) so it can reject reads of
 * unbacked frames instead of faulting the vmi_fd mmap. KVM has no
 * memslot-enumeration ioctl, so this is the agent's only way to learn the
 * layout the VMM programmed.
 */
#include <linux/kvm.h>
#include <linux/kvm_vmi.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

static void guest_nop(void)
{
	GUEST_DONE();
}

static uint64_t vmi_get_mem_info(int vmi_fd)
{
	struct kvm_vmi_mem_info info;
	int ret;

	memset(&info, 0, sizeof(info));
	ret = ioctl(vmi_fd, KVM_VMI_GET_MEM_INFO, &info);
	TEST_ASSERT(ret == 0,
		    "KVM_VMI_GET_MEM_INFO failed: ret=%d errno=%d", ret, errno);
	return info.max_gfn;
}

/*
 * The reported extent is non-trivial and tracks the live memslots: it grows to
 * cover a region added above the existing guest RAM, proving the ioctl really
 * iterates memslots and returns max(base_gfn + npages).
 */
static void test_mem_info(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	int vmi_fd;
	size_t pg = getpagesize();
	uint64_t before, after, region_paddr, region_base_gfn;

	vm = vm_create_with_one_vcpu(&vcpu, guest_nop);
	vmi_fd = vmi_create(vm);

	before = vmi_get_mem_info(vmi_fd);
	TEST_ASSERT(before > 0,
		    "max_gfn should be > 0 for a VM with RAM, got %lu",
		    (unsigned long)before);

	/*
	 * Add a memslot one GB (in frames) above the current RAM end. The gap
	 * is fine (memslots may be sparse) and keeps the region well within the
	 * guest IPA limit. The ioctl reads kvm_memslots() live, so the new slot
	 * must be reflected. region_paddr is host-page aligned by construction,
	 * which also satisfies guest-page alignment.
	 */
	region_base_gfn = before + (1ULL << 30) / pg;
	region_paddr = region_base_gfn * pg;
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, region_paddr,
				    10, 64, 0);

	after = vmi_get_mem_info(vmi_fd);
	TEST_ASSERT(after > before,
		    "max_gfn should grow after adding RAM: %lu -> %lu",
		    (unsigned long)before, (unsigned long)after);
	TEST_ASSERT(after > region_base_gfn,
		    "max_gfn 0x%lx should cover the added region base 0x%lx",
		    (unsigned long)after, (unsigned long)region_base_gfn);

	close(vmi_fd);
	kvm_vm_free(vm);
	pr_info("PASS: test_mem_info\n");
}

int main(int argc, char *argv[])
{
	vmi_force_el1_guests();
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));

	test_mem_info();

	pr_info("PASS: vmi_mem_info\n");
	return 0;
}
