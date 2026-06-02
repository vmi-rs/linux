// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI hugepage remap / block-shatter test (arm64, K9)
 *
 * A region large and aligned enough that the alternate view would naturally
 * map it with a 32 MB PMD block (16K granule). One GFN inside the block is
 * remapped (change_gfn) to a shadow page with a distinct sentinel. The guest,
 * on the view, reads a same-block NEIGHBOR first (which - if block shatter
 * were broken - would install a block leaf over the whole region using the
 * original HPAs, hiding the override), then reads the remapped GFN. The
 * remapped GFN must read the shadow sentinel; the neighbor reads the original.
 *
 * Block span is 32 MB = PMD block at the 16K granule (this host is fixed at
 * 16K pages per /opt/CLAUDE.md); asserted at runtime, never assumed elsewhere.
 */
#include <errno.h>
#include <linux/kvm.h>
#include <linux/kvm_vmi.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

#define REGION_GPA	0x20000000ULL	/* 512 MB, 32 MB-aligned */
#define TEST_MEMSLOT	10
#define VMI_BLOCK_BYTES	(32 * 1024 * 1024)	/* PMD block, 16K granule */
#define ORIG_REMAP	0xAAAAAAAAAAAAAAAAULL
#define ORIG_NEIGH	0xBBBBBBBBBBBBBBBBULL
#define SHADOW_VAL	0xCCCCCCCCCCCCCCCCULL

static uint64_t g_remap_gva, g_neigh_gva;

static void guest_main(void)
{
	volatile uint64_t *neigh = (volatile uint64_t *)g_neigh_gva;
	volatile uint64_t *remap = (volatile uint64_t *)g_remap_gva;

	GUEST_SYNC(*neigh);	/* read neighbor first - may install a block */
	GUEST_SYNC(*remap);	/* then the remapped page */
	GUEST_DONE();
}

static uint64_t expect_sync_read(struct kvm_vcpu *vcpu)
{
	struct ucall uc;

	vcpu_run(vcpu);
	TEST_ASSERT(get_ucall(vcpu, &uc) == UCALL_SYNC, "expected UCALL_SYNC");
	return uc.args[1];
}

int main(int argc, char *argv[])
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct ucall uc;
	size_t psz = getpagesize();
	size_t block = VMI_BLOCK_BYTES;
	uint64_t remap_gpa = REGION_GPA;
	uint64_t neigh_gpa = REGION_GPA + psz;
	uint64_t remap_gfn = remap_gpa / psz;
	uint64_t shadow_gfn, *shadow, val;
	uint32_t view_id;
	int vmi_fd;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_ASSERT(psz == 16384, "test assumes 16K host pages, got %zu", psz);

	vm = vm_create_with_one_vcpu(&vcpu, guest_main);
	vmi_fd = vmi_create(vm);

	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS_THP, REGION_GPA,
				    TEST_MEMSLOT,
				    vm_calc_num_guest_pages(vm->mode, block), 0);
	virt_map(vm, REGION_GPA, REGION_GPA,
		 vm_calc_num_guest_pages(vm->mode, block));

	*(uint64_t *)addr_gpa2hva(vm, remap_gpa) = ORIG_REMAP;
	*(uint64_t *)addr_gpa2hva(vm, neigh_gpa) = ORIG_NEIGH;

	g_remap_gva = remap_gpa;	/* identity-mapped via virt_map */
	g_neigh_gva = neigh_gpa;
	sync_global_to_guest(vm, g_remap_gva);
	sync_global_to_guest(vm, g_neigh_gva);

	shadow_gfn = vmi_alloc_gfn(vmi_fd);
	shadow = mmap(NULL, psz, PROT_READ | PROT_WRITE, MAP_SHARED,
		      vmi_fd, shadow_gfn * psz);
	TEST_ASSERT(shadow != MAP_FAILED, "mmap shadow failed: %d", errno);
	shadow[0] = SHADOW_VAL;

	view_id = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);
	vmi_change_gfn(vmi_fd, view_id, remap_gfn, shadow_gfn);

	vmi_switch_view(vmi_fd, view_id);

	val = expect_sync_read(vcpu);
	TEST_ASSERT(val == ORIG_NEIGH,
		    "neighbor read got 0x%lx, want ORIG_NEIGH",
		    (unsigned long)val);

	val = expect_sync_read(vcpu);
	TEST_ASSERT(val == SHADOW_VAL,
		    "remapped read got 0x%lx, want SHADOW (block subsumed remap?)",
		    (unsigned long)val);

	vcpu_run(vcpu);
	TEST_ASSERT(get_ucall(vcpu, &uc) == UCALL_DONE, "expected DONE");

	/* Move the vCPU off the alt view so it can be destroyed (vcpu_count). */
	vmi_switch_view(vmi_fd, 0);

	munmap(shadow, psz);
	vmi_destroy_view(vmi_fd, view_id);
	close(vmi_fd);
	kvm_vm_free(vm);

	pr_info("PASS: vmi_hugepage_remap\n");
	return 0;
}
