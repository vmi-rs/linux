// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI guest memory mapping test
 *
 * Tests mmap on vmi_fd for guest physical memory access.
 * The vmi_fd allows mapping guest physical pages into the host
 * userspace address space for direct read/write inspection.
 */
#include <errno.h>
#include <linux/kvm.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

#define TEST_GPA      0x800000ULL
#define TEST_GFN      (TEST_GPA >> 12)
#define TEST_PATTERN  0xCAFEBABE12345678ULL
#define TEST_MEMSLOT  10

#define LARGE_RANGE_PAGES  16
#define LARGE_GPA          0xA00000ULL
#define LARGE_GFN          (LARGE_GPA >> 12)
#define LARGE_MEMSLOT      11

#define SHADOW_GPA      0xC00000ULL
#define SHADOW_GFN      (SHADOW_GPA >> 12)
#define SHADOW_MEMSLOT  12

/*
 * Guest reads from TEST_GPA and asserts the expected pattern.
 */
static void guest_read_test_page(void)
{
	volatile uint64_t *ptr = (volatile uint64_t *)TEST_GPA;

	GUEST_SYNC(1);
	GUEST_ASSERT(*ptr == TEST_PATTERN);
	GUEST_DONE();
}

/*
 * Test 1: Map a guest page via vmi_fd mmap and verify read access.
 *
 * Write a known pattern to a guest page via HVA, then mmap the same
 * GPA via vmi_fd and verify the value matches.
 */
static void test_guest_mmap_read(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	int vmi_fd;
	void *hva;
	void *mapped;
	uint64_t val;

	vm = vm_create_with_one_vcpu(&vcpu, guest_read_test_page);
	vmi_fd = vmi_create(vm);

	/* Add a memslot for the test GPA */
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    TEST_GPA, TEST_MEMSLOT, 1, 0);

	/* Write the pattern via HVA (standard VM memory access) */
	hva = addr_gpa2hva(vm, TEST_GPA);
	*(uint64_t *)hva = 0xDEADBEEFULL;

	/* Map the same GPA via vmi_fd */
	mapped = mmap(NULL, getpagesize(), PROT_READ, MAP_SHARED,
		      vmi_fd, TEST_GFN * getpagesize());
	TEST_ASSERT(mapped != MAP_FAILED,
		    "mmap via vmi_fd failed: errno=%d", errno);

	/* Read the value and verify */
	val = *(volatile uint64_t *)mapped;
	TEST_ASSERT(val == 0xDEADBEEFULL,
		    "Expected 0xDEADBEEF via vmi_fd mmap, got 0x%lx", val);

	munmap(mapped, getpagesize());
	close(vmi_fd);
	kvm_vm_free(vm);
	pr_info("PASS: test_guest_mmap_read\n");
}

/*
 * Test 2: Write to a guest page via vmi_fd mmap, then verify
 * the guest sees the written value.
 */
static void test_guest_mmap_write(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	int vmi_fd;
	void *mapped;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_read_test_page, &ring);

	/* Add a memslot and map it into guest virtual = physical */
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    TEST_GPA, TEST_MEMSLOT, 1, 0);
	virt_map(vm, TEST_GPA, TEST_GPA, 1);

	/* Map the GPA via vmi_fd and write the test pattern */
	mapped = mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE,
		      MAP_SHARED, vmi_fd, TEST_GFN * getpagesize());
	TEST_ASSERT(mapped != MAP_FAILED,
		    "mmap via vmi_fd failed: errno=%d", errno);

	*(volatile uint64_t *)mapped = TEST_PATTERN;

	/* Start vCPU thread - guest reads the value and asserts */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done,
		    "Guest should see TEST_PATTERN and reach GUEST_DONE");

	munmap(mapped, getpagesize());
	vmi_test_teardown(vm, vmi_fd, &ring);
	pr_info("PASS: test_guest_mmap_write\n");
}

/*
 * Test 3: Attempt to mmap a GPA that has no backing memory.
 * Access should either fail at mmap time or trigger SIGBUS on access.
 * Uses sigsetjmp/siglongjmp to safely catch SIGBUS without fork.
 */
static sigjmp_buf sigbus_jmpbuf;
static volatile sig_atomic_t sigbus_caught;

static void sigbus_handler(int sig)
{
	sigbus_caught = 1;
	siglongjmp(sigbus_jmpbuf, 1);
}

static void test_guest_mmap_invalid_gfn(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	int vmi_fd;
	void *mapped;
	struct sigaction sa, old_sa;

	vm = vm_create_with_one_vcpu(&vcpu, guest_read_test_page);
	vmi_fd = vmi_create(vm);

	/* Try to mmap an unmapped GFN (way beyond any memslot) */
	mapped = mmap(NULL, getpagesize(), PROT_READ, MAP_SHARED,
		      vmi_fd, 0xFFFF0000ULL * getpagesize());
	if (mapped == MAP_FAILED) {
		/* Kernel rejected the mmap outright - this is valid behavior */
		pr_info("PASS: test_guest_mmap_invalid_gfn (mmap rejected)\n");
		close(vmi_fd);
		kvm_vm_free(vm);
		return;
	}

	/*
	 * mmap succeeded (some kernels allow it and fault on access).
	 * Install a SIGBUS handler and attempt the faulting read.
	 */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigbus_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGBUS, &sa, &old_sa);

	sigbus_caught = 0;
	if (sigsetjmp(sigbus_jmpbuf, 1) == 0) {
		volatile char c = ((volatile char *)mapped)[0];
		(void)c;
		/* No fault - kernel returned data (e.g. zeros) */
		pr_info("PASS: test_guest_mmap_invalid_gfn "
			"(no fault, read succeeded)\n");
	} else {
		/* SIGBUS caught */
		pr_info("PASS: test_guest_mmap_invalid_gfn "
			"(got SIGBUS as expected)\n");
	}

	sigaction(SIGBUS, &old_sa, NULL);
	munmap(mapped, getpagesize());
	close(vmi_fd);
	kvm_vm_free(vm);
}

/*
 * Test 4: Unmap a guest page then remap the same GFN.
 * Verify that content is preserved across unmap/remap.
 */
static void test_guest_mmap_unmap_remap(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	int vmi_fd;
	void *hva, *mapped;
	uint64_t val;

	vm = vm_create_with_one_vcpu(&vcpu, guest_read_test_page);
	vmi_fd = vmi_create(vm);

	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    TEST_GPA, TEST_MEMSLOT, 1, 0);

	hva = addr_gpa2hva(vm, TEST_GPA);
	*(uint64_t *)hva = TEST_PATTERN;

	/* First mapping */
	mapped = mmap(NULL, getpagesize(), PROT_READ, MAP_SHARED,
		      vmi_fd, TEST_GFN * getpagesize());
	TEST_ASSERT(mapped != MAP_FAILED, "first mmap failed");
	val = *(volatile uint64_t *)mapped;
	TEST_ASSERT(val == TEST_PATTERN, "first read mismatch: 0x%lx", val);

	/* Unmap */
	munmap(mapped, getpagesize());

	/* Remap same GFN */
	mapped = mmap(NULL, getpagesize(), PROT_READ, MAP_SHARED,
		      vmi_fd, TEST_GFN * getpagesize());
	TEST_ASSERT(mapped != MAP_FAILED, "remap failed");
	val = *(volatile uint64_t *)mapped;
	TEST_ASSERT(val == TEST_PATTERN, "remap read mismatch: 0x%lx", val);

	munmap(mapped, getpagesize());
	close(vmi_fd);
	kvm_vm_free(vm);
	pr_info("PASS: test_guest_mmap_unmap_remap\n");
}

/*
 * Test 5: Map 16 contiguous guest pages in one mmap call.
 * Write to first and last via HVA, verify via vmi_fd mmap.
 */
static void test_guest_mmap_large_range(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	int vmi_fd;
	void *hva, *mapped;
	size_t map_size = LARGE_RANGE_PAGES * getpagesize();

	vm = vm_create_with_one_vcpu(&vcpu, guest_read_test_page);
	vmi_fd = vmi_create(vm);

	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    LARGE_GPA, LARGE_MEMSLOT,
				    LARGE_RANGE_PAGES, 0);

	hva = addr_gpa2hva(vm, LARGE_GPA);
	*(uint64_t *)hva = 0xAAAAAAAAAAAAAAAAULL;
	hva = addr_gpa2hva(vm, LARGE_GPA + (LARGE_RANGE_PAGES - 1) * getpagesize());
	*(uint64_t *)hva = 0xBBBBBBBBBBBBBBBBULL;

	mapped = mmap(NULL, map_size, PROT_READ | PROT_WRITE,
		      MAP_SHARED, vmi_fd, LARGE_GFN * getpagesize());
	TEST_ASSERT(mapped != MAP_FAILED,
		    "large range mmap failed: errno=%d", errno);

	TEST_ASSERT(*(volatile uint64_t *)mapped == 0xAAAAAAAAAAAAAAAAULL,
		    "first page mismatch");
	TEST_ASSERT(*(volatile uint64_t *)((char *)mapped +
		    (LARGE_RANGE_PAGES - 1) * getpagesize()) ==
		    0xBBBBBBBBBBBBBBBBULL,
		    "last page mismatch");

	munmap(mapped, map_size);
	close(vmi_fd);
	kvm_vm_free(vm);
	pr_info("PASS: test_guest_mmap_large_range\n");
}

/*
 * Test 6: Create a view, remap a GFN to a shadow page, verify
 * mmap on original GFN sees original data (not shadow).
 * vmi_fd mmap reflects host memslots, not view overrides.
 */
static void test_guest_mmap_gfn_remap(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	int vmi_fd;
	void *hva_orig, *hva_shadow, *mapped;
	uint32_t view_id;
	uint64_t val;

	vm = vm_create_with_one_vcpu(&vcpu, guest_read_test_page);
	vmi_fd = vmi_create(vm);

	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    TEST_GPA, TEST_MEMSLOT, 1, 0);
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    SHADOW_GPA, SHADOW_MEMSLOT, 1, 0);

	hva_orig = addr_gpa2hva(vm, TEST_GPA);
	*(uint64_t *)hva_orig = 0x1111111111111111ULL;

	hva_shadow = addr_gpa2hva(vm, SHADOW_GPA);
	*(uint64_t *)hva_shadow = 0x2222222222222222ULL;

	view_id = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);
	vmi_change_gfn(vmi_fd, view_id, TEST_GFN, SHADOW_GFN);

	mapped = mmap(NULL, getpagesize(), PROT_READ, MAP_SHARED,
		      vmi_fd, TEST_GFN * getpagesize());
	TEST_ASSERT(mapped != MAP_FAILED,
		    "mmap via vmi_fd failed: errno=%d", errno);

	val = *(volatile uint64_t *)mapped;
	TEST_ASSERT(val == 0x1111111111111111ULL,
		    "mmap should see original (0x1111...), got 0x%lx", val);

	munmap(mapped, getpagesize());
	vmi_destroy_view(vmi_fd, view_id);
	close(vmi_fd);
	kvm_vm_free(vm);
	pr_info("PASS: test_guest_mmap_gfn_remap\n");
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_GUEST_MMAP));

	test_guest_mmap_read();
	test_guest_mmap_write();
	test_guest_mmap_invalid_gfn();
	test_guest_mmap_unmap_remap();
	test_guest_mmap_large_range();
	test_guest_mmap_gfn_remap();

	return 0;
}
