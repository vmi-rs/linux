// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI guest memory mapping test (arm64)
 *
 * Tests mmap on vmi_fd for guest physical memory access. The mmap page
 * offset is interpreted as a guest frame number (GFN); the page is faulted
 * in from the VM owner's address space. All offsets derive from
 * getpagesize() (16K on this host), never a hardcoded 4K shift.
 *
 * The x86 reference has two extra cases that depend on features not present
 * at this point in the arm64 series: a ring-based write path (event ring,
 * K4) and a gfn-remap case (alternate views, K6/K9). The write case here is
 * ring-free; the gfn-remap/view case is deferred until views land.
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

/*
 * Host pages are 16K here (getpagesize() == 16384) but the selftest guest
 * granule may be smaller (4K), so host and guest page sizes differ. The
 * vmi_fd mmap is host-page based (offset = GFN * getpagesize()), while
 * memslot sizes below are guest-page counts derived with
 * vm_calc_num_guest_pages() so each region stays host-page-aligned.
 *
 * GPAs sit at 256MB, well clear of memslot 0, and are 64K-aligned so they
 * are valid for any guest granule and fit the 36-bit IPA seen in nested L1.
 */
#define TEST_GPA      0x10000000ULL
#define TEST_PATTERN  0xCAFEBABE12345678ULL
#define TEST_MEMSLOT  10

#define LARGE_RANGE_PAGES  16
#define LARGE_GPA          0x10200000ULL
#define LARGE_MEMSLOT      11

/* Guest reads from TEST_GPA and asserts the expected pattern. */
static void guest_read_test_page(void)
{
	volatile uint64_t *ptr = (volatile uint64_t *)TEST_GPA;

	GUEST_SYNC(1);
	GUEST_ASSERT(*ptr == TEST_PATTERN);
	GUEST_DONE();
}

/* Test 1: map a guest page via vmi_fd and verify read access. */
static void test_guest_mmap_read(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	size_t psz = getpagesize();
	uint64_t gfn = TEST_GPA / psz;
	int vmi_fd;
	void *hva, *mapped;
	uint64_t val;

	vm = vm_create_with_one_vcpu(&vcpu, guest_read_test_page);
	vmi_fd = vmi_create(vm);

	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, TEST_GPA,
				    TEST_MEMSLOT,
				    vm_calc_num_guest_pages(vm->mode, psz), 0);

	hva = addr_gpa2hva(vm, TEST_GPA);
	*(uint64_t *)hva = 0xDEADBEEFULL;

	mapped = mmap(NULL, psz, PROT_READ, MAP_SHARED, vmi_fd, gfn * psz);
	TEST_ASSERT(mapped != MAP_FAILED,
		    "mmap via vmi_fd failed: errno=%d", errno);

	val = *(volatile uint64_t *)mapped;
	TEST_ASSERT(val == 0xDEADBEEFULL,
		    "Expected 0xDEADBEEF via vmi_fd mmap, got 0x%lx", val);

	munmap(mapped, psz);
	close(vmi_fd);
	kvm_vm_free(vm);
	pr_info("PASS: test_guest_mmap_read\n");
}

/* Test 2: write a guest page via vmi_fd, guest reads it back (ring-free). */
static void test_guest_mmap_write(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	size_t psz = getpagesize();
	uint64_t gfn = TEST_GPA / psz;
	int vmi_fd;
	void *mapped;

	vm = vm_create_with_one_vcpu(&vcpu, guest_read_test_page);
	vmi_fd = vmi_create(vm);

	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, TEST_GPA,
				    TEST_MEMSLOT,
				    vm_calc_num_guest_pages(vm->mode, psz), 0);
	virt_map(vm, TEST_GPA, TEST_GPA, vm_calc_num_guest_pages(vm->mode, psz));

	mapped = mmap(NULL, psz, PROT_READ | PROT_WRITE, MAP_SHARED,
		      vmi_fd, gfn * psz);
	TEST_ASSERT(mapped != MAP_FAILED,
		    "mmap via vmi_fd failed: errno=%d", errno);

	*(volatile uint64_t *)mapped = TEST_PATTERN;

	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);
	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done,
		    "Guest should see TEST_PATTERN and reach GUEST_DONE");

	munmap(mapped, psz);
	close(vmi_fd);
	kvm_vm_free(vm);
	pr_info("PASS: test_guest_mmap_write\n");
}

/* Test 3: mmap a GFN with no backing memslot -> mmap fails or access SIGBUSes. */
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
	size_t psz = getpagesize();
	int vmi_fd;
	void *mapped;
	struct sigaction sa, old_sa;

	vm = vm_create_with_one_vcpu(&vcpu, guest_read_test_page);
	vmi_fd = vmi_create(vm);

	/* GFN far beyond any memslot. */
	mapped = mmap(NULL, psz, PROT_READ, MAP_SHARED,
		      vmi_fd, 0xFFFF0000ULL * psz);
	if (mapped == MAP_FAILED) {
		pr_info("PASS: test_guest_mmap_invalid_gfn (mmap rejected)\n");
		close(vmi_fd);
		kvm_vm_free(vm);
		return;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigbus_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGBUS, &sa, &old_sa);

	sigbus_caught = 0;
	if (sigsetjmp(sigbus_jmpbuf, 1) == 0) {
		volatile char c = ((volatile char *)mapped)[0];
		(void)c;
		pr_info("PASS: test_guest_mmap_invalid_gfn (no fault, read succeeded)\n");
	} else {
		pr_info("PASS: test_guest_mmap_invalid_gfn (got SIGBUS as expected)\n");
	}

	sigaction(SIGBUS, &old_sa, NULL);
	munmap(mapped, psz);
	close(vmi_fd);
	kvm_vm_free(vm);
}

/* Test 4: unmap then remap the same GFN; content must survive. */
static void test_guest_mmap_unmap_remap(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	size_t psz = getpagesize();
	uint64_t gfn = TEST_GPA / psz;
	int vmi_fd;
	void *hva, *mapped;
	uint64_t val;

	vm = vm_create_with_one_vcpu(&vcpu, guest_read_test_page);
	vmi_fd = vmi_create(vm);

	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, TEST_GPA,
				    TEST_MEMSLOT,
				    vm_calc_num_guest_pages(vm->mode, psz), 0);

	hva = addr_gpa2hva(vm, TEST_GPA);
	*(uint64_t *)hva = TEST_PATTERN;

	mapped = mmap(NULL, psz, PROT_READ, MAP_SHARED, vmi_fd, gfn * psz);
	TEST_ASSERT(mapped != MAP_FAILED, "first mmap failed");
	val = *(volatile uint64_t *)mapped;
	TEST_ASSERT(val == TEST_PATTERN, "first read mismatch: 0x%lx", val);

	munmap(mapped, psz);

	mapped = mmap(NULL, psz, PROT_READ, MAP_SHARED, vmi_fd, gfn * psz);
	TEST_ASSERT(mapped != MAP_FAILED, "remap failed");
	val = *(volatile uint64_t *)mapped;
	TEST_ASSERT(val == TEST_PATTERN, "remap read mismatch: 0x%lx", val);

	munmap(mapped, psz);
	close(vmi_fd);
	kvm_vm_free(vm);
	pr_info("PASS: test_guest_mmap_unmap_remap\n");
}

/* Test 5: map 16 contiguous pages in one call; verify first and last. */
static void test_guest_mmap_large_range(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	size_t psz = getpagesize();
	uint64_t gfn = LARGE_GPA / psz;
	size_t map_size = LARGE_RANGE_PAGES * psz;
	int vmi_fd;
	void *hva, *mapped;

	vm = vm_create_with_one_vcpu(&vcpu, guest_read_test_page);
	vmi_fd = vmi_create(vm);

	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, LARGE_GPA,
				    LARGE_MEMSLOT,
				    vm_calc_num_guest_pages(vm->mode, map_size), 0);

	hva = addr_gpa2hva(vm, LARGE_GPA);
	*(uint64_t *)hva = 0xAAAAAAAAAAAAAAAAULL;
	hva = addr_gpa2hva(vm, LARGE_GPA + (LARGE_RANGE_PAGES - 1) * psz);
	*(uint64_t *)hva = 0xBBBBBBBBBBBBBBBBULL;

	mapped = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED,
		      vmi_fd, gfn * psz);
	TEST_ASSERT(mapped != MAP_FAILED,
		    "large range mmap failed: errno=%d", errno);

	TEST_ASSERT(*(volatile uint64_t *)mapped == 0xAAAAAAAAAAAAAAAAULL,
		    "first page mismatch");
	TEST_ASSERT(*(volatile uint64_t *)((char *)mapped +
		    (LARGE_RANGE_PAGES - 1) * psz) == 0xBBBBBBBBBBBBBBBBULL,
		    "last page mismatch");

	munmap(mapped, map_size);
	close(vmi_fd);
	kvm_vm_free(vm);
	pr_info("PASS: test_guest_mmap_large_range\n");
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

	return 0;
}
