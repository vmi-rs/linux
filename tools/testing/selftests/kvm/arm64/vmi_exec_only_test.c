// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI execute-only view test (arm64, K7)
 *
 * Exercises the arm64-specific execute-only capability (S2AP=00, XN=0): a view
 * page set to KVM_VMI_ACCESS_X only must allow instruction fetch while trapping
 * data read and write.
 *
 * The single code+data page Gxo holds an executable "ret" stub at offset 0 and
 * a data word later in the page. Three ordered phases, each bracketed by a
 * GUEST_SYNC so the corresponding event is unambiguous:
 *   (a) EXECUTE the stub      -> succeeds, NO event.
 *   (b) READ the data word    -> MEM_ACCESS with R bit; agent grants R+CONTINUE.
 *   (c) WRITE the data word   -> MEM_ACCESS with W bit; agent DENYs -> abort.
 *
 * After (b) the page is widened, so we re-set it X-only before (c) to keep the
 * write a genuine violation. GFN math is host-page based; the GPA is 64K
 * aligned so it is valid for any guest granule.
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

#define XO_GPA		0x10000000ULL	/* 256MB - exec-only code+data page */
#define XO_MEMSLOT	10
#define DATA_OFF	0x100		/* data word offset within the page */
#define DATA_GPA	(XO_GPA + DATA_OFF)

#define AARCH64_RET	0xd65f03c0U	/* "ret" */
#define DATA_INIT	0x1234567890abcdefULL
#define DATA_WRITE	0xfeedfacef00dULL

static volatile uint64_t g_esr;
static volatile int g_handled;

static void sync_handler(struct ex_regs *regs)
{
	g_esr = read_sysreg(esr_el1);
	g_handled = 1;
	regs->pc += 4;	/* skip the faulting store */
}

static void guest_main(void)
{
	void (*fn)(void) = (void (*)(void))XO_GPA;
	volatile uint64_t *data = (volatile uint64_t *)DATA_GPA;
	uint64_t val;

	/* (a) Execute the stub; X-only allows this, no event expected. */
	fn();
	GUEST_SYNC(1);

	/* (b) Read the data word; X-only traps the read. Agent grants R. */
	val = *data;
	GUEST_ASSERT_EQ(val, DATA_INIT);
	GUEST_SYNC(2);

	/* (c) Write the data word; X-only traps the write. Agent DENYs. */
	g_handled = 0;
	*data = DATA_WRITE;
	GUEST_ASSERT(g_handled);
	GUEST_ASSERT_EQ(ESR_ELx_EC(g_esr), ESR_ELx_EC_DABT_CUR);
	GUEST_ASSERT(g_esr & ESR_ELx_WNR);
	GUEST_ASSERT_EQ(*data, DATA_INIT);	/* write must not have landed */
	GUEST_DONE();
}

/* Wait for a MEM_ACCESS at the exec-only GFN with the given access bit set. */
static void expect_violation(struct vmi_test_ring *ring, uint64_t gfn,
			     size_t psz, uint8_t want_bit, const char *what,
			     uint32_t response, int vmi_fd, uint32_t view_id,
			     uint8_t grant)
{
	struct kvm_vmi_ring_event *ev;

	ev = vmi_wait_event_timeout(ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for %s violation", what);
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_MEM_ACCESS,
		    "Expected MEM_ACCESS for %s, got %u", what, ev->type);
	TEST_ASSERT(ev->mem_access.gpa / psz == gfn,
		    "Expected GFN 0x%lx for %s, got GPA 0x%llx",
		    (unsigned long)gfn, what, ev->mem_access.gpa);
	TEST_ASSERT(ev->mem_access.access & want_bit,
		    "Expected %s violation bit 0x%x, got access 0x%x",
		    what, want_bit, ev->mem_access.access);

	if (response == KVM_VMI_RESPONSE_CONTINUE)
		vmi_set_mem_access(vmi_fd, view_id, gfn, grant);

	ev->response = response;
	vmi_ack_event(ring, 0);
}

int main(int argc, char *argv[])
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	size_t psz = getpagesize();
	uint64_t gfn = XO_GPA / psz;
	uint32_t view_id;
	uint32_t *code;
	uint64_t *data;
	int vmi_fd;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_RING));

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_main, &ring);

	vm_init_descriptor_tables(vm);
	vcpu_init_descriptor_tables(vcpu);
	vm_install_sync_handler(vm, VECTOR_SYNC_CURRENT,
				ESR_ELx_EC_DABT_CUR, sync_handler);

	/* One page holding a "ret" stub at offset 0 and a data word later. */
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, XO_GPA,
				    XO_MEMSLOT,
				    vm_calc_num_guest_pages(vm->mode, psz), 0);
	virt_map(vm, XO_GPA, XO_GPA, vm_calc_num_guest_pages(vm->mode, psz));
	code = (uint32_t *)addr_gpa2hva(vm, XO_GPA);
	code[0] = AARCH64_RET;
	data = (uint64_t *)addr_gpa2hva(vm, DATA_GPA);
	*data = DATA_INIT;

	/* View default RWX, but the code+data page is execute-only. */
	view_id = vmi_create_view(vmi_fd, KVM_VMI_ACCESS_RWX);
	vmi_set_mem_access(vmi_fd, view_id, gfn, KVM_VMI_ACCESS_X);
	vmi_switch_view(vmi_fd, view_id);

	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/*
	 * The vCPU free-runs in its own thread across the guest's phases. Phase
	 * (a) executes the X-only stub and produces NO event, so the vCPU does
	 * not block there -- it races straight into phase (b)'s data read, which
	 * traps and blocks. There is no host/guest handshake holding the guest
	 * at (a), so we cannot poll for "no event" without racing the read.
	 *
	 * Instead we prove execute-only by event ORDERING: the FIRST MEM_ACCESS
	 * must be the phase-(b) READ (R bit set, X bit clear). Had the fetch in
	 * (a) trapped, is_exec_fault would classify it as an execute violation
	 * and the first event would carry the X bit. So the arrival of a pure
	 * read violation as the first event is positive proof that the preceding
	 * instruction fetch was NOT trapped -- and a real execute-only regression
	 * (a trapped fetch) still fails loudly here via the X-bit assertion.
	 *
	 * (b) Read traps with R; grant R then CONTINUE so the read completes.
	 */
	{
		struct kvm_vmi_ring_event *ev;

		ev = vmi_wait_event_timeout(&ring, 5000);
		TEST_ASSERT(ev != NULL, "Timeout waiting for first (read) event");
		TEST_ASSERT(ev->type == KVM_VMI_EVENT_MEM_ACCESS,
			    "Expected MEM_ACCESS as first event, got type=%u",
			    ev->type);
		TEST_ASSERT(ev->mem_access.gpa / psz == gfn,
			    "Expected first event at exec-only GFN 0x%lx, got GPA 0x%llx",
			    (unsigned long)gfn, ev->mem_access.gpa);
		TEST_ASSERT(ev->mem_access.access & KVM_VMI_ACCESS_R,
			    "Expected R bit on first event, got access 0x%x",
			    ev->mem_access.access);
		TEST_ASSERT(!(ev->mem_access.access & KVM_VMI_ACCESS_X),
			    "First event carries X bit (access 0x%x): execute-only fetch was trapped -- regression",
			    ev->mem_access.access);

		/* Grant R then CONTINUE so the read completes. */
		vmi_set_mem_access(vmi_fd, view_id, gfn, KVM_VMI_ACCESS_RX);
		ev->response = KVM_VMI_RESPONSE_CONTINUE;
		vmi_ack_event(&ring, 0);
	}

	/*
	 * Leave the page at R+X (granted above for the read). A re-arm to
	 * X-only here would race the guest's not-yet-retired load and re-trap it
	 * as another READ; R+X already denies W, so the upcoming write is still a
	 * genuine W violation without the race.
	 */

	/* (c) Write traps with W; DENY -> guest takes an injected data abort. */
	expect_violation(&ring, gfn, psz, KVM_VMI_ACCESS_W, "write",
			 KVM_VMI_RESPONSE_DENY, vmi_fd, view_id, 0);

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");

	vmi_switch_view(vmi_fd, 0);
	vmi_destroy_view(vmi_fd, view_id);
	vmi_test_teardown(vm, vmi_fd, &ring);
	pr_info("PASS: vmi_exec_only\n");

	return 0;
}
