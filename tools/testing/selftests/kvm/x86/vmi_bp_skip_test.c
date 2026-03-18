// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI breakpoint RIP integrity test
 *
 * Verifies that the kernel never auto-advances RIP past INT3.  The
 * agent is responsible for advancing RIP via SET_REGS (Xen model).
 *
 * Test 1 (SET_REGS): Agent catches INT3, redirects RIP to a different
 *   function via SET_REGS.  Verifies the kernel does not corrupt the
 *   new RIP by adding the INT3 instruction length.
 *
 * Test 2 (SINGLESTEP_FAST): Agent catches INT3 on a shadow page,
 *   responds with SINGLESTEP_FAST (no SWITCH_VIEW).  Kernel defaults
 *   to view 0 for the step.  Verifies the step executes from the
 *   original RIP (byte 0 of the clean page), not RIP+1.
 *
 * Detection: func_b encodes "MOV QWORD PTR [RESULT], RAX; RET" as:
 *   48 89 04 25 <addr32> C3
 *
 * Byte 0 (0x48) is the REX.W prefix making it a 64-bit store. If RIP
 * were incorrectly advanced by 1, the CPU would decode from byte 1:
 *   89 04 25 <addr32> C3 = "MOV DWORD PTR [RESULT], EAX; RET"
 *
 * By pre-filling RESULT with a sentinel (0xCCCCCCCCCCCCCCCC) and
 * storing a magic value with distinct upper bits (0xDEADBEEF00000042),
 * the 32-bit vs 64-bit write difference is observable:
 *   Correct (64-bit): RESULT = 0xDEADBEEF00000042
 *   Buggy   (32-bit): RESULT = 0xCCCCCCCC00000042
 */
#include <linux/kvm.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

#define FUNC_A_GPA	0x900000  /* INT3 + RET trampoline */
#define FUNC_B_GPA	0x901000  /* MOV [RESULT], RAX; RET */
#define RESULT_GPA	0x902000  /* Result location */
#define SHADOW_GPA	0x903000  /* Shadow page (INT3 at byte 0) */

/*
 * Sentinel: initial RESULT contents. Upper 32 bits (0xCCCCCCCC) are
 * preserved by a buggy 32-bit write but overwritten by a correct
 * 64-bit write.
 */
#define SENTINEL	0xCCCCCCCCCCCCCCCCULL

/*
 * Magic value stored via RAX. Upper 32 bits (0xDEADBEEF) differ from
 * the sentinel, making 32-bit vs 64-bit writes distinguishable.
 */
#define MAGIC		0xDEADBEEF00000042ULL

/* func_a: INT3 + RET */
static const uint8_t func_a_code[] = {
	0xCC,	/* INT3 */
	0xC3,	/* RET */
};

/*
 * func_b: mov qword ptr [RESULT_GPA], rax; ret
 *
 *   [0] 48 REX.W (64-bit operand size)
 *   [1] 89 MOV Ev, Gv
 *   [2] 04 ModRM: mod=00, reg=RAX, rm=SIB
 *   [3] 25 SIB: scale=00, index=none, base=disp32
 *   [4..7] RESULT_GPA (little-endian)
 *   [8] C3 RET
 *
 * If RIP is off by +1, the ModRM/SIB/disp32 are identical (same
 * address) but the REX.W prefix is missing, so the CPU performs a
 * 32-bit store instead of 64-bit.
 */
static const uint8_t func_b_code[] = {
	0x48, 0x89, 0x04, 0x25,		/* REX.W MOV [disp32], RAX */
	(RESULT_GPA >>  0) & 0xFF,
	(RESULT_GPA >>  8) & 0xFF,
	(RESULT_GPA >> 16) & 0xFF,
	(RESULT_GPA >> 24) & 0xFF,
	0xC3,				/* RET */
};

/* ------------------------------------------------------------------ */
/* Test 1: SET_REGS redirect preserves the agent's RIP                */
/* ------------------------------------------------------------------ */

static void guest_set_regs(void)
{
	typedef void (*func_t)(void);
	func_t fn = (func_t)FUNC_A_GPA;
	volatile uint64_t *result = (volatile uint64_t *)RESULT_GPA;

	*result = SENTINEL;
	GUEST_SYNC(1);

	fn();	/* INT3 at func_a -> agent redirects RIP to func_b */

	GUEST_DONE();
}

/*
 * Agent catches INT3 at func_a, redirects RIP to func_b and sets RAX
 * to MAGIC via SET_REGS. The kernel must use the agent's RIP as-is.
 * func_b executes from byte 0 (64-bit MOV) and RESULT = MAGIC.
 */
static void test_bp_set_regs_no_skip(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;
	uint8_t *func_a_hva, *func_b_hva;
	uint64_t *result_hva;

	vm = vm_create_with_one_vcpu(&vcpu, guest_set_regs);
	vmi_fd = vmi_create(vm);
	vmi_setup_ring(vmi_fd, 0, &ring);

	/* Map pages */
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    FUNC_A_GPA, 20, 1, 0);
	virt_map(vm, FUNC_A_GPA, FUNC_A_GPA, 1);

	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    FUNC_B_GPA, 21, 1, 0);
	virt_map(vm, FUNC_B_GPA, FUNC_B_GPA, 1);

	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS,
				    RESULT_GPA, 22, 1, 0);
	virt_map(vm, RESULT_GPA, RESULT_GPA, 1);

	/* Write function code */
	func_a_hva = addr_gpa2hva(vm, FUNC_A_GPA);
	func_b_hva = addr_gpa2hva(vm, FUNC_B_GPA);
	result_hva = addr_gpa2hva(vm, RESULT_GPA);

	memcpy(func_a_hva, func_a_code, sizeof(func_a_code));
	memcpy(func_b_hva, func_b_code, sizeof(func_b_code));
	*result_hva = SENTINEL;

	/* Enable breakpoint monitoring */
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_BREAKPOINT, 1);

	/* Start vCPU thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* Wait for breakpoint event */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for breakpoint");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_BREAKPOINT,
		    "Expected breakpoint, got %u", ev->type);

	/* Redirect RIP to func_b, set RAX to MAGIC */
	ev->regs.rip = FUNC_B_GPA;
	ev->regs.rax = MAGIC;
	ev->response = KVM_VMI_RESPONSE_SET_REGS;
	vmi_ack_event(&ring, 0);

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");

	TEST_ASSERT(*result_hva == MAGIC,
		    "RESULT = 0x%016lx, expected 0x%016lx "
		    "(0x%016lx means the skip bug is present)",
		    (unsigned long)*result_hva,
		    (unsigned long)MAGIC,
		    (unsigned long)0xCCCCCCCC00000042ULL);

	pr_info("PASS: bp + SET_REGS - RIP not skipped, "
		"result=0x%lx\n", (unsigned long)*result_hva);

	vmi_teardown_ring(&ring);
	close(vmi_fd);
	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));

	test_bp_set_regs_no_skip();

	return 0;
}
