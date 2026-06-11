// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI hypercall (HVC) monitoring test (arm64)
 *
 * Verifies event contents (GP args + HVC imm) and CONTINUE vs DENY
 * semantics. The guest issues HVC with an unrecognized SMCCC function id,
 * so a CONTINUE (SMCCC dispatch runs) returns SMCCC_RET_NOT_SUPPORTED
 * while a DENY (dispatch skipped) leaves x0 unchanged.
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

#define TEST_FID 0xdeadbeefUL
#define TEST_A1	0x1111UL
#define TEST_A2	0x2222UL
#define TEST_A3	0x3333UL
#define SMCCC_NOT_SUPPORTED ((uint64_t)-1)	/* SMCCC_RET_NOT_SUPPORTED */

static uint64_t guest_hvc(uint64_t fid, uint64_t a1, uint64_t a2, uint64_t a3)
{
	register uint64_t x0 asm("x0") = fid;
	register uint64_t x1 asm("x1") = a1;
	register uint64_t x2 asm("x2") = a2;
	register uint64_t x3 asm("x3") = a3;

	asm volatile("hvc #0"
		     : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3)
		     :
		     : "memory", "x4", "x5", "x6", "x7");
	return x0;
}

static void guest_hypercall(void)
{
	uint64_t ret;

	/* Phase 1: agent CONTINUE -> SMCCC dispatch runs -> NOT_SUPPORTED. */
	ret = guest_hvc(TEST_FID, TEST_A1, TEST_A2, TEST_A3);
	GUEST_ASSERT_EQ(ret, SMCCC_NOT_SUPPORTED);
	GUEST_SYNC(1);

	/* Phase 2: agent DENY -> dispatch skipped -> x0 unchanged. */
	ret = guest_hvc(TEST_FID, TEST_A1, TEST_A2, TEST_A3);
	GUEST_ASSERT_EQ(ret, TEST_FID);
	GUEST_DONE();
}

int main(int argc, char *argv[])
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_RING));

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_hypercall, &ring);
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_HYPERCALL, 1);

	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* Phase 1: verify event fields, then CONTINUE. */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for first HVC event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_HYPERCALL,
		    "Expected HYPERCALL event, got %u", ev->type);
	TEST_ASSERT(ev->regs.regs[0] == TEST_FID,
		    "Expected x0 0x%lx, got 0x%llx", TEST_FID, ev->regs.regs[0]);
	TEST_ASSERT(ev->regs.regs[1] == TEST_A1,
		    "Expected x1 0x%lx, got 0x%llx", TEST_A1, ev->regs.regs[1]);
	TEST_ASSERT(ev->regs.regs[2] == TEST_A2,
		    "Expected x2 0x%lx, got 0x%llx", TEST_A2, ev->regs.regs[2]);
	TEST_ASSERT(ev->regs.regs[3] == TEST_A3,
		    "Expected x3 0x%lx, got 0x%llx", TEST_A3, ev->regs.regs[3]);
	TEST_ASSERT(ev->hypercall.imm == 0,
		    "Expected imm 0, got %u", ev->hypercall.imm);

	ev->response = KVM_VMI_RESPONSE_CONTINUE;
	vmi_ack_event(&ring, 0);

	/* Phase 2: DENY the second HVC. */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for second HVC event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_HYPERCALL,
		    "Expected HYPERCALL event");

	ev->response = KVM_VMI_RESPONSE_DENY;
	vmi_ack_event(&ring, 0);

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");

	vmi_test_teardown(vm, vmi_fd, &ring);
	pr_info("PASS: vmi_hypercall\n");

	return 0;
}
