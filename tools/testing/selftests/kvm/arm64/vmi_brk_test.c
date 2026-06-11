// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI breakpoint (BRK) monitoring test (arm64)
 *
 * Verifies: BRK -> KVM_VMI_EVENT_BREAKPOINT with ipa+imm+insn_len; the
 * kernel never auto-advances PC (CONTINUE re-traps the same BRK); SET_REGS
 * (PC+=4) skips; disabling delivers BRK to the guest's own handler; and
 * REINJECT delivers BRK to the guest's handler.
 *
 * Guest-debug neutralization (VCPU_DEBUG_HOST_OWNED while monitoring, see
 * debug.c) is relied on by the coarse-TDE design but is not directly asserted
 * here; the disable and REINJECT paths exercise guest-owned BRK delivery.
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

#define BRK_IMM 0x5

static void guest_brk(void)
{
	GUEST_SYNC(1);
	asm volatile("brk #0x5");
	GUEST_SYNC(2);
	asm volatile("brk #0x5");
	GUEST_SYNC(3);
	GUEST_DONE();
}

/* Guest BRK handler: skip the 4-byte BRK so the guest can continue. */
static void guest_brk_handler(struct ex_regs *regs)
{
	regs->pc += 4;
}

/* Basic: event fields, CONTINUE re-traps (no auto-advance), SET_REGS skips. */
static void test_brk_basic(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	uint64_t first_pc;
	int vmi_fd;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_brk, &ring);
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_BREAKPOINT, 1);

	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* First BRK: validate fields. */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for first BRK event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_BREAKPOINT,
		    "Expected breakpoint, got %u", ev->type);
	TEST_ASSERT(ev->insn_len == 4, "BRK is 4 bytes, got %u", ev->insn_len);
	TEST_ASSERT(ev->arch.breakpoint.imm == BRK_IMM,
		    "Expected imm 0x%x, got 0x%x", BRK_IMM, ev->arch.breakpoint.imm);
	TEST_ASSERT(ev->arch.breakpoint.ipa != 0,
		    "Expected nonzero BRK ipa");
	first_pc = ev->regs.pc;

	/* CONTINUE (no SET_REGS): kernel must NOT advance PC -> same BRK re-traps. */
	ev->response = KVM_VMI_RESPONSE_CONTINUE;
	vmi_ack_event(&ring, 0);

	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for re-trap after CONTINUE");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_BREAKPOINT, "Expected breakpoint re-trap");
	TEST_ASSERT(ev->regs.pc == first_pc,
		    "CONTINUE must re-trap same PC: was 0x%lx now 0x%llx",
		    first_pc, ev->regs.pc);

	/* Now skip past it via SET_REGS (PC += 4). */
	ev->regs.pc += 4;
	ev->response = KVM_VMI_RESPONSE_SET_REGS;
	vmi_ack_event(&ring, 0);

	/* Second BRK: skip it too. */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for second BRK event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_BREAKPOINT, "Expected breakpoint");
	ev->regs.pc += 4;
	ev->response = KVM_VMI_RESPONSE_SET_REGS;
	vmi_ack_event(&ring, 0);

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");
	vmi_test_teardown(vm, vmi_fd, &ring);
	pr_info("PASS: vmi_brk basic (fields, CONTINUE re-traps, SET_REGS skips)\n");
}

/* Disable -> the next BRK is delivered to the guest's own handler. */
static void test_brk_disable(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_brk, &ring);
	vm_init_descriptor_tables(vm);
	vcpu_init_descriptor_tables(vcpu);
	vm_install_sync_handler(vm, VECTOR_SYNC_CURRENT, ESR_ELx_EC_BRK64,
				guest_brk_handler);
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_BREAKPOINT, 1);

	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* First BRK -> VMI event. The vCPU is now parked on this event. */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for BRK event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_BREAKPOINT, "Expected breakpoint");

	/*
	 * Disable monitoring while the vCPU is parked on this event. This avoids
	 * a race: if we disabled only after resuming, the guest could reach the
	 * second BRK while monitoring was still enabled, delivering an event with
	 * no waiter (the test has moved on to join) and blocking the vCPU forever.
	 * Disabling now clears enabled_events and queues the MDCR_EL2.TDE clear
	 * (KVM_REQ_VMI_UPDATE), both of which take effect before the resumed guest
	 * reaches the second BRK -- so it is delivered to the guest's own handler.
	 */
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_BREAKPOINT, 0);

	/* Resume past the first BRK; the second BRK now hits the guest handler. */
	ev->regs.pc += 4;
	ev->response = KVM_VMI_RESPONSE_SET_REGS;
	vmi_ack_event(&ring, 0);

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should complete after disabling BRK monitoring");
	vmi_test_teardown(vm, vmi_fd, &ring);
	pr_info("PASS: vmi_brk disable -> guest handler\n");
}

/* REINJECT -> the guest's own BRK handler fires. */
static void test_brk_reinject(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd, i;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_brk, &ring);
	vm_init_descriptor_tables(vm);
	vcpu_init_descriptor_tables(vcpu);
	vm_install_sync_handler(vm, VECTOR_SYNC_CURRENT, ESR_ELx_EC_BRK64,
				guest_brk_handler);
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_BREAKPOINT, 1);

	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	for (i = 0; i < 2; i++) {
		ev = vmi_wait_event_timeout(&ring, 5000);
		TEST_ASSERT(ev != NULL, "Timeout waiting for BRK event %d", i);
		TEST_ASSERT(ev->type == KVM_VMI_EVENT_BREAKPOINT, "Expected breakpoint");
		ev->response = KVM_VMI_RESPONSE_REINJECT;
		vmi_ack_event(&ring, 0);
	}

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should complete with reinjected BRK");
	vmi_test_teardown(vm, vmi_fd, &ring);
	pr_info("PASS: vmi_brk REINJECT -> guest handler\n");
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_RING));

	test_brk_basic();
	test_brk_disable();
	test_brk_reinject();

	return 0;
}
