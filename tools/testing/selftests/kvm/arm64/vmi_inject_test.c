// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI event-injection test (arm64)
 *
 * Parks the vCPU on an HVC ring event, injects an exception from the
 * controlling thread, then lets the guest resume and take it. The guest's
 * exception handlers record ESR_EL1/FAR_EL1; the guest asserts the syndrome
 * matches what was injected. Also checks parameter validation.
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

#define SENTINEL_FAR	0x0000beef0000UL

static volatile uint64_t g_esr;
static volatile uint64_t g_far;
static volatile int g_handled;

static void reset_capture(void)
{
	g_esr = 0;
	g_far = 0;
	g_handled = 0;
}

static void sync_handler(struct ex_regs *regs)
{
	g_esr = read_sysreg(esr_el1);
	g_far = read_sysreg(far_el1);
	g_handled = 1;
	/*
	 * No PC fixup: the abort was injected, not caused by a real access.
	 * ELR_EL1 already points at the instruction after the parking HVC,
	 * so ERET resumes normal execution - one-shot, no re-fault loop.
	 */
}

static void serror_handler(struct ex_regs *regs)
{
	g_esr = read_sysreg(esr_el1);
	g_handled = 1;
}

/* Hand control to the agent; the injected exception fires on resume. */
static void guest_park(void)
{
	asm volatile("hvc #0" ::: "memory", "x0", "x1", "x2", "x3",
		     "x4", "x5", "x6", "x7");
}

static void guest_main(void)
{
	/* Case 1: data abort, translation fault, write. */
	reset_capture();
	guest_park();
	GUEST_ASSERT(g_handled);
	GUEST_ASSERT_EQ(ESR_ELx_EC(g_esr), ESR_ELx_EC_DABT_CUR);
	GUEST_ASSERT_EQ(g_esr & ESR_ELx_FSC, ESR_ELx_FSC_FAULT);
	GUEST_ASSERT(g_esr & ESR_ELx_WNR);
	GUEST_ASSERT_EQ(g_far, SENTINEL_FAR);
	GUEST_SYNC(1);

	/* Case 2: instruction abort, translation fault. */
	reset_capture();
	guest_park();
	GUEST_ASSERT(g_handled);
	GUEST_ASSERT_EQ(ESR_ELx_EC(g_esr), ESR_ELx_EC_IABT_CUR);
	GUEST_ASSERT_EQ(g_esr & ESR_ELx_FSC, ESR_ELx_FSC_FAULT);
	GUEST_ASSERT_EQ(g_far, SENTINEL_FAR);
	GUEST_SYNC(2);

	/* Case 3: SError (no syndrome). Unmask PSTATE.A first. */
	reset_capture();
	asm volatile("msr daifclr, #4" ::: "memory");	/* clear A (SError) */
	guest_park();
	GUEST_ASSERT(g_handled);
	GUEST_ASSERT_EQ(ESR_ELx_EC(g_esr), ESR_ELx_EC_SERROR);
	GUEST_SYNC(3);

	GUEST_DONE();
}

static void inject_on_park(struct vmi_test_ring *ring, int vmi_fd,
			   struct kvm_vmi_inject_event *inject)
{
	struct kvm_vmi_ring_event *ev;
	int ret;

	ev = vmi_wait_event_timeout(ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for park HVC");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_HYPERCALL,
		    "Expected HYPERCALL park event, got %u", ev->type);

	ret = vmi_inject_event(vmi_fd, inject);
	TEST_ASSERT(ret == 0, "vmi_inject_event failed: %d", ret);

	ev->response = KVM_VMI_RESPONSE_CONTINUE;
	vmi_ack_event(ring, 0);
}

static void check_validation(int vmi_fd, struct kvm_vcpu *vcpu)
{
	struct kvm_vmi_inject_event inj;
	struct kvm_vcpu_events events = {};

	/* Unknown type. */
	inj = (struct kvm_vmi_inject_event){ .vcpu_id = 0, .type = 0xffff };
	TEST_ASSERT(vmi_inject_event(vmi_fd, &inj) == -EINVAL,
		    "unknown type should be -EINVAL");

	/* Non-zero pad. */
	inj = (struct kvm_vmi_inject_event){
		.vcpu_id = 0, .type = KVM_VMI_INJECT_ABORT,
		.fsc = ESR_ELx_FSC_FAULT, .pad = { 1 } };
	TEST_ASSERT(vmi_inject_event(vmi_fd, &inj) == -EINVAL,
		    "non-zero pad should be -EINVAL");

	/* ABORT with an out-of-set FSC (alignment fault 0x21). */
	inj = (struct kvm_vmi_inject_event){
		.vcpu_id = 0, .type = KVM_VMI_INJECT_ABORT, .fsc = 0x21 };
	TEST_ASSERT(vmi_inject_event(vmi_fd, &inj) == -EINVAL,
		    "bad FSC should be -EINVAL");

	/* ABORT instruction abort with WnR set. */
	inj = (struct kvm_vmi_inject_event){
		.vcpu_id = 0, .type = KVM_VMI_INJECT_ABORT, .iabt = 1,
		.write = 1, .fsc = ESR_ELx_FSC_FAULT };
	TEST_ASSERT(vmi_inject_event(vmi_fd, &inj) == -EINVAL,
		    "iabt + WnR should be -EINVAL");

	/* Unknown vcpu_id (generic ioctl rejects). */
	inj = (struct kvm_vmi_inject_event){
		.vcpu_id = 99, .type = KVM_VMI_INJECT_SERROR };
	TEST_ASSERT(vmi_inject_event(vmi_fd, &inj) == -EINVAL,
		    "unknown vcpu_id should be -EINVAL");

	/* SError syndrome requires RAS; if absent, has_esr must be rejected. */
	vcpu_events_get(vcpu, &events);
	if (!events.exception.serror_has_esr) {
		inj = (struct kvm_vmi_inject_event){
			.vcpu_id = 0, .type = KVM_VMI_INJECT_SERROR,
			.has_esr = 1, .esr = 0x12 };
		TEST_ASSERT(vmi_inject_event(vmi_fd, &inj) == -EINVAL,
			    "has_esr without RAS should be -EINVAL");
	}
}

int main(int argc, char *argv[])
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	struct kvm_vmi_inject_event inj;
	pthread_t thread;
	int vmi_fd;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_RING));

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_main, &ring);

	vm_init_descriptor_tables(vm);
	vcpu_init_descriptor_tables(vcpu);
	vm_install_sync_handler(vm, VECTOR_SYNC_CURRENT,
				ESR_ELx_EC_DABT_CUR, sync_handler);
	vm_install_sync_handler(vm, VECTOR_SYNC_CURRENT,
				ESR_ELx_EC_IABT_CUR, sync_handler);
	vm_install_exception_handler(vm, VECTOR_ERROR_CURRENT, serror_handler);

	check_validation(vmi_fd, vcpu);

	vmi_control_event(vmi_fd, KVM_VMI_EVENT_HYPERCALL, 1);

	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* Case 1: data abort, translation fault, write. */
	inj = (struct kvm_vmi_inject_event){
		.vcpu_id = 0, .type = KVM_VMI_INJECT_ABORT, .iabt = 0,
		.fsc = ESR_ELx_FSC_FAULT, .addr = SENTINEL_FAR, .write = 1 };
	inject_on_park(&ring, vmi_fd, &inj);

	/* Case 2: instruction abort, translation fault. */
	inj = (struct kvm_vmi_inject_event){
		.vcpu_id = 0, .type = KVM_VMI_INJECT_ABORT, .iabt = 1,
		.fsc = ESR_ELx_FSC_FAULT, .addr = SENTINEL_FAR };
	inject_on_park(&ring, vmi_fd, &inj);

	/* Case 3: SError, no syndrome. */
	inj = (struct kvm_vmi_inject_event){
		.vcpu_id = 0, .type = KVM_VMI_INJECT_SERROR };
	inject_on_park(&ring, vmi_fd, &inj);

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");

	vmi_test_teardown(vm, vmi_fd, &ring);
	pr_info("PASS: vmi_inject\n");

	return 0;
}
