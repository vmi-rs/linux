// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI event injection test
 *
 * Tests KVM_VMI_INJECT_EVENT ioctl for injecting hardware exceptions,
 * software exceptions, software interrupts, external interrupts, and
 * NMIs into a guest via vmi_fd while the vCPU is blocked on a ring event.
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

/*
 * GP_VECTOR (13) is defined in <uapi/asm/kvm.h>.
 * NMI_VECTOR (0x02) is defined in "processor.h".
 */

#define UD_VECTOR	6
#define PF_VECTOR	14
#define BP_VECTOR	3
#define OF_VECTOR	4
#define SW_INT_VECTOR	0x80

/* ---- Guest code for #GP injection test ---- */

static volatile uint64_t gp_count;

static void guest_gp_handler(struct ex_regs *regs)
{
	gp_count++;
	regs->rip += 2; /* Skip past 2-byte CPUID (0F A2) */
}

static void guest_cpuid_inject_gp(void)
{
	uint32_t eax, ebx, ecx, edx;

	gp_count = 0;
	GUEST_SYNC(1);

	/* CPUID will be intercepted; host injects #GP before resuming */
	__asm__ __volatile__("cpuid"
		: "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
		: "a"(0), "c"(0));

	GUEST_ASSERT(gp_count == 1);
	GUEST_DONE();
}

/* ---- Guest code for NMI injection test ---- */

static volatile uint64_t nmi_count;

static void guest_nmi_handler(struct ex_regs *regs)
{
	nmi_count++;
}

static void guest_cpuid_inject_nmi(void)
{
	uint32_t eax, ebx, ecx, edx;

	nmi_count = 0;
	GUEST_SYNC(1);

	/* CPUID will be intercepted; host injects NMI before resuming */
	__asm__ __volatile__("cpuid"
		: "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
		: "a"(0), "c"(0));

	GUEST_ASSERT(nmi_count == 1);
	GUEST_DONE();
}

/* ---- Guest code for software interrupt injection test ---- */

static volatile uint64_t sw_int_count;

static void guest_sw_int_handler(struct ex_regs *regs)
{
	sw_int_count++;
}

/*
 * SW_INT injection via VMCS adds insn_len to the return address.
 * After CPUID emulation advances RIP, the SW_INT handler returns to
 * RIP + insn_len. We pad with 2 NOPs (insn_len=2) so the return
 * lands at the correct instruction after the padding.
 */
static void guest_cpuid_inject_sw_int(void)
{
	uint32_t eax, ebx, ecx, edx;

	sw_int_count = 0;
	GUEST_SYNC(1);

	/* STI enables IF before CPUID so SW_INT injection can succeed */
	__asm__ __volatile__("sti\n\t"
		"cpuid\n\t"
		"nop\n\t"
		"nop"
		: "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
		: "a"(0), "c"(0));

	GUEST_ASSERT(sw_int_count == 1);
	GUEST_DONE();
}

/* ---- Guest code for external interrupt injection test ---- */

static volatile uint64_t ext_int_count;

static void guest_ext_int_handler(struct ex_regs *regs)
{
	ext_int_count++;
}

/*
 * EXT_INT does not add insn_len to the return address, so no NOP
 * padding is needed.
 */
static void guest_cpuid_inject_ext_int(void)
{
	uint32_t eax, ebx, ecx, edx;

	ext_int_count = 0;
	GUEST_SYNC(1);

	/* EXT_INT injection requires RFLAGS.IF=1 (Intel SDM 26.3.1.4) */
	__asm__ __volatile__("sti\n\t"
		"cpuid"
		: "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
		: "a"(0), "c"(0));

	GUEST_ASSERT(ext_int_count == 1);
	GUEST_DONE();
}


/* ---- Guest code for #BP injection test ---- */

static volatile uint64_t bp_count;

static void guest_bp_handler(struct ex_regs *regs)
{
	bp_count++;
}

/*
 * SW_EXCEPT (#BP) injection also adds insn_len to the return address.
 * Pad with 1 NOP for insn_len=1 (matching the 0xCC INT3 encoding).
 */
static void guest_cpuid_inject_bp(void)
{
	uint32_t eax, ebx, ecx, edx;

	bp_count = 0;
	GUEST_SYNC(1);

	__asm__ __volatile__("cpuid\n\t"
		"nop"
		: "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
		: "a"(0), "c"(0));

	GUEST_ASSERT(bp_count == 1);
	GUEST_DONE();
}

/*
 * Test 1: Inject #GP(0) while vCPU is blocked on a CPUID ring event.
 *
 * Flow:
 * 1. Guest executes CPUID -> ring event, vCPU blocked in kernel
 * 2. Host reads event from ring
 * 3. Host injects #GP(0) via KVM_VMI_INJECT_EVENT
 * 4. Host acks the ring event with CONTINUE (don't emulate CPUID)
 * 5. vCPU resumes, #GP fires, guest handler increments gp_count and skips
 * 6. Guest asserts gp_count == 1, then GUEST_DONE
 */
static void test_inject_gp(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	struct kvm_vmi_inject_event ie = {};
	int vmi_fd, ret;

	vm = vm_create_with_one_vcpu(&vcpu, guest_cpuid_inject_gp);
	vm_install_exception_handler(vm, GP_VECTOR, guest_gp_handler);

	vmi_fd = vmi_create(vm);
	vmi_setup_ring(vmi_fd, 0, &ring);

	/* Enable CPUID monitoring */
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_CPUID, 1);

	/* Start vCPU thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* Wait for CPUID event */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for CPUID event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_CPUID,
		    "Expected CPUID event, got %u", ev->type);

	/* Inject #GP(0) while vCPU is blocked */
	ie.vcpu_id = 0;
	ie.vector = GP_VECTOR;
	ie.type = KVM_VMI_EVENT_TYPE_HW_EXCEPT;
	ie.has_error = 1;
	ie.error_code = 0;

	ret = ioctl(vmi_fd, KVM_VMI_INJECT_EVENT, &ie);
	TEST_ASSERT(ret == 0,
		    "KVM_VMI_INJECT_EVENT (#GP) failed: %d (errno=%d)",
		    ret, errno);

	/*
	 * Ack with CONTINUE (don't emulate). The #GP fires at the
	 * CPUID RIP. The guest handler skips past CPUID (rip += 2).
	 */
	ev->response = KVM_VMI_RESPONSE_CONTINUE;
	vmi_ack_event(&ring, 0);

	/* Guest should see #GP, increment counter, skip CPUID, then DONE */
	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done,
		    "Guest should have completed after #GP injection");

	vmi_teardown_ring(&ring);
	close(vmi_fd);
	kvm_vm_free(vm);
	pr_info("PASS: test_inject_gp\n");
}

/*
 * Test 2: Validate error code enforcement for HW_EXCEPT.
 *
 * - #GP (vector 13) MUST have has_error=1
 * - #UD (vector 6) MUST have has_error=0
 * - #PF (vector 14) MUST have has_error=1
 * - Mismatched has_error should fail with -EINVAL
 */
static void test_inject_error_code_validation(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct kvm_vmi_inject_event ie = {};
	int vmi_fd, ret;

	vm = vm_create_with_one_vcpu(&vcpu, guest_cpuid_inject_gp);
	vmi_fd = vmi_create(vm);

	/* #GP without error code should fail */
	ie.vcpu_id = 0;
	ie.vector = GP_VECTOR;
	ie.type = KVM_VMI_EVENT_TYPE_HW_EXCEPT;
	ie.has_error = 0;

	ret = ioctl(vmi_fd, KVM_VMI_INJECT_EVENT, &ie);
	TEST_ASSERT(ret == -1 && errno == EINVAL,
		    "#GP without error code should fail, got ret=%d errno=%d",
		    ret, errno);

	/* #UD with error code should fail */
	memset(&ie, 0, sizeof(ie));
	ie.vcpu_id = 0;
	ie.vector = UD_VECTOR;
	ie.type = KVM_VMI_EVENT_TYPE_HW_EXCEPT;
	ie.has_error = 1;
	ie.error_code = 0;

	ret = ioctl(vmi_fd, KVM_VMI_INJECT_EVENT, &ie);
	TEST_ASSERT(ret == -1 && errno == EINVAL,
		    "#UD with error code should fail, got ret=%d errno=%d",
		    ret, errno);

	/* #PF without error code should fail */
	memset(&ie, 0, sizeof(ie));
	ie.vcpu_id = 0;
	ie.vector = PF_VECTOR;
	ie.type = KVM_VMI_EVENT_TYPE_HW_EXCEPT;
	ie.has_error = 0;

	ret = ioctl(vmi_fd, KVM_VMI_INJECT_EVENT, &ie);
	TEST_ASSERT(ret == -1 && errno == EINVAL,
		    "#PF without error code should fail, got ret=%d errno=%d",
		    ret, errno);

	/* #UD without error code should succeed (no ring needed for queue) */
	memset(&ie, 0, sizeof(ie));
	ie.vcpu_id = 0;
	ie.vector = UD_VECTOR;
	ie.type = KVM_VMI_EVENT_TYPE_HW_EXCEPT;
	ie.has_error = 0;

	ret = ioctl(vmi_fd, KVM_VMI_INJECT_EVENT, &ie);
	TEST_ASSERT(ret == 0,
		    "#UD without error code should succeed, got ret=%d errno=%d",
		    ret, errno);

	/* HW_EXCEPT with insn_len != 0 should fail */
	memset(&ie, 0, sizeof(ie));
	ie.vcpu_id = 0;
	ie.vector = UD_VECTOR;
	ie.type = KVM_VMI_EVENT_TYPE_HW_EXCEPT;
	ie.has_error = 0;
	ie.insn_len = 1;

	ret = ioctl(vmi_fd, KVM_VMI_INJECT_EVENT, &ie);
	TEST_ASSERT(ret == -1 && errno == EINVAL,
		    "HW_EXCEPT with insn_len should fail, got ret=%d errno=%d",
		    ret, errno);

	close(vmi_fd);
	kvm_vm_free(vm);
	pr_info("PASS: test_inject_error_code_validation\n");
}

/*
 * Test 3: Invalid injection types/parameters should fail.
 *
 * - PRIV_SW_INT (type 5) returns -EOPNOTSUPP
 * - Invalid type (type 7) returns -EINVAL
 * - SW_INT without insn_len returns -EINVAL
 * - SW_EXCEPT with wrong vector returns -EINVAL
 */
static void test_inject_invalid_params(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct kvm_vmi_inject_event ie = {};
	int vmi_fd, ret;

	vm = vm_create_with_one_vcpu(&vcpu, guest_cpuid_inject_gp);
	vmi_fd = vmi_create(vm);

	/* PRIV_SW_INT should fail with EOPNOTSUPP */
	ie.vcpu_id = 0;
	ie.vector = 1;
	ie.type = KVM_VMI_EVENT_TYPE_PRIV_SW_INT;
	ie.insn_len = 1;

	ret = ioctl(vmi_fd, KVM_VMI_INJECT_EVENT, &ie);
	TEST_ASSERT(ret == -1 && errno == EOPNOTSUPP,
		    "PRIV_SW_INT should fail with EOPNOTSUPP, got ret=%d errno=%d",
		    ret, errno);

	/* Invalid type 7 should fail with EINVAL */
	memset(&ie, 0, sizeof(ie));
	ie.vcpu_id = 0;
	ie.vector = 0;
	ie.type = 7;

	ret = ioctl(vmi_fd, KVM_VMI_INJECT_EVENT, &ie);
	TEST_ASSERT(ret == -1 && errno == EINVAL,
		    "Invalid type should fail with EINVAL, got ret=%d errno=%d",
		    ret, errno);

	/* SW_INT without insn_len should fail */
	memset(&ie, 0, sizeof(ie));
	ie.vcpu_id = 0;
	ie.vector = SW_INT_VECTOR;
	ie.type = KVM_VMI_EVENT_TYPE_SW_INT;
	ie.insn_len = 0;

	ret = ioctl(vmi_fd, KVM_VMI_INJECT_EVENT, &ie);
	TEST_ASSERT(ret == -1 && errno == EINVAL,
		    "SW_INT without insn_len should fail, got ret=%d errno=%d",
		    ret, errno);

	/* SW_INT with insn_len > 15 should fail */
	memset(&ie, 0, sizeof(ie));
	ie.vcpu_id = 0;
	ie.vector = SW_INT_VECTOR;
	ie.type = KVM_VMI_EVENT_TYPE_SW_INT;
	ie.insn_len = 16;

	ret = ioctl(vmi_fd, KVM_VMI_INJECT_EVENT, &ie);
	TEST_ASSERT(ret == -1 && errno == EINVAL,
		    "SW_INT with insn_len=16 should fail, got ret=%d errno=%d",
		    ret, errno);

	/* SW_EXCEPT with vector != 3 and != 4 should fail */
	memset(&ie, 0, sizeof(ie));
	ie.vcpu_id = 0;
	ie.vector = GP_VECTOR;
	ie.type = KVM_VMI_EVENT_TYPE_SW_EXCEPT;
	ie.insn_len = 1;

	ret = ioctl(vmi_fd, KVM_VMI_INJECT_EVENT, &ie);
	TEST_ASSERT(ret == -1 && errno == EINVAL,
		    "SW_EXCEPT with GP vector should fail, got ret=%d errno=%d",
		    ret, errno);

	/* SW_EXCEPT with has_error should fail */
	memset(&ie, 0, sizeof(ie));
	ie.vcpu_id = 0;
	ie.vector = BP_VECTOR;
	ie.type = KVM_VMI_EVENT_TYPE_SW_EXCEPT;
	ie.insn_len = 1;
	ie.has_error = 1;

	ret = ioctl(vmi_fd, KVM_VMI_INJECT_EVENT, &ie);
	TEST_ASSERT(ret == -1 && errno == EINVAL,
		    "SW_EXCEPT with has_error should fail, got ret=%d errno=%d",
		    ret, errno);

	/* NMI with insn_len != 0 should fail */
	memset(&ie, 0, sizeof(ie));
	ie.vcpu_id = 0;
	ie.vector = NMI_VECTOR;
	ie.type = KVM_VMI_EVENT_TYPE_NMI;
	ie.insn_len = 1;

	ret = ioctl(vmi_fd, KVM_VMI_INJECT_EVENT, &ie);
	TEST_ASSERT(ret == -1 && errno == EINVAL,
		    "NMI with insn_len should fail, got ret=%d errno=%d",
		    ret, errno);

	/* EXT_INT with insn_len != 0 should fail */
	memset(&ie, 0, sizeof(ie));
	ie.vcpu_id = 0;
	ie.vector = 32;
	ie.type = KVM_VMI_EVENT_TYPE_EXT_INT;
	ie.insn_len = 1;

	ret = ioctl(vmi_fd, KVM_VMI_INJECT_EVENT, &ie);
	TEST_ASSERT(ret == -1 && errno == EINVAL,
		    "EXT_INT with insn_len should fail, got ret=%d errno=%d",
		    ret, errno);

	/*
	 * EXT_INT with IF=0 should fail with EBUSY.
	 * The selftest guest starts with IF=0, so this should fail.
	 */
	memset(&ie, 0, sizeof(ie));
	ie.vcpu_id = 0;
	ie.vector = 32;
	ie.type = KVM_VMI_EVENT_TYPE_EXT_INT;

	ret = ioctl(vmi_fd, KVM_VMI_INJECT_EVENT, &ie);
	TEST_ASSERT(ret == -1 && errno == EBUSY,
		    "EXT_INT with IF=0 should fail with EBUSY, got ret=%d errno=%d",
		    ret, errno);

	close(vmi_fd);
	kvm_vm_free(vm);
	pr_info("PASS: test_inject_invalid_params\n");
}

/*
 * Test 4: Inject NMI while vCPU is blocked on a CPUID ring event.
 */
static void test_inject_nmi(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	struct kvm_vmi_inject_event ie = {};
	int vmi_fd, ret;

	vm = vm_create_with_one_vcpu(&vcpu, guest_cpuid_inject_nmi);
	vm_install_exception_handler(vm, NMI_VECTOR, guest_nmi_handler);

	vmi_fd = vmi_create(vm);
	vmi_setup_ring(vmi_fd, 0, &ring);

	/* Enable CPUID monitoring */
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_CPUID, 1);

	/* Start vCPU thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* Wait for CPUID event */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for CPUID event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_CPUID,
		    "Expected CPUID event, got %u", ev->type);

	/* Inject NMI while vCPU is blocked */
	ie.vcpu_id = 0;
	ie.vector = NMI_VECTOR;
	ie.type = KVM_VMI_EVENT_TYPE_NMI;

	ret = ioctl(vmi_fd, KVM_VMI_INJECT_EVENT, &ie);
	TEST_ASSERT(ret == 0,
		    "KVM_VMI_INJECT_EVENT (NMI) failed: %d (errno=%d)",
		    ret, errno);

	/* Ack the CPUID event with EMULATE */
	ev->response = KVM_VMI_RESPONSE_EMULATE;
	vmi_ack_event(&ring, 0);

	/* Guest should see NMI, increment counter, then DONE */
	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done,
		    "Guest should have completed after NMI injection");

	vmi_teardown_ring(&ring);
	close(vmi_fd);
	kvm_vm_free(vm);
	pr_info("PASS: test_inject_nmi\n");
}

/*
 * Test 5: Inject software interrupt (INT 0x80) while vCPU is blocked.
 *
 * SW_INT injection via VMCS uses INTR_TYPE_SOFT_INTR which adds insn_len
 * to the return address pushed on the stack. The guest code has 2 NOP bytes
 * after CPUID to absorb the insn_len=2 offset.
 */
static void test_inject_sw_int(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	struct kvm_vmi_inject_event ie = {};
	int vmi_fd, ret;

	vm = vm_create_with_one_vcpu(&vcpu, guest_cpuid_inject_sw_int);
	vm_install_exception_handler(vm, SW_INT_VECTOR, guest_sw_int_handler);

	vmi_fd = vmi_create(vm);
	vmi_setup_ring(vmi_fd, 0, &ring);

	/* Enable CPUID monitoring */
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_CPUID, 1);

	/* Start vCPU thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* Wait for CPUID event */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for CPUID event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_CPUID,
		    "Expected CPUID event, got %u", ev->type);

	/* Inject INT 0x80 with insn_len=2 (matching 2 NOPs in guest code) */
	ie.vcpu_id = 0;
	ie.vector = SW_INT_VECTOR;
	ie.type = KVM_VMI_EVENT_TYPE_SW_INT;
	ie.insn_len = 2;

	ret = ioctl(vmi_fd, KVM_VMI_INJECT_EVENT, &ie);
	TEST_ASSERT(ret == 0,
		    "KVM_VMI_INJECT_EVENT (SW_INT) failed: %d (errno=%d)",
		    ret, errno);

	/* Ack the CPUID event with EMULATE */
	ev->response = KVM_VMI_RESPONSE_EMULATE;
	vmi_ack_event(&ring, 0);

	/* Guest should see INT 0x80 fire, then DONE */
	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done,
		    "Guest should have completed after SW_INT injection");

	vmi_teardown_ring(&ring);
	close(vmi_fd);
	kvm_vm_free(vm);
	pr_info("PASS: test_inject_sw_int\n");
}

/*
 * Test 6: Inject external interrupt while vCPU is blocked.
 *
 * EXT_INT uses INTR_TYPE_EXT_INTR which does NOT add insn_len to the
 * return address, so no NOP padding is needed.
 */
static void test_inject_ext_int(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	struct kvm_vmi_inject_event ie = {};
	int vmi_fd, ret;
	uint8_t vector = SW_INT_VECTOR;

	vm = vm_create_with_one_vcpu(&vcpu, guest_cpuid_inject_ext_int);
	vm_install_exception_handler(vm, vector, guest_ext_int_handler);

	vmi_fd = vmi_create(vm);
	vmi_setup_ring(vmi_fd, 0, &ring);

	/* Enable CPUID monitoring */
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_CPUID, 1);

	/* Start vCPU thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* Wait for CPUID event */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for CPUID event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_CPUID,
		    "Expected CPUID event, got %u", ev->type);

	/* Inject external interrupt (no insn_len needed) */
	ie.vcpu_id = 0;
	ie.vector = vector;
	ie.type = KVM_VMI_EVENT_TYPE_EXT_INT;

	ret = ioctl(vmi_fd, KVM_VMI_INJECT_EVENT, &ie);
	TEST_ASSERT(ret == 0,
		    "KVM_VMI_INJECT_EVENT (EXT_INT) failed: %d (errno=%d)",
		    ret, errno);

	/* Ack the CPUID event with EMULATE */
	ev->response = KVM_VMI_RESPONSE_EMULATE;
	vmi_ack_event(&ring, 0);

	/* Guest should see the interrupt, then DONE */
	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done,
		    "Guest should have completed after EXT_INT injection");

	vmi_teardown_ring(&ring);
	close(vmi_fd);
	kvm_vm_free(vm);
	pr_info("PASS: test_inject_ext_int\n");
}

/*
 * Test 7: Inject #BP (software exception) with insn_len=1.
 *
 * SW_EXCEPT injection adds insn_len to the return address (same as SW_INT).
 * The guest has 1 NOP after CPUID to absorb the offset.
 */
static void test_inject_sw_except_bp(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	struct kvm_vmi_inject_event ie = {};
	int vmi_fd, ret;

	vm = vm_create_with_one_vcpu(&vcpu, guest_cpuid_inject_bp);
	vm_install_exception_handler(vm, BP_VECTOR, guest_bp_handler);

	vmi_fd = vmi_create(vm);
	vmi_setup_ring(vmi_fd, 0, &ring);

	/* Enable CPUID monitoring */
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_CPUID, 1);

	/* Start vCPU thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* Wait for CPUID event */
	ev = vmi_wait_event_timeout(&ring, 5000);
	TEST_ASSERT(ev != NULL, "Timeout waiting for CPUID event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_CPUID,
		    "Expected CPUID event, got %u", ev->type);

	/* Inject #BP (SW_EXCEPT, vector 3, insn_len=1) */
	ie.vcpu_id = 0;
	ie.vector = BP_VECTOR;
	ie.type = KVM_VMI_EVENT_TYPE_SW_EXCEPT;
	ie.insn_len = 1;

	ret = ioctl(vmi_fd, KVM_VMI_INJECT_EVENT, &ie);
	TEST_ASSERT(ret == 0,
		    "KVM_VMI_INJECT_EVENT (SW_EXCEPT #BP) failed: %d (errno=%d)",
		    ret, errno);

	/* Ack the CPUID event with EMULATE */
	ev->response = KVM_VMI_RESPONSE_EMULATE;
	vmi_ack_event(&ring, 0);

	/* Guest should see #BP, then DONE */
	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done,
		    "Guest should have completed after #BP injection");

	vmi_teardown_ring(&ring);
	close(vmi_fd);
	kvm_vm_free(vm);
	pr_info("PASS: test_inject_sw_except_bp\n");
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_INJECT));

	test_inject_gp();
	test_inject_error_code_validation();
	test_inject_invalid_params();
	test_inject_nmi();
	test_inject_ext_int();
	test_inject_sw_except_bp();
	test_inject_sw_int();

	return 0;
}
