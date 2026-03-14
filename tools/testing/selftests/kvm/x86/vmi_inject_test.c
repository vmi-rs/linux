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

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI_INJECT));

	test_inject_error_code_validation();
	test_inject_invalid_params();

	return 0;
}
