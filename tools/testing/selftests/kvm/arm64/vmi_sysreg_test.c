// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI system-register (SYSREG) write monitoring test (arm64)
 *
 * Monitors CONTEXTIDR_EL1 (safe to write: no translation effect) and verifies:
 *   - event delivery with old/new values, CONTINUE applies the write;
 *   - DENY keeps the old value (and proves HCR_EL2.TVM is force-kept: the write
 *     traps even after kvm_toggle_cache ran on the prior trapped write);
 *   - onchangeonly filters same-value writes;
 *   - bitmask filters writes that change no in-mask bit;
 *   - disabling monitoring stops delivery.
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

#define CTX_V1		0x0000AAA0UL	/* low nibble 0 */
#define CTX_V2		0x0000BBB0UL	/* low nibble 0, differs from V1 widely */
#define CTX_OUTMASK	0x0000CBB0UL	/* differs from V2 only outside low nibble */
#define CTX_INMASK	0x0000BBB5UL	/* differs from V2 in the low nibble (bit0/2) */
#define CTX_LAST	0x00001234UL	/* written after monitoring is disabled */
#define MASK_LOWNIB	0xFULL

static void guest_write_ctxid(uint64_t v)
{
	asm volatile("msr contextidr_el1, %0\n\tisb" :: "r"(v) : "memory");
}

static uint64_t guest_read_ctxid(void)
{
	uint64_t v;

	asm volatile("mrs %0, contextidr_el1" : "=r"(v));
	return v;
}

static void guest_sysreg(void)
{
	/* P1: CONTINUE -> new value (V1) sticks. CONTEXTIDR resets to 0. */
	guest_write_ctxid(CTX_V1);
	GUEST_ASSERT_EQ(guest_read_ctxid(), CTX_V1);

	/* P2: write V2, agent DENY -> value stays V1 (and TVM was force-kept). */
	guest_write_ctxid(CTX_V2);
	GUEST_ASSERT_EQ(guest_read_ctxid(), CTX_V1);

	/* P3: onchangeonly. Same-value write (V1) is filtered (no trap/block);
	 * the V2 write traps. CONTINUE -> value becomes V2.
	 */
	guest_write_ctxid(CTX_V1);
	guest_write_ctxid(CTX_V2);
	GUEST_ASSERT_EQ(guest_read_ctxid(), CTX_V2);

	/* P4: bitmask = low nibble. Out-of-mask change is filtered (the write
	 * still applies, so the register becomes CTX_OUTMASK - filtering
	 * suppresses the event, not the write); the in-mask change traps.
	 * CONTINUE -> value becomes CTX_INMASK.
	 */
	guest_write_ctxid(CTX_OUTMASK);
	guest_write_ctxid(CTX_INMASK);
	GUEST_ASSERT_EQ(guest_read_ctxid(), CTX_INMASK);

	/* P5: monitoring disabled -> no event, write applies normally. */
	guest_write_ctxid(CTX_LAST);
	GUEST_ASSERT_EQ(guest_read_ctxid(), CTX_LAST);

	GUEST_DONE();
}

static struct kvm_vmi_ring_event *wait_sysreg(struct vmi_test_ring *ring)
{
	struct kvm_vmi_ring_event *ev = vmi_wait_event_timeout(ring, 5000);

	TEST_ASSERT(ev != NULL, "Timeout waiting for SYSREG event");
	TEST_ASSERT(ev->type == KVM_VMI_EVENT_SYSREG,
		    "Expected SYSREG event, got %u", ev->type);
	TEST_ASSERT(ev->arch.sysreg.reg == KVM_VMI_SYSREG_CONTEXTIDR_EL1,
		    "Expected CONTEXTIDR, got reg %u", ev->arch.sysreg.reg);
	return ev;
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

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_sysreg, &ring);

	/* Negative: out-of-range register index -> EINVAL. */
	{
		struct kvm_vmi_control_event bad = {
			.event = KVM_VMI_EVENT_SYSREG, .enable = 1,
		};
		bad.arch.sysreg.reg = KVM_VMI_NR_SYSREG_MONITORS;
		TEST_ASSERT(ioctl(vmi_fd, KVM_VMI_CONTROL_EVENT, &bad) < 0 &&
			    errno == EINVAL,
			    "Expected EINVAL for out-of-range sysreg index");
	}

	/* Enable CONTEXTIDR monitoring (no filtering for P1/P2). */
	vmi_control_sysreg(vmi_fd, KVM_VMI_SYSREG_CONTEXTIDR_EL1, 0, 0, 1);

	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/* P1: write V1, old == 0 (reset), CONTINUE. */
	ev = wait_sysreg(&ring);
	TEST_ASSERT(ev->arch.sysreg.old_value == 0,
		    "P1 old 0x%llx != 0", ev->arch.sysreg.old_value);
	TEST_ASSERT(ev->arch.sysreg.new_value == CTX_V1,
		    "P1 new 0x%llx != 0x%lx", ev->arch.sysreg.new_value, CTX_V1);
	ev->response = KVM_VMI_RESPONSE_CONTINUE;
	vmi_ack_event(&ring, 0);

	/* P2: write V2, old == V1, DENY. Before ack, switch to onchangeonly
	 * so P3's same-value write is filtered.
	 */
	ev = wait_sysreg(&ring);
	TEST_ASSERT(ev->arch.sysreg.old_value == CTX_V1,
		    "P2 old 0x%llx != 0x%lx", ev->arch.sysreg.old_value, CTX_V1);
	TEST_ASSERT(ev->arch.sysreg.new_value == CTX_V2,
		    "P2 new 0x%llx != 0x%lx", ev->arch.sysreg.new_value, CTX_V2);
	ev->response = KVM_VMI_RESPONSE_DENY;
	vmi_control_sysreg(vmi_fd, KVM_VMI_SYSREG_CONTEXTIDR_EL1, 1, 0, 1);
	vmi_ack_event(&ring, 0);

	/* P3: same-value V1 write filtered (DENY kept V1); the V2 write traps.
	 * old == V1, new == V2. CONTINUE. Before ack, set bitmask = low nibble.
	 */
	ev = wait_sysreg(&ring);
	TEST_ASSERT(ev->arch.sysreg.old_value == CTX_V1,
		    "P3 old 0x%llx != 0x%lx (same-value write not filtered?)",
		    ev->arch.sysreg.old_value, CTX_V1);
	TEST_ASSERT(ev->arch.sysreg.new_value == CTX_V2,
		    "P3 new 0x%llx != 0x%lx", ev->arch.sysreg.new_value, CTX_V2);
	ev->response = KVM_VMI_RESPONSE_CONTINUE;
	vmi_control_sysreg(vmi_fd, KVM_VMI_SYSREG_CONTEXTIDR_EL1, 0,
			   MASK_LOWNIB, 1);
	vmi_ack_event(&ring, 0);

	/* P4: out-of-mask write is filtered but still applies (value now
	 * CTX_OUTMASK); the in-mask write traps. old == CTX_OUTMASK,
	 * new == CTX_INMASK. CONTINUE. Before ack, DISABLE monitoring so P5
	 * delivers nothing.
	 */
	ev = wait_sysreg(&ring);
	TEST_ASSERT(ev->arch.sysreg.old_value == CTX_OUTMASK,
		    "P4 old 0x%llx != 0x%lx (out-of-mask write not filtered?)",
		    ev->arch.sysreg.old_value, CTX_OUTMASK);
	TEST_ASSERT(ev->arch.sysreg.new_value == CTX_INMASK,
		    "P4 new 0x%llx != 0x%lx", ev->arch.sysreg.new_value,
		    CTX_INMASK);
	ev->response = KVM_VMI_RESPONSE_CONTINUE;
	vmi_control_sysreg(vmi_fd, KVM_VMI_SYSREG_CONTEXTIDR_EL1, 0, 0, 0);
	vmi_ack_event(&ring, 0);

	/* P5: monitoring disabled -> no further event. */
	ev = vmi_wait_event_timeout(&ring, 1000);
	TEST_ASSERT(ev == NULL, "Unexpected event after disabling monitoring");

	pthread_join(thread, NULL);
	TEST_ASSERT(targ.done, "Guest should have completed");

	vmi_test_teardown(vm, vmi_fd, &ring);
	pr_info("PASS: vmi_sysreg\n");

	return 0;
}
