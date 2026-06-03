/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * KVM VMI - arm64-specific uAPI types
 *
 * A fresh ABI modeled on the x86 uAPI
 * (arch/x86/include/uapi/asm/kvm_vmi.h); not derived from the
 * deprecated vmi-rs kvm-arm64 branch.
 *
 * Like the x86 series, every arm64 event ID and its event-data /
 * control / injection members are defined by the commit that implements
 * the feature, never ahead of time. The catch on arm64: the generic
 * core (include/uapi/linux/kvm_vmi.h) is reused unchanged and already
 * embeds the arch aggregate types by value -
 *   struct kvm_vmi_ring_event    -> struct kvm_vmi_regs,
 *                                   union kvm_vmi_arch_event_data
 *   struct kvm_vmi_control_event -> union kvm_vmi_arch_control_data
 *   KVM_VMI_INJECT_EVENT ioctl   -> struct kvm_vmi_inject_event
 * so those type *names* must exist for the core to compile. They are
 * declared here empty and grown by their implementing commits:
 *   - kvm_vmi_regs members:                register capture
 *   - kvm_vmi_arch_event_data /
 *     kvm_vmi_arch_control_data members,
 *     KVM_VMI_EVENT_SYSREG:               system-register monitoring
 *   - KVM_VMI_EVENT_BREAKPOINT:           breakpoint monitoring
 *   - kvm_vmi_inject_event members:       event injection
 */
#ifndef _UAPI_ASM_ARM64_KVM_VMI_H
#define _UAPI_ASM_ARM64_KVM_VMI_H

#include <linux/types.h>
#include <linux/kvm_vmi_events.h>

/*
 * arm64 VMI event types. Generic events (MEM_ACCESS, SINGLESTEP,
 * HYPERCALL) live below KVM_VMI_EVENT_ARCH_BASE; arm64 arch-specific
 * events start at KVM_VMI_ARCH_EVENT(0) and are added by their
 * implementing commits. KVM_VMI_NUM_EVENTS is one past the last.
 */
/* arm64 arch-specific event IDs (start at KVM_VMI_ARCH_EVENT(0) == 8). */
#define KVM_VMI_EVENT_SYSREG		KVM_VMI_ARCH_EVENT(0)	/* = 8 */

/* One past the last defined arm64 event. */
#define KVM_VMI_NUM_EVENTS		KVM_VMI_ARCH_EVENT(1)	/* = 9 */

/*
 * Identifiers for the monitorable EL1 VM system registers, the set routed
 * through access_vm_reg() and trapped by HCR_EL2.TVM. Stable ABI: each value
 * is explicit and never reordered. Used in kvm_vmi_control_event.arch.sysreg.reg
 * and kvm_vmi_event_sysreg.reg.
 */
#define KVM_VMI_SYSREG_SCTLR_EL1	0
#define KVM_VMI_SYSREG_TTBR0_EL1	1
#define KVM_VMI_SYSREG_TTBR1_EL1	2
#define KVM_VMI_SYSREG_TCR_EL1		3
#define KVM_VMI_SYSREG_CONTEXTIDR_EL1	4
#define KVM_VMI_SYSREG_MAIR_EL1		5
#define KVM_VMI_NR_SYSREG_MONITORS	6

/*
 * Register snapshot carried in ring events. Embedded by value in the
 * generic struct kvm_vmi_ring_event, so it must be declared here; its
 * fields are added by the register-capture commit.
 */
struct kvm_vmi_regs {
	/* General-purpose registers, stack pointers, PC, processor state */
	__u64 regs[31];		/* x0..x30 */
	__u64 sp_el0;
	__u64 sp_el1;
	__u64 pc;
	__u64 pstate;

	/* Translation / control system registers */
	__u64 ttbr0_el1;
	__u64 ttbr1_el1;
	__u64 tcr_el1;
	__u64 sctlr_el1;
	__u64 mair_el1;
	__u64 vbar_el1;
	__u64 contextidr_el1;

	/* Exception / thread-context system registers */
	__u64 elr_el1;
	__u64 spsr_el1;
	__u64 esr_el1;
	__u64 far_el1;
	__u64 tpidr_el0;
	__u64 tpidr_el1;
	__u64 tpidrro_el0;
};

/*
 * Per-event control parameters for arch-specific events. Embedded by
 * value in the generic struct kvm_vmi_control_event; members are added
 * by the system-register monitoring commit.
 */
union kvm_vmi_arch_control_data {
	struct {
		__u8  reg;		/* KVM_VMI_SYSREG_* to monitor */
		__u8  onchangeonly;	/* 1 = skip writes that don't change the value */
		__u8  pad[6];
		__u64 bitmask;		/* 0 = any change fires; else fire iff
					 * ((old ^ new) & bitmask) != 0 */
	} sysreg;
};

/*
 * Per-event payloads for arch-specific events. Embedded by value in the
 * generic struct kvm_vmi_ring_event; members are added by the
 * sysreg-write and breakpoint commits.
 */
/* KVM_VMI_EVENT_SYSREG payload (delivered as ring_event.arch.sysreg). */
struct kvm_vmi_event_sysreg {
	__u32 reg;		/* KVM_VMI_SYSREG_* that was written */
	__u32 pad;
	__u64 old_value;	/* value before the (deferred) write */
	__u64 new_value;	/* value the guest is writing (observe-only) */
};

union kvm_vmi_arch_event_data {
	struct kvm_vmi_event_sysreg sysreg;
};

/* kvm_vmi_inject_event.type */
#define KVM_VMI_INJECT_SERROR	0	/* asynchronous SError (virtual SError) */
#define KVM_VMI_INJECT_ABORT	1	/* synchronous abort to EL1 (FSC + FAR) */

/*
 * Exception-injection descriptor for the KVM_VMI_INJECT_EVENT ioctl.
 * @vcpu_id is read by the generic ioctl to locate the target vCPU.
 *
 * @type    KVM_VMI_INJECT_*.
 * @addr    ABORT: faulting VA written to FAR_EL1.
 * @esr     SERROR: ISS/syndrome bits, valid iff @has_esr (requires RAS).
 * @iabt    ABORT: 1 = instruction abort, 0 = data abort.
 * @has_esr SERROR: @esr is valid.
 * @fsc     ABORT: fault status code (ESR_ELx_FSC_*; e.g. translation FAULT
 *          for the demand-paging / x86 #PF analog).
 * @write   ABORT data abort: WnR - write fault (1) vs read fault (0).
 * @pad     must be zero.
 */
struct kvm_vmi_inject_event {
	__u32 vcpu_id;
	__u32 type;
	__u64 addr;
	__u64 esr;
	__u8  iabt;
	__u8  has_esr;
	__u8  fsc;
	__u8  write;
	__u8  pad[4];
};

#endif /* _UAPI_ASM_ARM64_KVM_VMI_H */
