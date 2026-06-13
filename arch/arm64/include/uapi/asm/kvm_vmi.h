/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * KVM VMI - arm64-specific uAPI types
 *
 * A fresh, stable ABI modeled on the x86 uAPI
 * (arch/x86/include/uapi/asm/kvm_vmi.h).
 *
 * The generic core (include/uapi/linux/kvm_vmi.h) is reused unchanged and
 * embeds the arch aggregate types by value:
 *   struct kvm_vmi_ring_event    -> struct kvm_vmi_regs,
 *                                   union kvm_vmi_arch_event_data
 *   struct kvm_vmi_control_event -> union kvm_vmi_arch_control_data
 *   KVM_VMI_INJECT_EVENT ioctl   -> struct kvm_vmi_inject_event
 * so those type names must exist for the core to compile. They are declared
 * here and grown as features land (register capture, system-register
 * monitoring, breakpoint monitoring, event injection).
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
#define KVM_VMI_NUM_EVENTS		KVM_VMI_ARCH_EVENT(0)

/*
 * Exception-injection descriptor for the KVM_VMI_INJECT_EVENT ioctl.
 * @vcpu_id is read by the generic ioctl to locate the target vCPU; the
 * remaining fields are added by the event-injection commit.
 */
struct kvm_vmi_inject_event {
	__u32 vcpu_id;
};

/*
 * Register snapshot carried in ring events. Embedded by value in the
 * generic struct kvm_vmi_ring_event, so it must be declared here; its
 * fields are added by the register-capture commit.
 */
struct kvm_vmi_regs {
};

/*
 * Per-event control parameters for arch-specific events. Embedded by
 * value in the generic struct kvm_vmi_control_event; members are added
 * by the system-register monitoring commit.
 */
union kvm_vmi_arch_control_data {
};

union kvm_vmi_arch_event_data {
};

#endif /* _UAPI_ASM_ARM64_KVM_VMI_H */
