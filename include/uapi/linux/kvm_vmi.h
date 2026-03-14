/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * KVM Virtual Machine Introspection (VMI) uAPI
 *
 * Provides userspace interfaces for virtual machine introspection,
 * including event monitoring and alternate memory views.
 *
 * Events are delivered via per-vCPU ring buffers.
 * A vmi_fd (from KVM_CREATE_VMI) serves as the control plane.
 *
 * Generic event IDs occupy range 0 to KVM_VMI_EVENT_ARCH_BASE-1.
 * Arch-specific event IDs start at KVM_VMI_EVENT_ARCH_BASE and
 * are defined in <asm/kvm_vmi.h>.
 */
#ifndef _UAPI_LINUX_KVM_VMI_H
#define _UAPI_LINUX_KVM_VMI_H

#include <linux/types.h>
#include <linux/kvm_vmi_events.h>
#include <asm/kvm_vmi.h>

/**
 * struct kvm_vmi_control_event - VM-wide event monitoring control
 * @event: Event type (KVM_VMI_EVENT_*)
 * @enable: 1 to enable, 0 to disable
 */
struct kvm_vmi_control_event {
	__u32 event;
	__u32 enable;
};

/**
 * struct kvm_vmi_vcpu - Generic vCPU identifier for vmi_fd ioctls
 */
struct kvm_vmi_vcpu {
	__u32 vcpu_id;
	__u32 pad;
};

#endif /* _UAPI_LINUX_KVM_VMI_H */
