/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * KVM VMI Event ID definitions
 *
 * Separated from kvm_vmi.h so that arch-specific headers
 * (asm/kvm_vmi.h) can include this without circular dependencies.
 */
#ifndef _UAPI_LINUX_KVM_VMI_EVENTS_H
#define _UAPI_LINUX_KVM_VMI_EVENTS_H

/*
 * Generic VMI Event Types (arch-independent)
 *
 * Arch-specific events (CR, MSR, CPUID, etc.) are defined in
 * <asm/kvm_vmi.h> starting at KVM_VMI_EVENT_ARCH_BASE.
 */
#define KVM_VMI_EVENT_MEM_ACCESS	0  /* EPT/stage-2 violation with VMI permissions */

/*
 * Base for arch-specific event IDs. Arch headers use KVM_VMI_ARCH_EVENT(nr)
 * to define event IDs relative to this base.
 */
#define KVM_VMI_EVENT_ARCH_BASE		8
#define KVM_VMI_ARCH_EVENT(nr)		((nr) + KVM_VMI_EVENT_ARCH_BASE)

#endif /* _UAPI_LINUX_KVM_VMI_EVENTS_H */
