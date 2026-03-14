/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * KVM Virtual Machine Introspection - internal kernel header
 */
#ifndef __KVM_VMI_H
#define __KVM_VMI_H

#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/xarray.h>
#include <linux/atomic.h>
#include <linux/wait.h>
#include <linux/kvm_types.h>
#include <uapi/linux/kvm_vmi.h>

struct kvm;
struct kvm_vcpu;
struct eventfd_ctx;

/**
 * struct kvm_vmi - VM-level VMI state
 * @lock: Protects VMI state modifications.
 * @enabled_events: Bitmask of enabled event types (BIT_ULL(KVM_VMI_EVENT_*)).
 * @arch: Architecture-specific VMI monitoring config (CR/MSR).
 */
struct kvm_vmi {
	struct mutex lock;

	/* Event monitoring config (VM-wide) */
	u64 enabled_events;
	struct kvm_arch_vmi arch;
};

/**
 * struct kvm_vcpu_vmi - Per-vCPU VMI state
 * @arch: Architecture-specific per-vCPU VMI state.
 */
struct kvm_vcpu_vmi {
	/* Ring state */
	struct page *ring_page;
	struct kvm_vmi_ring_header *ring;
	struct eventfd_ctx *event_fd_ctx;
	struct eventfd_ctx *ack_fd_ctx;
	struct file *ring_file;
	wait_queue_entry_t ack_wait;	/* Wakeup callback on ack_fd */
	wait_queue_head_t *ack_wqh;	/* ack_fd's waitqueue head */
	wait_queue_head_t wq;

	/* Lifecycle / teardown */
	bool teardown;
	atomic_t pause_count;
	wait_queue_head_t pause_wq;

	/* Architecture-specific per-vCPU VMI state */
	struct kvm_arch_vcpu_vmi arch;

	struct rcu_head rcu_head;	/* Deferred free via call_srcu */
};

#ifdef CONFIG_KVM_VMI

/* Capability */
bool kvm_vmi_has_cap(void);

/* Session lifecycle */
int kvm_create_vmi(struct kvm *kvm);
void kvm_vmi_destroy(struct kvm *kvm);

/* vCPU lifecycle */
int kvm_vmi_vcpu_init(struct kvm_vcpu *vcpu);
void kvm_vmi_vcpu_destroy(struct kvm_vcpu *vcpu);

/* Event delivery */
int kvm_vmi_deliver_via_ring(struct kvm_vcpu *vcpu,
			     struct kvm_vmi_ring_event *event);

/* Pause support (called from vcpu_run) */
bool kvm_vmi_vcpu_paused(struct kvm_vcpu *vcpu);
void kvm_vmi_vcpu_pause_wait(struct kvm_vcpu *vcpu);

/* Per-arch functions (implemented per-arch, not a generic->arch contract) */
void kvm_vmi_capture_regs(struct kvm_vcpu *vcpu, struct kvm_vmi_regs *regs);
void kvm_vmi_restore_regs(struct kvm_vcpu *vcpu, struct kvm_vmi_regs *regs);
void kvm_vmi_handle_event_response(struct kvm_vcpu *vcpu,
				   u32 event_type, u32 resp);

/* Arch callbacks (generic -> arch contract) */
bool kvm_arch_vmi_supported(void);

void kvm_arch_vmi_session_init(struct kvm_vmi *vmi);
void kvm_arch_vmi_session_cleanup(struct kvm_vmi *vmi);
void kvm_arch_vmi_session_reset(struct kvm_vmi *vmi);
void kvm_arch_vmi_reset_vcpu_state(struct kvm_vcpu *vcpu);

int kvm_arch_vmi_control_event(struct kvm *kvm,
			       struct kvm_vmi_control_event *ctrl);
void kvm_arch_vmi_update(struct kvm *kvm);

#else /* !CONFIG_KVM_VMI */

static inline bool kvm_vmi_vcpu_paused(struct kvm_vcpu *vcpu) { return false; }
static inline void kvm_vmi_vcpu_pause_wait(struct kvm_vcpu *vcpu) {}

#endif /* CONFIG_KVM_VMI */

#endif /* __KVM_VMI_H */
