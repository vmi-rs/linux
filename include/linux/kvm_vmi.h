/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * KVM Virtual Machine Introspection - internal kernel header
 */
#ifndef __KVM_VMI_H
#define __KVM_VMI_H

#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/xarray.h>
#include <linux/atomic.h>
#include <linux/wait.h>
#include <linux/kvm_types.h>
#include <uapi/linux/kvm_vmi.h>

struct kvm;
struct kvm_vcpu;
struct eventfd_ctx;

/**
 * struct kvm_vmi_view_data - An alternate memory view (alternate EPT root)
 * @id: Unique stable view ID (usable as EPTP list index if <= 511).
 * @vcpu_count: Number of vCPUs currently executing in this view.
 * @default_access: Default R/W/X permissions for lazily-populated entries.
 * @visible: VMFUNC visibility (for future EPTP list, currently unused).
 * @dying: Set under vmi->lock before xa_erase to back off the lock-free view
 *	switch from incrementing vcpu_count on a view committed to free.
 * @access_overrides: Xarray mapping GFN -> u8 access permissions.
 * @arch: Architecture-specific view data.
 * @rcu_head: Deferred free via call_srcu(&kvm->srcu): the struct must outlive
 *	an SRCU grace period for lock-free fault-path readers.
 */
struct kvm_vmi_view_data {
	u32 id;
	atomic_t vcpu_count;
	u8 default_access;
	bool visible;
	bool dying;
	struct xarray access_overrides;
	struct kvm_arch_vmi_view arch;
	struct rcu_head rcu_head;	/* deferred free via call_srcu */
};

/**
 * struct kvm_vmi - VM-level VMI state
 * @lock: Protects VMI state modifications.
 * @views: Xarray of alternate memory views (struct kvm_vmi_view_data).
 * @next_view_id: Next view ID to allocate (starts at 1; 0 is the host view).
 * @shadow_pages: Xarray mapping shadow_gfn -> struct page *.
 * @next_shadow_gfn: Monotonic counter for shadow GFN allocation.
 * @enabled_events: Bitmask of enabled event types (BIT_ULL(KVM_VMI_EVENT_*)).
 * @arch: Architecture-specific VMI monitoring config (CR/MSR).
 */
struct kvm_vmi {
	struct mutex lock;
	struct xarray views;
	u32 next_view_id;

	/* Shadow page allocation */
	struct xarray shadow_pages;	/* shadow_gfn -> struct page * */
	u64 next_shadow_gfn;		/* monotonic counter */

	/* Event monitoring config (VM-wide) */
	u64 enabled_events;
	struct kvm_arch_vmi arch;
};

/**
 * struct kvm_vcpu_vmi - Per-vCPU VMI state
 * @view_lock: Serializes this vCPU's view-state transitions against the VM-wide
 *	KVM_VMI_SWITCH_VIEW ioctl, so a fast-singlestep completion cannot
 *	resurrect a refcount on a switched-away view (destroy_view -EBUSY).
 * @current_view_id: ID of the memory view this vCPU is currently on.
 * @current_view: Pointer to current alternate view (NULL when on view 0).
 * @arch: Architecture-specific per-vCPU VMI state.
 */
struct kvm_vcpu_vmi {
	spinlock_t view_lock;
	u32 current_view_id;
	struct kvm_vmi_view_data __rcu *current_view; /* NULL when on view 0 */

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
	bool teardown;		/* ring deliver-fence: ring page freed */
	bool session_teardown;	/* set only by kvm_vmi_release(); ring-scoped
				 * @teardown must not drive the pause escape */
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
int kvm_vmi_pause_vm(struct kvm *kvm);
int kvm_vmi_unpause_vm(struct kvm *kvm);

/* vCPU lifecycle */
int kvm_vmi_vcpu_init(struct kvm_vcpu *vcpu);
void kvm_vmi_vcpu_destroy(struct kvm_vcpu *vcpu);

/* Event delivery */
int kvm_vmi_deliver_via_ring(struct kvm_vcpu *vcpu,
			     struct kvm_vmi_ring_event *event);

/* View management */
int kvm_vmi_vcpu_switch_view(struct kvm_vcpu *vcpu, u32 view_id);

/* Pause support (called from vcpu_run) */
bool kvm_vmi_vcpu_paused(struct kvm_vcpu *vcpu);
void kvm_vmi_vcpu_pause_wait(struct kvm_vcpu *vcpu);

/* Per-arch functions (implemented per-arch, not a generic->arch contract) */
void kvm_vmi_capture_regs(struct kvm_vcpu *vcpu, struct kvm_vmi_regs *regs);
void kvm_vmi_restore_regs(struct kvm_vcpu *vcpu, struct kvm_vmi_regs *regs);
void kvm_vmi_handle_event_response(struct kvm_vcpu *vcpu,
				   u32 event_type, u32 resp);
int kvm_vmi_inject_event(struct kvm_vcpu *vcpu,
			 struct kvm_vmi_inject_event *inject);

/* Arch callbacks (generic -> arch contract) */
bool kvm_arch_vmi_supported(void);
bool kvm_arch_vmi_has_auto_step(void);

void kvm_arch_vmi_session_init(struct kvm_vmi *vmi);
void kvm_arch_vmi_session_cleanup(struct kvm_vmi *vmi);
void kvm_arch_vmi_session_reset(struct kvm_vmi *vmi);
void kvm_arch_vmi_reset_vcpu_state(struct kvm_vcpu *vcpu);

int kvm_arch_vmi_control_event(struct kvm *kvm,
			       struct kvm_vmi_control_event *ctrl);
void kvm_arch_vmi_update(struct kvm *kvm);

/* Shed/re-take per-vCPU read locks the arch holds, around a VMI op that
 * blocks the vCPU thread. */
void kvm_arch_vmi_block_begin(struct kvm_vcpu *vcpu);
void kvm_arch_vmi_block_end(struct kvm_vcpu *vcpu);

int kvm_arch_vmi_create_view(struct kvm *kvm, struct kvm_vmi_view_data *view);
void kvm_arch_vmi_destroy_view(struct kvm *kvm, struct kvm_vmi_view_data *view);
void kvm_arch_vmi_switch_view(struct kvm_vcpu *vcpu,
			      struct kvm_vmi_view_data *view);
void kvm_arch_vmi_reset_view(struct kvm_vcpu *vcpu);
bool kvm_arch_vmi_view_has_root(struct kvm_vmi_view_data *view);

void kvm_arch_vmi_invalidate_gfn(struct kvm *kvm,
				 struct kvm_vmi_view_data *view, gfn_t gfn);
void kvm_arch_vmi_invalidate_gfn_locked(struct kvm *kvm,
					 struct kvm_vmi_view_data *view,
					 gfn_t gfn);

#else /* !CONFIG_KVM_VMI */

static inline bool kvm_vmi_vcpu_paused(struct kvm_vcpu *vcpu) { return false; }
static inline void kvm_vmi_vcpu_pause_wait(struct kvm_vcpu *vcpu) {}

#endif /* CONFIG_KVM_VMI */

#endif /* __KVM_VMI_H */
