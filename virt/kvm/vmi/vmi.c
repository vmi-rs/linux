// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM Virtual Machine Introspection (VMI) - Generic Core
 *
 * Provides the architecture-independent VMI functionality:
 * - VM-level VMI lifecycle (create/destroy)
 * - Event delivery framework
 * - Response handling
 * - Ioctl dispatch
 */

#include <linux/kvm_host.h>
#include <linux/kvm_vmi.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/eventfd.h>
#include <linux/poll.h>
#include <linux/mm.h>

#define CREATE_TRACE_POINTS
#include <trace/events/kvm_vmi.h>

static const struct file_operations kvm_vmi_fops;
static const struct file_operations kvm_vmi_ring_fops;

/**
 * kvm_vmi_has_cap - Check if VMI is supported on this platform
 *
 * VMI requires vendor-specific support (alternate EPT views, VMCS
 * interception controls, etc). Currently only Intel VMX implements
 * the required callbacks.
 *
 * Return: true if VMI is supported, false otherwise.
 */
bool kvm_vmi_has_cap(void)
{
	return kvm_arch_vmi_supported();
}

/**
 * kvm_create_vmi - Create a VMI session for a VM
 * @kvm: The VM to create a VMI session for.
 *
 * Allocates and initializes the VM-level VMI state and creates an
 * anonymous file descriptor (vmi_fd) for the session. Only one VMI
 * session can be active per VM at a time. Closing the returned fd
 * performs full cleanup.
 *
 * Return: Non-negative fd on success, -EBUSY if a session already
 *         exists, -ENOMEM on allocation failure.
 */
int kvm_create_vmi(struct kvm *kvm)
{
	struct kvm_vmi *vmi;
	struct kvm_vcpu *vcpu;
	unsigned long i;
	int fd, r;

	mutex_lock(&kvm->lock);
	if (kvm->vmi) {
		mutex_unlock(&kvm->lock);
		return -EBUSY;
	}

	vmi = kzalloc(sizeof(*vmi), GFP_KERNEL_ACCOUNT);
	if (!vmi) {
		mutex_unlock(&kvm->lock);
		return -ENOMEM;
	}

	mutex_init(&vmi->lock);
	xa_init(&vmi->views);
	kvm_arch_vmi_session_init(vmi);
	vmi->next_view_id = 1; /* View 0 is the default/host view */

	rcu_assign_pointer(kvm->vmi, vmi);

	/* Initialize VMI state for any already-created vCPUs */
	kvm_for_each_vcpu(i, vcpu, kvm) {
		r = kvm_vmi_vcpu_init(vcpu);
		if (r)
			goto err_rollback;
	}

	/*
	 * Request VMCS recalculation on all vCPUs so tertiary execution
	 * controls pick up the new VMI session state (e.g., enabling
	 * TERTIARY_EXEC_EPT_PAGING_WRITE when supported by hardware).
	 */
	kvm_arch_vmi_update(kvm);

	mutex_unlock(&kvm->lock);

	/* Create the session fd */
	mutex_lock(&vmi->lock);
	kvm_get_kvm(kvm);
	fd = anon_inode_getfd("kvm-vmi", &kvm_vmi_fops, kvm,
			      O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		r = fd;
		kvm_put_kvm(kvm);
		mutex_unlock(&vmi->lock);
		mutex_lock(&kvm->lock);
		goto err_rollback;
	}

	xa_init(&vmi->shadow_pages);
	vmi->next_shadow_gfn = KVM_VMI_SHADOW_GFN_BASE;
	mutex_unlock(&vmi->lock);

	trace_kvm_vmi_session(true);
	return fd;

err_rollback:
	/* kvm->lock must be held here */
	kvm_for_each_vcpu(i, vcpu, kvm)
		kvm_vmi_vcpu_destroy(vcpu);
	rcu_assign_pointer(kvm->vmi, NULL);
	mutex_unlock(&kvm->lock);
	mutex_destroy(&vmi->lock);
	kvm_arch_vmi_session_cleanup(vmi);
	xa_destroy(&vmi->views);
	kfree(vmi);
	return r;
}

/**
 * kvm_vmi_destroy - Free VMI resources for a VM being destroyed.
 * @kvm: The VM being destroyed.
 *
 * Called during VM teardown after all vCPU threads have been stopped.
 * Normally release has already cleaned everything up; this handles
 * the edge case where release never ran (e.g., process killed before
 * closing vmi_fd).
 */
void kvm_vmi_destroy(struct kvm *kvm)
{
	struct kvm_vmi *vmi;
	struct kvm_vcpu *vcpu;
	unsigned long i;

	vmi = kvm_vmi_get(kvm);
	if (!vmi)
		return;

	/*
	 * Release never ran - clean up everything.
	 * No SRCU needed: all vCPU threads are stopped at this point.
	 */
	kvm_for_each_vcpu(i, vcpu, kvm)
		kvm_vmi_vcpu_destroy(vcpu);

	rcu_assign_pointer(kvm->vmi, NULL);
	xa_destroy(&vmi->shadow_pages);
	kvm_arch_vmi_session_cleanup(vmi);
	xa_destroy(&vmi->views);
	mutex_destroy(&vmi->lock);
	kfree(vmi);
}

/**
 * kvm_vmi_vcpu_init - Initialize per-vCPU VMI state
 * @vcpu: The vCPU to initialize.
 *
 * Called when a vCPU is created and VMI is enabled.
 *
 * Return: 0 on success, negative errno on failure.
 */
int kvm_vmi_vcpu_init(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_vmi *vcpu_vmi;

	if (!vcpu->kvm->vmi)
		return 0;

	vcpu_vmi = kzalloc(sizeof(*vcpu_vmi), GFP_KERNEL_ACCOUNT);
	if (!vcpu_vmi)
		return -ENOMEM;

	vcpu_vmi->current_view_id = 0; /* Default to host view */

	init_waitqueue_head(&vcpu_vmi->wq);
	init_waitqueue_head(&vcpu_vmi->pause_wq);
	atomic_set(&vcpu_vmi->pause_count, 0);
	vcpu_vmi->teardown = false;

	vcpu->vmi = vcpu_vmi;

	return 0;
}

/**
 * kvm_vmi_vcpu_destroy - Free per-vCPU VMI state
 * @vcpu: The vCPU being destroyed.
 */
void kvm_vmi_vcpu_destroy(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_vmi *vcpu_vmi = vcpu->vmi;

	if (!vcpu_vmi)
		return;

	kfree(vcpu_vmi);
	vcpu->vmi = NULL;
}

/**
 * kvm_vmi_apply_ring_response - Apply agent response from ring event
 * @vcpu: The vCPU whose event was processed.
 * @event: The ring event slot containing the agent's response.
 *
 * Reads the response flags from the ring event and dispatches to the
 * appropriate arch-specific response handlers.
 */
static int kvm_vmi_apply_ring_response(struct kvm_vcpu *vcpu,
				       struct kvm_vmi_ring_event *event)
{
	u32 resp = READ_ONCE(event->response);
	u32 event_type = event->type;
	struct kvm_vcpu_vmi *vcpu_vmi = vcpu->vmi;

	/* Mask to known flags */
	resp &= KVM_VMI_RESPONSE_MASK;

	trace_kvm_vmi_event_response(vcpu->vcpu_id, event_type, resp);

	/* Restore GP registers if agent modified them */
	if (resp & KVM_VMI_RESPONSE_SET_REGS)
		kvm_vmi_restore_regs(vcpu, &event->regs);

	/* Dispatch to arch-specific response handler */
	kvm_vmi_handle_event_response(vcpu, event_type, resp);

	if (resp & KVM_VMI_RESPONSE_SINGLESTEP)
		kvm_arch_vmi_set_singlestep(vcpu, true);

	/*
	 * Fast singlestep: execute one instruction in a target view,
	 * then auto-switch back and suppress the singlestep event.
	 *
	 * With SWITCH_VIEW: step in the specified view_id.
	 * Without SWITCH_VIEW: step in view 0 (default/host view).
	 */
	if ((resp & KVM_VMI_RESPONSE_SINGLESTEP_FAST) && vcpu_vmi) {
		u32 target_view;

		vcpu_vmi->fast_singlestep_active = true;
		vcpu_vmi->fast_singlestep_restore_view =
			vcpu_vmi->current_view_id;
		kvm_arch_vmi_set_singlestep(vcpu, true);

		if (resp & KVM_VMI_RESPONSE_SWITCH_VIEW)
			target_view = READ_ONCE(event->view_id);
		else
			target_view = 0;

		kvm_vmi_vcpu_switch_view(vcpu, target_view);
	} else if (resp & KVM_VMI_RESPONSE_SWITCH_VIEW) {
		u32 view_id = READ_ONCE(event->view_id);

		kvm_vmi_vcpu_switch_view(vcpu, view_id);
	}

	return resp;
}

/**
 * kvm_vmi_deliver_via_ring - Deliver a VMI event through the shared ring
 * @vcpu: The vCPU generating the event.
 * @src_event: Pre-filled ring event with type, vcpu_id, and event-specific
 *             data. The register capture will be added by this function.
 *
 * This is the core ring delivery function. It:
 * 1. Copies event data into the ring slot
 * 2. Snapshots vCPU registers into the ring
 * 3. Publishes the event (advances req_prod)
 * 4. Signals the agent via event_fd
 * 5. Blocks until the agent acknowledges (req_cons advances)
 * 6. Applies the agent's response
 *
 * The vCPU thread releases vcpu->mutex before blocking. This enables
 * the agent to call standard KVM vCPU ioctls (KVM_GET_FPU, KVM_GET_XSAVE,
 * etc.) on the duplicated vCPU fd while the vCPU is blocked. Common
 * registers are also available directly from the ring event.
 *
 * Return: Response flags (>= 0) on success, negative errno on error.
 *         On teardown, returns 0 (treated as CONTINUE).
 */
int kvm_vmi_deliver_via_ring(struct kvm_vcpu *vcpu,
			     struct kvm_vmi_ring_event *src_event)
{
	struct kvm_vcpu_vmi *vcpu_vmi = vcpu->vmi;
	struct kvm_vmi_ring_header *hdr;
	struct kvm_vmi_ring_event *slots;
	struct kvm_vmi_ring_event *slot;
	u32 prod;

	if (!vcpu_vmi)
		return 0;

	hdr = READ_ONCE(vcpu_vmi->ring);
	if (!hdr)
		return 0;

	prod = hdr->req_prod;
	slots = (struct kvm_vmi_ring_event *)((u8 *)hdr + sizeof(*hdr));
	slot = &slots[prod % hdr->num_slots];

	/* Copy event header and event-specific data */
	memcpy(slot, src_event,
	       offsetof(struct kvm_vmi_ring_event, regs));

	/* Snapshot registers into the ring slot */
	kvm_vmi_capture_regs(vcpu, &slot->regs);

	/* Initialize response area: view_id defaults to current view
	 * so the agent can read it to know which view the event fired in.
	 * The agent can overwrite it for SWITCH_VIEW responses.
	 */
	slot->response = 0;
	slot->view_id = vcpu_vmi->current_view_id;

	/* Publish event: ensure all writes are visible before prod update */
	smp_wmb();
	WRITE_ONCE(hdr->req_prod, prod + 1);

	/* Signal agent */
	eventfd_signal(vcpu_vmi->event_fd_ctx);

	/*
	 * Release vcpu->mutex and SRCU read lock before blocking.
	 * This allows the agent to call standard KVM vCPU ioctls
	 * (KVM_GET_FPU, KVM_GET_XSAVE, etc.) on the duplicated vCPU fd
	 * while the vCPU is blocked, and allows synchronize_srcu() in
	 * kvm_vmi_release() to complete.
	 */
	kvm_vcpu_srcu_read_unlock(vcpu);
	vcpu_put(vcpu);
	mutex_unlock(&vcpu->mutex);

	/*
	 * Safe to access vcpu_vmi here: kvm_vmi_release() sets
	 * teardown=true and wakes this waitqueue before call_srcu(),
	 * so the wait completes while the struct is still alive.
	 */
	wait_event(vcpu_vmi->wq,
		READ_ONCE(hdr->req_cons) > prod ||
		vcpu_vmi->teardown);

	mutex_lock(&vcpu->mutex);
	vcpu_load(vcpu);
	kvm_vcpu_srcu_read_lock(vcpu);

	/*
	 * Re-read under SRCU - call_srcu() may have freed vcpu_vmi
	 * while we were outside SRCU.
	 */
	vcpu_vmi = vcpu->vmi;
	if (!vcpu_vmi || vcpu_vmi->teardown)
		return 0; /* Teardown: CONTINUE (default action) */

	/* Read barrier: ensure we see agent's response writes */
	smp_rmb();

	/* Apply response and return the masked response flags */
	return kvm_vmi_apply_ring_response(vcpu, slot);
}

/**
 * kvm_vmi_vcpu_switch_view - Switch a vCPU to an alternate memory view
 * @vcpu: The target vCPU.
 * @view_id: The view ID to switch to (0 = host view).
 *
 * Return: 0 on success, negative errno on failure.
 */
int kvm_vmi_vcpu_switch_view(struct kvm_vcpu *vcpu, u32 view_id)
{
	struct kvm_vmi *vmi = vcpu->kvm->vmi;
	struct kvm_vcpu_vmi *vcpu_vmi = vcpu->vmi;
	struct kvm_vmi_view_data *new_view, *old_view;
	u32 old_view_id;

	if (!vmi || !vcpu_vmi)
		return -EINVAL;

	old_view_id = vcpu_vmi->current_view_id;

	/* Switching to same view is a no-op */
	if (view_id == old_view_id)
		return 0;

	if (view_id == 0) {
		new_view = NULL;
	} else {
		new_view = xa_load(&vmi->views, view_id);
		if (!new_view)
			return -ENOENT;
	}

	/* Update refcounts */
	if (old_view_id != 0) {
		old_view = xa_load(&vmi->views, old_view_id);
		if (old_view)
			atomic_dec(&old_view->vcpu_count);
	}
	if (new_view)
		atomic_inc(&new_view->vcpu_count);

	/* Perform the arch-specific EPTP switch */
	kvm_arch_vmi_switch_view(vcpu, new_view);

	trace_kvm_vmi_view_switch(vcpu->vcpu_id, old_view_id, view_id);
	vcpu_vmi->current_view_id = view_id;
	vcpu_vmi->current_view = new_view;
	return 0;
}

/**
 * kvm_vmi_vcpu_paused - Check if a vCPU is currently VMI-paused.
 * @vcpu: The vCPU to check.
 *
 * Returns true if the vCPU has VMI state and its pause_count > 0.
 * When VMI is not active, vcpu->vmi is NULL so this returns
 * false immediately.
 */
bool kvm_vmi_vcpu_paused(struct kvm_vcpu *vcpu)
{
	return vcpu->vmi &&
	       atomic_read(&vcpu->vmi->pause_count) > 0;
}

/**
 * kvm_vmi_vcpu_pause_wait - Sleep until a paused vCPU is unpaused.
 * @vcpu: The vCPU to sleep.
 *
 * Called from the vCPU run loop when kvm_vmi_vcpu_paused() returns true.
 * Releases vcpu->mutex and unloads vCPU state so the VMI agent can call
 * KVM ioctls (register reads, etc.) on this vCPU while it sleeps, and
 * re-acquires them before returning.  The caller owns any per-vCPU SRCU
 * read lock held across the run loop (x86 drops and re-takes it around
 * this call; arm64 holds none here), since that is arch-specific.
 */
void kvm_vmi_vcpu_pause_wait(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_vmi *vcpu_vmi = vcpu->vmi;

	vcpu_put(vcpu);
	mutex_unlock(&vcpu->mutex);

	/*
	 * Safe to access vcpu_vmi here: kvm_vmi_release() sets
	 * teardown=true and wakes this waitqueue before call_srcu(),
	 * so the wait completes while the struct is still alive.
	 */
	wait_event(vcpu_vmi->pause_wq,
		atomic_read(&vcpu_vmi->pause_count) == 0 ||
		vcpu_vmi->teardown);

	/*
	 * Don't touch vcpu_vmi past this point - call_srcu() may
	 * have freed it while we were outside SRCU.
	 */
	mutex_lock(&vcpu->mutex);
	vcpu_load(vcpu);
}

/**
 * kvm_vmi_control_event - Enable or disable VM-wide event monitoring
 * @kvm: The VM.
 * @ctrl: Event control parameters from userspace.
 *
 * Dispatches to arch-specific handler for arch events (CR, MSR, etc.),
 * then falls through to generic bit-toggle for generic events.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int kvm_vmi_control_event(struct kvm *kvm,
				 struct kvm_vmi_control_event *ctrl)
{
	struct kvm_vmi *vmi = kvm->vmi;
	u32 event = ctrl->event;
	int r = 0;

	if (!vmi)
		return -EINVAL;

	if (event >= KVM_VMI_NUM_EVENTS)
		return -EINVAL;

	mutex_lock(&vmi->lock);

	/*
	 * Try arch callback first for arch-specific event IDs.
	 * Events with special parameters (e.g., CR index, MSR number)
	 * are fully handled by the arch callback (returns 0 or error).
	 * Events the arch doesn't handle specially return -EOPNOTSUPP,
	 * falling through to generic bit-toggle handling below.
	 */
	if (event >= KVM_VMI_EVENT_ARCH_BASE) {
		r = kvm_arch_vmi_control_event(kvm, ctrl);
		if (r != -EOPNOTSUPP)
			goto out_unlock;
		r = 0;
	}

	/* Generic events: manage enabled_events bit directly */
	if (ctrl->enable)
		vmi->enabled_events |= BIT_ULL(event);
	else
		vmi->enabled_events &= ~BIT_ULL(event);
	kvm_arch_vmi_update(kvm);

out_unlock:
	mutex_unlock(&vmi->lock);
	return r;
}

/**
 * kvm_vmi_create_view - Create an alternate memory view
 * @kvm: The target VM.
 * @uview: View descriptor from userspace (view_id is output).
 *
 * Allocates a new alternate view with its own EPT root. The view starts
 * empty; entries are lazily populated from the host EPT on first access.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int kvm_vmi_create_view(struct kvm *kvm, struct kvm_vmi_view *uview)
{
	struct kvm_vmi *vmi = kvm->vmi;
	struct kvm_vmi_view_data *view;
	int ret;

	if (!vmi)
		return -EINVAL;

	/* Reject PW flag in default_access when hardware doesn't support it */
	if ((uview->default_access & KVM_VMI_ACCESS_PW) &&
	    !kvm_arch_vmi_has_paging_write())
		return -EOPNOTSUPP;

	/* Reject W without R - EPT cannot encode this combination */
	if ((uview->default_access & KVM_VMI_ACCESS_W) &&
	    !(uview->default_access & KVM_VMI_ACCESS_R))
		return -EINVAL;

	view = kzalloc(sizeof(*view), GFP_KERNEL);
	if (!view)
		return -ENOMEM;

	atomic_set(&view->vcpu_count, 0);
	view->default_access = uview->default_access;
	view->visible = true;
	xa_init(&view->gfn_overrides);
	xa_init(&view->access_overrides);

	/* Allocate arch-specific EPT root */
	ret = kvm_arch_vmi_create_view(kvm, view);
	if (ret) {
		xa_destroy(&view->gfn_overrides);
		xa_destroy(&view->access_overrides);
		kfree(view);
		return ret;
	}

	/* Assign view ID and store in xarray */
	mutex_lock(&vmi->lock);
	view->id = vmi->next_view_id++;
	ret = xa_insert(&vmi->views, view->id, view, GFP_KERNEL);
	mutex_unlock(&vmi->lock);

	if (ret) {
		kvm_arch_vmi_destroy_view(kvm, view);
		xa_destroy(&view->gfn_overrides);
		xa_destroy(&view->access_overrides);
		kfree(view);
		return ret;
	}

	uview->view_id = view->id;
	trace_kvm_vmi_view_create(view->id, view->default_access);
	return 0;
}

/**
 * kvm_vmi_destroy_view - Destroy an alternate memory view
 * @kvm: The target VM.
 * @uview: View descriptor from userspace (view_id identifies the view).
 *
 * Frees a view and all its resources. Fails if any vCPU is currently
 * executing in the view.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int kvm_vmi_destroy_view(struct kvm *kvm, struct kvm_vmi_view *uview)
{
	struct kvm_vmi *vmi = kvm->vmi;
	struct kvm_vmi_view_data *view;

	if (!vmi)
		return -EINVAL;

	if (uview->view_id == 0)
		return -EINVAL; /* Cannot destroy host view */

	mutex_lock(&vmi->lock);
	view = xa_load(&vmi->views, uview->view_id);
	if (!view) {
		mutex_unlock(&vmi->lock);
		return -ENOENT;
	}

	/* Check no vCPUs are currently on this view */
	if (atomic_read(&view->vcpu_count) > 0) {
		mutex_unlock(&vmi->lock);
		return -EBUSY;
	}

	xa_erase(&vmi->views, uview->view_id);
	mutex_unlock(&vmi->lock);

	trace_kvm_vmi_view_destroy(uview->view_id);

	/* Free arch-specific resources (EPT pages) */
	kvm_arch_vmi_destroy_view(kvm, view);

	/* Free override xarrays */
	xa_destroy(&view->gfn_overrides);
	xa_destroy(&view->access_overrides);

	kfree(view);
	return 0;
}

static int kvm_vmi_validate_access(u8 access)
{
	/* Reject PW flag when hardware doesn't support EPT paging-write */
	if ((access & KVM_VMI_ACCESS_PW) &&
	    !kvm_arch_vmi_has_paging_write())
		return -EOPNOTSUPP;

	/* Reject W without R - EPT cannot encode this combination */
	if ((access & KVM_VMI_ACCESS_W) && !(access & KVM_VMI_ACCESS_R))
		return -EINVAL;

	return 0;
}

static void kvm_vmi_set_gfn_access(struct kvm *kvm,
				    struct kvm_vmi_view_data *view,
				    u32 view_id, u64 gfn, u8 access)
{
	trace_kvm_vmi_set_mem_access(view_id, gfn, access);

	xa_store(&view->access_overrides, gfn,
		 xa_mk_value(access), GFP_KERNEL);

	if (kvm_arch_vmi_view_has_root(view))
		kvm_arch_vmi_invalidate_gfn(kvm, view, gfn);
}

static int kvm_vmi_set_mem_access_batch(struct kvm *kvm,
					struct kvm_vmi_view_data *view,
					struct kvm_vmi_mem_access *ma)
{
	u64 *gfns;
	u8 *accesses;
	u32 i;
	int ret;

	if (!ma->gfns_uaddr || !ma->accesses_uaddr)
		return -EFAULT;

	gfns = vmemdup_array_user((u64 __user *)ma->gfns_uaddr,
				  ma->nr, sizeof(*gfns));
	if (IS_ERR(gfns))
		return PTR_ERR(gfns);

	accesses = vmemdup_array_user((u8 __user *)ma->accesses_uaddr,
				      ma->nr, sizeof(*accesses));
	if (IS_ERR(accesses)) {
		kvfree(gfns);
		return PTR_ERR(accesses);
	}

	for (i = 0; i < ma->nr; i++) {
		ret = kvm_vmi_validate_access(accesses[i]);
		if (ret)
			goto out;

		kvm_vmi_set_gfn_access(kvm, view, ma->view_id,
				       gfns[i], accesses[i]);
	}

	ret = 0;
out:
	kvfree(accesses);
	kvfree(gfns);
	return ret;
}

static int kvm_vmi_set_mem_access(struct kvm *kvm, struct kvm_vmi_mem_access *ma)
{
	struct kvm_vmi *vmi = kvm->vmi;
	struct kvm_vmi_view_data *view;
	int ret;

	if (!vmi)
		return -EINVAL;

	if (ma->view_id == 0)
		return -EINVAL; /* Cannot modify host view permissions */

	view = xa_load(&vmi->views, ma->view_id);
	if (!view)
		return -ENOENT;

	if (ma->nr <= 1) {
		ret = kvm_vmi_validate_access(ma->access);
		if (ret)
			return ret;

		kvm_vmi_set_gfn_access(kvm, view, ma->view_id,
				       ma->gfn, ma->access);
	} else {
		ret = kvm_vmi_set_mem_access_batch(kvm, view, ma);
		if (ret)
			return ret;
	}

	kvm_flush_remote_tlbs(kvm);

	return 0;
}

static u8 kvm_vmi_get_gfn_access(struct kvm_vmi_view_data *view, u64 gfn)
{
	void *entry;

	if (!view)
		return KVM_VMI_ACCESS_RWX;

	entry = xa_load(&view->access_overrides, gfn);
	if (entry)
		return (u8)xa_to_value(entry);
	return view->default_access;
}

static int kvm_vmi_get_mem_access_batch(struct kvm *kvm,
					struct kvm_vmi_view_data *view,
					struct kvm_vmi_mem_access *ma)
{
	u8 __user *accesses_out = (u8 __user *)ma->accesses_uaddr;
	u64 *gfns;
	u8 *accesses;
	u32 i;
	int ret;

	if (!ma->gfns_uaddr || !accesses_out)
		return -EFAULT;

	gfns = vmemdup_array_user((u64 __user *)ma->gfns_uaddr,
				  ma->nr, sizeof(*gfns));
	if (IS_ERR(gfns))
		return PTR_ERR(gfns);

	accesses = kvmalloc_array(ma->nr, sizeof(*accesses), GFP_KERNEL);
	if (!accesses) {
		ret = -ENOMEM;
		goto out_gfns;
	}

	for (i = 0; i < ma->nr; i++)
		accesses[i] = kvm_vmi_get_gfn_access(view, gfns[i]);

	if (copy_to_user(accesses_out, accesses, ma->nr * sizeof(*accesses)))
		ret = -EFAULT;
	else
		ret = 0;

	kvfree(accesses);
out_gfns:
	kvfree(gfns);
	return ret;
}

static int kvm_vmi_get_mem_access(struct kvm *kvm, struct kvm_vmi_mem_access *ma)
{
	struct kvm_vmi *vmi = kvm->vmi;
	struct kvm_vmi_view_data *view = NULL;

	if (!vmi)
		return -EINVAL;

	if (ma->view_id != 0) {
		view = xa_load(&vmi->views, ma->view_id);
		if (!view)
			return -ENOENT;
	}

	if (ma->nr <= 1) {
		ma->access = kvm_vmi_get_gfn_access(view, ma->gfn);
		return 0;
	}

	return kvm_vmi_get_mem_access_batch(kvm, view, ma);
}

/**
 * kvm_vmi_propagate_change - Invalidate view EPT entries when host mapping changes
 * @kvm: The VM whose views to update.
 * @start: Start GFN of the invalidated range.
 * @end: End GFN (exclusive) of the invalidated range.
 *
 * Called from the mmu_notifier path when host memory mappings change
 * (page migration, swap, etc). Zaps the affected GFN entries in all
 * alternate views so they get lazily re-populated with the new HPAs.
 *
 * Remapped GFNs (via change_gfn) are skipped since they intentionally
 * point to different physical pages.
 *
 * Called with kvm->mmu_lock held by the mmu_notifier framework.
 */
void kvm_vmi_propagate_change(struct kvm *kvm, gfn_t start, gfn_t end)
{
	struct kvm_vmi *vmi = kvm_vmi_get(kvm);
	struct kvm_vmi_view_data *view;
	unsigned long index;
	gfn_t gfn;

	if (!vmi)
		return;

	/* TODO: batched range zap instead of per-GFN walks for large ranges */
	xa_for_each(&vmi->views, index, view) {
		if (!kvm_arch_vmi_view_has_root(view))
			continue;
		for (gfn = start; gfn < end; gfn++) {
			/* Skip remapped GFNs - they have intentional overrides */
			if (xa_load(&view->gfn_overrides, gfn))
				continue;

			kvm_arch_vmi_invalidate_gfn_locked(kvm, view, gfn);
		}
	}
}

/**
 * kvm_vmi_change_gfn - Remap a GFN in an alternate view
 * @kvm: The target VM.
 * @change: Change descriptor with view_id, old_gfn, new_gfn.
 *
 * Maps old_gfn to the physical page backing new_gfn in this view.
 * When new_gfn is KVM_VMI_INVALID_GFN, reverts to the host mapping.
 *
 * This is the core mechanism for shadow page breakpoints:
 *   1. Allocate shadow GFN, copy original page
 *   2. Patch shadow page (e.g., insert INT3)
 *   3. change_gfn(view, original_gfn, shadow_gfn)
 *   4. Guest on this view now sees shadow page at original_gfn
 *
 * Return: 0 on success, negative errno on failure.
 */
static int kvm_vmi_change_gfn(struct kvm *kvm, struct kvm_vmi_change_gfn *change)
{
	struct page *refcounted_page = NULL;
	struct kvm_vmi *vmi = kvm->vmi;
	struct kvm_vmi_view_data *view;
	struct kvm_memory_slot *slot;
	struct page *shadow;
	bool writable;
	kvm_pfn_t pfn;
	hpa_t new_hpa;

	if (!vmi)
		return -EINVAL;

	if (change->view_id == 0)
		return -EINVAL; /* Cannot remap in host view */

	view = xa_load(&vmi->views, change->view_id);
	if (!view)
		return -ENOENT;

	trace_kvm_vmi_change_gfn(change->view_id, change->old_gfn,
				 change->new_gfn);

	if (change->new_gfn == KVM_VMI_INVALID_GFN) {
		/* Revert: remove remapping, restore host mapping */
		xa_erase(&view->gfn_overrides, change->old_gfn);

		if (kvm_arch_vmi_view_has_root(view))
			kvm_arch_vmi_invalidate_gfn_revert(kvm, view,
							   change->old_gfn);
		kvm_flush_remote_tlbs(kvm);
		return 0;
	}

	/*
	 * Resolve new_gfn to HPA. If new_gfn is a VMI-allocated shadow
	 * page, use it directly. Otherwise resolve via host memslots.
	 */
	if (change->new_gfn >= KVM_VMI_SHADOW_GFN_BASE) {
		shadow = xa_load(&vmi->shadow_pages, change->new_gfn);
		if (!shadow)
			return -ENOENT;
		new_hpa = page_to_phys(shadow);
	} else {
		slot = gfn_to_memslot(kvm, change->new_gfn);
		if (!slot)
			return -EFAULT;

		pfn = __kvm_faultin_pfn(slot, change->new_gfn, 0,
					&writable, &refcounted_page);
		if (is_error_noslot_pfn(pfn))
			return -EFAULT;
		new_hpa = (hpa_t)pfn << PAGE_SHIFT;
	}

	/* Store the remapping: old_gfn -> new_hpa */
	xa_store(&view->gfn_overrides, change->old_gfn,
		 (void *)(unsigned long)new_hpa, GFP_KERNEL);

	/* Zap old mapping so next fault installs with remap PFN */
	if (kvm_arch_vmi_view_has_root(view))
		kvm_arch_vmi_invalidate_gfn(kvm, view, change->old_gfn);

	if (refcounted_page)
		put_page(refcounted_page);
	kvm_flush_remote_tlbs(kvm);

	return 0;
}

static int kvm_vmi_alloc_gfn(struct kvm *kvm, struct kvm_vmi_alloc_gfn *alloc)
{
	struct kvm_vmi *vmi = kvm->vmi;
	struct page *page;
	u64 shadow_gfn;
	int ret;

	if (!vmi)
		return -EINVAL;

	page = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!page)
		return -ENOMEM;

	mutex_lock(&vmi->lock);
	shadow_gfn = vmi->next_shadow_gfn++;
	ret = xa_err(xa_store(&vmi->shadow_pages, shadow_gfn, page, GFP_KERNEL));
	mutex_unlock(&vmi->lock);

	if (ret) {
		__free_page(page);
		return ret;
	}

	alloc->gfn = shadow_gfn;
	return 0;
}

static int kvm_vmi_free_gfn(struct kvm *kvm, struct file *file,
			    struct kvm_vmi_free_gfn *free_req)
{
	struct kvm_vmi *vmi = kvm->vmi;
	struct kvm_vmi_view_data *view;
	struct page *page;
	unsigned long view_idx;
	hpa_t shadow_hpa;

	if (!vmi)
		return -EINVAL;

	if (free_req->gfn < KVM_VMI_SHADOW_GFN_BASE)
		return -EINVAL;

	mutex_lock(&vmi->lock);

	page = xa_load(&vmi->shadow_pages, free_req->gfn);
	if (!page) {
		mutex_unlock(&vmi->lock);
		return -ENOENT;
	}

	shadow_hpa = page_to_phys(page);

	/* Check if any view's gfn_overrides references this page */
	xa_for_each(&vmi->views, view_idx, view) {
		void *entry;
		unsigned long gfn;

		xa_for_each(&view->gfn_overrides, gfn, entry) {
			if ((hpa_t)(unsigned long)entry == shadow_hpa) {
				mutex_unlock(&vmi->lock);
				return -EBUSY;
			}
		}
	}

	xa_erase(&vmi->shadow_pages, free_req->gfn);
	mutex_unlock(&vmi->lock);

	/* Forcibly unmap from any agent userspace mappings */
	unmap_mapping_range(file->f_mapping,
			    (loff_t)free_req->gfn << PAGE_SHIFT, PAGE_SIZE, 1);

	__free_page(page);
	return 0;
}

/*
 * Per-vCPU ring fd file operations
 */

static int kvm_vmi_ring_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct kvm_vcpu *vcpu = file->private_data;
	struct kvm_vcpu_vmi *vcpu_vmi = vcpu->vmi;

	if (!vcpu_vmi || !vcpu_vmi->ring_page)
		return -EINVAL;
	if (vma->vm_pgoff != 0 || vma_pages(vma) != 1)
		return -EINVAL;

	vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);
	return remap_pfn_range(vma, vma->vm_start,
			       page_to_pfn(vcpu_vmi->ring_page),
			       PAGE_SIZE, vma->vm_page_prot);
}

static int kvm_vmi_ring_release(struct inode *inode, struct file *file)
{
	/* Ring page lifetime is managed by session, not ring_fd */
	return 0;
}

static const struct file_operations kvm_vmi_ring_fops = {
	.owner = THIS_MODULE,
	.release = kvm_vmi_ring_release,
	.mmap = kvm_vmi_ring_mmap,
	.llseek = noop_llseek,
};

/*
 * Ack eventfd wakeup - called when the agent signals ack_fd after
 * processing a ring event. Consumes the eventfd counter and wakes
 * the vCPU thread blocked in kvm_vmi_deliver_via_ring().
 */
static int vmi_ack_wakeup(wait_queue_entry_t *wait, unsigned mode,
			  int sync, void *key)
{
	struct kvm_vcpu_vmi *vcpu_vmi =
		container_of(wait, struct kvm_vcpu_vmi, ack_wait);
	__poll_t flags = key_to_poll(key);

	if (flags & EPOLLIN) {
		u64 cnt;

		eventfd_ctx_do_read(vcpu_vmi->ack_fd_ctx, &cnt);
		wake_up(&vcpu_vmi->wq);
	}

	return 0;
}

struct vmi_ack_poll_table {
	struct kvm_vcpu_vmi *vcpu_vmi;
	poll_table pt;
};

/*
 * Poll callback for ack_fd registration - discovers the eventfd's
 * internal waitqueue and registers the wakeup callback on it.
 */
static void vmi_ack_poll_cb(struct file *file, wait_queue_head_t *wqh,
			    poll_table *pt)
{
	struct vmi_ack_poll_table *p =
		container_of(pt, struct vmi_ack_poll_table, pt);
	struct kvm_vcpu_vmi *vcpu_vmi = p->vcpu_vmi;

	init_waitqueue_func_entry(&vcpu_vmi->ack_wait, vmi_ack_wakeup);
	vcpu_vmi->ack_wqh = wqh;
	add_wait_queue(wqh, &vcpu_vmi->ack_wait);
}

/*
 * Per-vCPU ring setup and teardown
 */

/**
 * kvm_vmi_setup_ring - Set up a per-vCPU event ring
 * @kvm: The VM owning the vCPU.
 * @setup: Ring setup parameters (IN/OUT).
 *
 * Allocates a shared ring page, acquires eventfd contexts from
 * userspace-provided fds (event_fd for kernel->agent notification,
 * ack_fd for agent->kernel acknowledgement), and creates a ring_fd
 * that userspace can mmap to access the ring page.
 *
 * The event_fd and ack_fd fields are INPUT (userspace creates eventfds
 * and passes the fds). The ring_fd field is OUTPUT (kernel creates it).
 *
 * Return: 0 on success, negative errno on failure.
 */
static int kvm_vmi_setup_ring(struct kvm *kvm,
			      struct kvm_vmi_setup_ring *setup)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vcpu_vmi *vcpu_vmi;
	struct kvm_vmi_ring_header *hdr;
	struct page *page;
	struct eventfd_ctx *event_ctx = NULL, *ack_ctx = NULL;
	struct file *ring_file, *ack_file;
	struct vmi_ack_poll_table ack_pt;
	int ring_fd, r;

	if (setup->flags != 0)
		return -EINVAL;

	vcpu = kvm_get_vcpu_by_id(kvm, setup->vcpu_id);
	if (!vcpu)
		return -EINVAL;

	vcpu_vmi = vcpu->vmi;
	if (!vcpu_vmi)
		return -EINVAL;

	if (vcpu_vmi->ring_page)
		return -EEXIST; /* Ring already set up */

	/* Acquire eventfd contexts from userspace-provided fds */
	event_ctx = eventfd_ctx_fdget(setup->event_fd);
	if (IS_ERR(event_ctx))
		return PTR_ERR(event_ctx);

	ack_ctx = eventfd_ctx_fdget(setup->ack_fd);
	if (IS_ERR(ack_ctx)) {
		r = PTR_ERR(ack_ctx);
		goto err_put_event;
	}

	/* Allocate and initialize ring page */
	page = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!page) {
		r = -ENOMEM;
		goto err_put_ack;
	}

	hdr = page_address(page);
	hdr->req_prod = 0;
	hdr->req_cons = 0;
	/* Calculate how many event slots fit after the header */
	hdr->num_slots = (PAGE_SIZE - sizeof(struct kvm_vmi_ring_header)) /
			  sizeof(struct kvm_vmi_ring_event);
	if (hdr->num_slots == 0)
		hdr->num_slots = 1; /* At least 1 slot */

	/* Create ring fd for mmap access */
	ring_fd = get_unused_fd_flags(O_CLOEXEC);
	if (ring_fd < 0) {
		r = ring_fd;
		goto err_free_page;
	}

	ring_file = anon_inode_getfile("kvm-vmi-ring", &kvm_vmi_ring_fops,
				       vcpu, O_RDWR | O_CLOEXEC);
	if (IS_ERR(ring_file)) {
		r = PTR_ERR(ring_file);
		goto err_put_fd;
	}

	/* Install everything - after this point ring_fd is visible to userspace */
	vcpu_vmi->ring_page = page;
	vcpu_vmi->ring = hdr;
	vcpu_vmi->event_fd_ctx = event_ctx;
	vcpu_vmi->ack_fd_ctx = ack_ctx;
	vcpu_vmi->ring_file = ring_file;
	vcpu_vmi->teardown = false;

	/*
	 * Register wakeup callback on ack_fd so agent can wake vCPU
	 * by writing to ack_fd instead of requiring an ioctl.
	 */
	ack_file = fget(setup->ack_fd);
	if (ack_file) {
		ack_pt.vcpu_vmi = vcpu_vmi;
		init_poll_funcptr(&ack_pt.pt, vmi_ack_poll_cb);
		vfs_poll(ack_file, &ack_pt.pt);
		fput(ack_file);
	}

	fd_install(ring_fd, ring_file);

	/* Return ring_fd to caller for copy_to_user */
	setup->ring_fd = ring_fd;
	return 0;

err_put_fd:
	put_unused_fd(ring_fd);
err_free_page:
	__free_page(page);
err_put_ack:
	eventfd_ctx_put(ack_ctx);
err_put_event:
	eventfd_ctx_put(event_ctx);
	return r;
}

/**
 * kvm_vmi_free_ring - Free per-vCPU ring resources
 * @vcpu: The vCPU whose ring to free.
 *
 * Releases the eventfd contexts, frees the ring page, and wakes any
 * waiters (vCPU threads blocked waiting for event acknowledgement).
 * Called during ring teardown and session cleanup.
 */
static void kvm_vmi_free_ring(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_vmi *vcpu_vmi = vcpu->vmi;

	if (!vcpu_vmi)
		return;

	vcpu_vmi->teardown = true;
	wake_up(&vcpu_vmi->wq);
	wake_up(&vcpu_vmi->pause_wq);

	/* Remove ack_fd wakeup callback before releasing eventfd ctx */
	if (vcpu_vmi->ack_wqh) {
		remove_wait_queue(vcpu_vmi->ack_wqh, &vcpu_vmi->ack_wait);
		vcpu_vmi->ack_wqh = NULL;
	}

	if (vcpu_vmi->event_fd_ctx) {
		eventfd_ctx_put(vcpu_vmi->event_fd_ctx);
		vcpu_vmi->event_fd_ctx = NULL;
	}
	if (vcpu_vmi->ack_fd_ctx) {
		eventfd_ctx_put(vcpu_vmi->ack_fd_ctx);
		vcpu_vmi->ack_fd_ctx = NULL;
	}
	if (vcpu_vmi->ring_page) {
		__free_page(vcpu_vmi->ring_page);
		vcpu_vmi->ring_page = NULL;
	}
	vcpu_vmi->ring = NULL;
	vcpu_vmi->ring_file = NULL;
}

/**
 * kvm_vmi_teardown_ring - Tear down a per-vCPU event ring
 * @kvm: The VM owning the vCPU.
 * @vcpu_id: The vCPU ID whose ring to tear down.
 *
 * Frees the ring for the specified vCPU. Userspace must close the
 * ring_fd separately; this only releases kernel-side resources.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int kvm_vmi_teardown_ring(struct kvm *kvm, u32 vcpu_id)
{
	struct kvm_vcpu *vcpu;

	vcpu = kvm_get_vcpu_by_id(kvm, vcpu_id);
	if (!vcpu)
		return -EINVAL;

	if (!vcpu->vmi || !vcpu->vmi->ring_page)
		return -ENOENT;

	kvm_vmi_free_ring(vcpu);
	return 0;
}

/*
 * vmi_fd ioctl handlers
 */

/**
 * kvm_vmi_ack_event - Acknowledge a ring event for a vCPU
 * @kvm: The VM.
 * @ack: vCPU identifier.
 *
 * Called by the agent after processing a ring event and writing the
 * response into the ring slot. This function advances req_cons and
 * wakes the blocked vCPU thread so it can apply the response.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int kvm_vmi_ack_event(struct kvm *kvm, struct kvm_vmi_vcpu *ack)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vcpu_vmi *vcpu_vmi;

	vcpu = kvm_get_vcpu_by_id(kvm, ack->vcpu_id);
	if (!vcpu)
		return -EINVAL;

	vcpu_vmi = vcpu->vmi;
	if (!vcpu_vmi || !vcpu_vmi->ring)
		return -EINVAL;

	/*
	 * Advance the consumer index. The agent has already written
	 * the response to the ring slot; this makes it visible to
	 * the blocked vCPU thread.
	 */
	smp_wmb();
	WRITE_ONCE(vcpu_vmi->ring->req_cons, vcpu_vmi->ring->req_cons + 1);

	/* Wake the blocked vCPU */
	wake_up(&vcpu_vmi->wq);

	return 0;
}

/**
 * kvm_vmi_switch_view - Switch all vCPUs to a view (ioctl wrapper)
 * @kvm: The target VM.
 * @sv: Switch view descriptor from userspace.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int kvm_vmi_switch_view(struct kvm *kvm,
			       struct kvm_vmi_switch_view *sv)
{
	struct kvm_vmi *vmi = kvm->vmi;
	struct kvm_vmi_view_data *new_view, *old_view;
	struct kvm_vcpu *vcpu;
	unsigned long i;

	if (!vmi)
		return -EINVAL;

	if (sv->view_id == 0) {
		new_view = NULL;
	} else {
		new_view = xa_load(&vmi->views, sv->view_id);
		if (!new_view)
			return -ENOENT;
	}

	/*
	 * Switch every vCPU to the target view. Update in-memory state
	 * first, then kick all vCPUs via kvm_arch_vmi_update() so they
	 * pick up the new EPTP in apply_vmcs_state().
	 */
	kvm_for_each_vcpu(i, vcpu, kvm) {
		struct kvm_vcpu_vmi *vcpu_vmi = vcpu->vmi;
		u32 old_view_id;

		if (!vcpu_vmi)
			continue;

		old_view_id = vcpu_vmi->current_view_id;
		if (sv->view_id == old_view_id)
			continue;

		/* Update refcounts */
		if (old_view_id != 0) {
			old_view = xa_load(&vmi->views, old_view_id);
			if (old_view)
				atomic_dec(&old_view->vcpu_count);
		}
		if (new_view)
			atomic_inc(&new_view->vcpu_count);

		vcpu_vmi->current_view_id = sv->view_id;
		vcpu_vmi->current_view = new_view;

		/*
		 * When switching back to view 0, ask the arch layer
		 * to reload the host page table root on next entry.
		 */
		if (sv->view_id == 0 && old_view_id != 0)
			kvm_arch_vmi_reset_view(vcpu);
	}

	/* Schedule VMCS sync + kick on all vCPUs */
	kvm_arch_vmi_update(kvm);

	return 0;
}

/*
 * VM-wide pause: increment pause_count on all vCPUs, force them out
 * of guest mode and off waitqueues.
 *
 * Three vCPU states are handled:
 *  - In guest mode: KVM_REQ_OUTSIDE_GUEST_MODE forces a VM-exit and
 *    waits for acknowledgement (Dekker barrier pattern).
 *  - Halted/sleeping (HLT, kvm_vcpu_block): KVM_REQ_UNBLOCK wakes
 *    them (KVM_REQ_OUTSIDE_GUEST_MODE has KVM_REQUEST_NO_WAKEUP).
 *  - Not in KVM_RUN: vcpu->mutex is already free.
 *
 * After return, vCPUs will reach the pause check at the top of
 * vcpu_run() and release vcpu->mutex.  KVM_GET_REGS from the VMI
 * agent naturally serializes on vcpu->mutex, so no explicit barrier
 * is needed here.
 */
static int kvm_vmi_pause_vm(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	unsigned long i;

	trace_kvm_vmi_pause(-1, true);
	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (vcpu->vmi)
			atomic_inc(&vcpu->vmi->pause_count);
	}

	/* Force in-guest vCPUs out synchronously. */
	kvm_make_all_cpus_request(kvm, KVM_REQ_OUTSIDE_GUEST_MODE);

	/*
	 * Wake halted/sleeping vCPUs.  KVM_REQ_OUTSIDE_GUEST_MODE has
	 * KVM_REQUEST_NO_WAKEUP so it skips sleeping vCPUs.
	 * KVM_REQ_UNBLOCK wakes them from kvm_vcpu_block/halt.
	 */
	kvm_make_all_cpus_request(kvm, KVM_REQ_UNBLOCK);

	/*
	 * At this point:
	 * - In-guest vCPUs have exited (KVM_REQ_OUTSIDE_GUEST_MODE is sync)
	 * - Halted vCPUs have been woken (KVM_REQ_UNBLOCK)
	 * - vCPUs will reach the pause check and release vcpu->mutex
	 *
	 * KVM_GET_REGS from the VMI agent will wait for vcpu->mutex
	 * if the vCPU hasn't released it yet, providing the necessary
	 * synchronization without us touching vcpu->mutex here.
	 */
	return 0;
}

static int kvm_vmi_unpause_vm(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	unsigned long i;

	trace_kvm_vmi_pause(-1, false);
	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (vcpu->vmi) {
			atomic_dec_if_positive(&vcpu->vmi->pause_count);
			wake_up(&vcpu->vmi->pause_wq);
		}
	}
	return 0;
}

static int kvm_vmi_pause_vcpu_ioctl(struct kvm *kvm, u32 vcpu_id)
{
	struct kvm_vcpu *vcpu;

	vcpu = kvm_get_vcpu_by_id(kvm, vcpu_id);
	if (!vcpu || !vcpu->vmi)
		return -EINVAL;

	atomic_inc(&vcpu->vmi->pause_count);
	kvm_vcpu_kick(vcpu);
	trace_kvm_vmi_pause(vcpu_id, true);
	return 0;
}

static int kvm_vmi_unpause_vcpu_ioctl(struct kvm *kvm, u32 vcpu_id)
{
	struct kvm_vcpu *vcpu;

	vcpu = kvm_get_vcpu_by_id(kvm, vcpu_id);
	if (!vcpu || !vcpu->vmi)
		return -EINVAL;

	atomic_dec_if_positive(&vcpu->vmi->pause_count);
	wake_up(&vcpu->vmi->pause_wq);
	trace_kvm_vmi_pause(vcpu_id, false);
	return 0;
}

static int kvm_vmi_inject_event_ioctl(struct kvm *kvm,
				      struct kvm_vmi_inject_event *inject)
{
	struct kvm_vcpu *vcpu;
	int r;

	vcpu = kvm_get_vcpu_by_id(kvm, inject->vcpu_id);
	if (!vcpu || !vcpu->vmi)
		return -EINVAL;

	/* Exception injection modifies vCPU exception state */
	mutex_lock(&vcpu->mutex);
	r = kvm_vmi_inject_event(vcpu, inject);
	mutex_unlock(&vcpu->mutex);
	return r;
}

static void free_vcpu_vmi(struct rcu_head *head)
{
	kfree(container_of(head, struct kvm_vcpu_vmi, rcu_head));
}

/**
 * kvm_vmi_release - Tear down the VMI session when vmi_fd is closed.
 *
 * Disables all monitoring, destroys views, frees rings, and detaches
 * per-vCPU VMI state.  All vcpu->vmi access is inside SRCU read
 * sections, so NULLing the pointer + call_srcu() safely defers kfree
 * until readers have finished.  synchronize_srcu() then ensures both
 * the per-vCPU and VM-wide state are freed before we return.
 */
static int kvm_vmi_release(struct inode *inode, struct file *file)
{
	struct kvm *kvm = file->private_data;
	struct kvm_vmi *vmi = kvm_vmi_get(kvm);
	struct kvm_vcpu *vcpu;
	struct kvm_vmi_view_data *view;
	struct page *page;
	unsigned long i, index;

	trace_kvm_vmi_session(false);

	if (!vmi)
		goto out;

	/* Signal all vCPUs to teardown and wake any blocked ones */
	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (!vcpu->vmi)
			continue;
		vcpu->vmi->teardown = true;
		atomic_set(&vcpu->vmi->pause_count, 0);
		wake_up(&vcpu->vmi->wq);
		wake_up(&vcpu->vmi->pause_wq);
		kvm_vcpu_kick(vcpu);
	}

	/* Clear VM-wide event monitoring state */
	vmi->enabled_events = 0;
	kvm_arch_vmi_session_reset(vmi);

	/*
	 * Disable events and switch to view 0 on each vCPU.
	 * Only update in-memory state here - we cannot write VMCS
	 * fields from this thread. The vCPU threads will pick up
	 * the changes via kvm_arch_vmi_update() at the end.
	 */
	kvm_for_each_vcpu(i, vcpu, kvm) {
		struct kvm_vmi_view_data *old_view;
		struct kvm_vcpu_vmi *vcpu_vmi = vcpu->vmi;

		if (!vcpu_vmi)
			continue;
		kvm_arch_vmi_reset_vcpu_state(vcpu);

		if (vcpu_vmi->current_view_id != 0) {
			old_view = xa_load(&vmi->views,
					   vcpu_vmi->current_view_id);
			if (old_view)
				atomic_dec(&old_view->vcpu_count);
			vcpu_vmi->current_view_id = 0;
			WRITE_ONCE(vcpu_vmi->current_view, NULL);
			/*
			 * The vCPU was on an alternate view. Ask the
			 * arch layer to reload the host page table
			 * root on next entry.
			 */
			kvm_arch_vmi_reset_view(vcpu);
		}
	}

	/* Schedule VMCS sync on all vCPUs */
	kvm_arch_vmi_update(kvm);

	/*
	 * Wait for any in-flight page faults to complete.  Page faults
	 * hold mmu_lock for read while accessing current_view and the
	 * page table root.  After this write-lock cycle completes, all
	 * such faults have finished, and new ones will see
	 * current_view=NULL (written above) and fall through to the
	 * primary root.
	 */
	write_lock(&kvm->mmu_lock);
	write_unlock(&kvm->mmu_lock);

	/* Free all shadow pages */
	xa_for_each(&vmi->shadow_pages, index, page) {
		xa_erase(&vmi->shadow_pages, index);
		__free_page(page);
	}
	xa_destroy(&vmi->shadow_pages);

	/* Destroy all non-zero views */
	xa_for_each(&vmi->views, index, view) {
		if (index == 0)
			continue;
		xa_erase(&vmi->views, index);
		kvm_arch_vmi_destroy_view(kvm, view);
		xa_destroy(&view->gfn_overrides);
		xa_destroy(&view->access_overrides);
		kfree(view);
	}

	/*
	 * Free per-vCPU ring state, then detach and schedule deferred
	 * free of per-vCPU VMI structs.  All vcpu->vmi readers
	 * are inside SRCU, so NULLing the pointer ensures new readers
	 * see NULL, and call_srcu() defers kfree until existing
	 * readers finish.
	 */
	kvm_for_each_vcpu(i, vcpu, kvm) {
		struct kvm_vcpu_vmi *vcpu_vmi = vcpu->vmi;

		if (!vcpu_vmi)
			continue;
		kvm_vmi_free_ring(vcpu);
		WRITE_ONCE(vcpu->vmi, NULL);
		call_srcu(&kvm->srcu, &vcpu_vmi->rcu_head, free_vcpu_vmi);
	}

	/*
	 * Detach VM-wide VMI.  synchronize_srcu() waits for all
	 * existing SRCU readers to finish, which also guarantees
	 * the call_srcu() callbacks above have completed.
	 */
	mutex_lock(&kvm->lock);
	rcu_assign_pointer(kvm->vmi, NULL);
	mutex_unlock(&kvm->lock);
	synchronize_srcu(&kvm->srcu);

	kvm_arch_vmi_session_cleanup(vmi);
	xa_destroy(&vmi->views);
	mutex_destroy(&vmi->lock);
	kfree(vmi);

out:
	kvm_put_kvm(kvm);
	return 0;
}

static long kvm_vmi_ioctl(struct file *file, unsigned int ioctl,
			  unsigned long arg)
{
	struct kvm *kvm = file->private_data;
	void __user *argp = (void __user *)arg;

	switch (ioctl) {
	case KVM_VMI_SETUP_RING: {
		struct kvm_vmi_setup_ring setup;
		int r;

		if (copy_from_user(&setup, argp, sizeof(setup)))
			return -EFAULT;
		r = kvm_vmi_setup_ring(kvm, &setup);
		if (r)
			return r;
		if (copy_to_user(argp, &setup, sizeof(setup)))
			return -EFAULT;
		return 0;
	}
	case KVM_VMI_TEARDOWN_RING: {
		u32 vcpu_id;

		if (get_user(vcpu_id, (u32 __user *)argp))
			return -EFAULT;
		return kvm_vmi_teardown_ring(kvm, vcpu_id);
	}
	case KVM_VMI_CONTROL_EVENT: {
		struct kvm_vmi_control_event ctrl;

		if (copy_from_user(&ctrl, argp, sizeof(ctrl)))
			return -EFAULT;
		return kvm_vmi_control_event(kvm, &ctrl);
	}
	case KVM_VMI_ACK_EVENT: {
		struct kvm_vmi_vcpu ack;

		if (copy_from_user(&ack, argp, sizeof(ack)))
			return -EFAULT;
		return kvm_vmi_ack_event(kvm, &ack);
	}
	case KVM_VMI_CREATE_VIEW: {
		struct kvm_vmi_view view;
		int r;

		if (copy_from_user(&view, argp, sizeof(view)))
			return -EFAULT;
		r = kvm_vmi_create_view(kvm, &view);
		if (r)
			return r;
		if (copy_to_user(argp, &view, sizeof(view)))
			return -EFAULT;
		return 0;
	}
	case KVM_VMI_DESTROY_VIEW: {
		struct kvm_vmi_view view;

		if (copy_from_user(&view, argp, sizeof(view)))
			return -EFAULT;
		return kvm_vmi_destroy_view(kvm, &view);
	}
	case KVM_VMI_SWITCH_VIEW: {
		struct kvm_vmi_switch_view sv;

		if (copy_from_user(&sv, argp, sizeof(sv)))
			return -EFAULT;
		return kvm_vmi_switch_view(kvm, &sv);
	}
	case KVM_VMI_GET_MEM_ACCESS: {
		struct kvm_vmi_mem_access ma;
		int r;

		if (copy_from_user(&ma, argp, sizeof(ma)))
			return -EFAULT;
		r = kvm_vmi_get_mem_access(kvm, &ma);
		if (r)
			return r;
		if (copy_to_user(argp, &ma, sizeof(ma)))
			return -EFAULT;
		return 0;
	}
	case KVM_VMI_SET_MEM_ACCESS: {
		struct kvm_vmi_mem_access ma;

		if (copy_from_user(&ma, argp, sizeof(ma)))
			return -EFAULT;
		return kvm_vmi_set_mem_access(kvm, &ma);
	}
	case KVM_VMI_ALLOC_GFN: {
		struct kvm_vmi_alloc_gfn alloc = {};
		int r;

		r = kvm_vmi_alloc_gfn(kvm, &alloc);
		if (r)
			return r;
		if (copy_to_user(argp, &alloc, sizeof(alloc)))
			return -EFAULT;
		return 0;
	}
	case KVM_VMI_FREE_GFN: {
		struct kvm_vmi_free_gfn free_req;

		if (copy_from_user(&free_req, argp, sizeof(free_req)))
			return -EFAULT;
		return kvm_vmi_free_gfn(kvm, file, &free_req);
	}
	case KVM_VMI_CHANGE_GFN: {
		struct kvm_vmi_change_gfn change;

		if (copy_from_user(&change, argp, sizeof(change)))
			return -EFAULT;
		return kvm_vmi_change_gfn(kvm, &change);
	}
	case KVM_VMI_PAUSE_VM:
		return kvm_vmi_pause_vm(kvm);
	case KVM_VMI_UNPAUSE_VM:
		return kvm_vmi_unpause_vm(kvm);
	case KVM_VMI_PAUSE_VCPU: {
		struct kvm_vmi_vcpu v;

		if (copy_from_user(&v, argp, sizeof(v)))
			return -EFAULT;
		return kvm_vmi_pause_vcpu_ioctl(kvm, v.vcpu_id);
	}
	case KVM_VMI_UNPAUSE_VCPU: {
		struct kvm_vmi_vcpu v;

		if (copy_from_user(&v, argp, sizeof(v)))
			return -EFAULT;
		return kvm_vmi_unpause_vcpu_ioctl(kvm, v.vcpu_id);
	}
	case KVM_VMI_INJECT_EVENT: {
		struct kvm_vmi_inject_event inject;

		if (copy_from_user(&inject, argp, sizeof(inject)))
			return -EFAULT;
		return kvm_vmi_inject_event_ioctl(kvm, &inject);
	}
	default:
		return -ENOTTY;
	}
}

static vm_fault_t kvm_vmi_guest_fault(struct vm_fault *vmf)
{
	struct kvm *kvm = vmf->vma->vm_private_data;
	gfn_t gfn = vmf->pgoff;
	unsigned long hva;
	struct page *page;
	vm_fault_t ret;
	int r;

	/* Check if this is a VMI-allocated shadow page */
	if (gfn >= KVM_VMI_SHADOW_GFN_BASE && kvm->vmi) {
		page = xa_load(&kvm->vmi->shadow_pages, gfn);
		if (!page)
			return VM_FAULT_SIGBUS;
		return vmf_insert_pfn(vmf->vma, vmf->address,
				      page_to_pfn(page));
	}

	hva = gfn_to_hva(kvm, gfn);
	if (kvm_is_error_hva(hva))
		return VM_FAULT_SIGBUS;

	/*
	 * Resolve the guest page via the VM owner's address space.
	 *
	 * Use vmf_insert_pfn() rather than returning the page via
	 * vmf->page to avoid RSS counter mismatches: foreign anonymous
	 * pages returned via vmf->page are accounted as MM_SHMEMPAGES
	 * on fault (swapbacked), but classified as MM_ANONPAGES on
	 * unmap (folio_test_anon), causing "Bad rss-counter state"
	 * warnings on process exit. PFN mappings bypass RSS accounting.
	 */
	mmap_read_lock(kvm->mm);
	r = get_user_pages_remote(kvm->mm, hva, 1,
				  FOLL_WRITE, &page, NULL);
	mmap_read_unlock(kvm->mm);
	if (r < 0)
		return VM_FAULT_SIGBUS;

	ret = vmf_insert_pfn(vmf->vma, vmf->address, page_to_pfn(page));
	put_page(page);
	return ret;
}

static const struct vm_operations_struct kvm_vmi_guest_vm_ops = {
	.fault = kvm_vmi_guest_fault,
};

static int kvm_vmi_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct kvm *kvm = file->private_data;

	if (!kvm->vmi)
		return -EINVAL;

	vma->vm_ops = &kvm_vmi_guest_vm_ops;
	vma->vm_private_data = kvm;
	vm_flags_set(vma, VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP);
	return 0;
}

static const struct file_operations kvm_vmi_fops = {
	.owner = THIS_MODULE,
	.release = kvm_vmi_release,
	.unlocked_ioctl = kvm_vmi_ioctl,
	.mmap = kvm_vmi_mmap,
	.llseek = noop_llseek,
};
