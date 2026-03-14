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
	kvm_arch_vmi_session_init(vmi);

	rcu_assign_pointer(kvm->vmi, vmi);

	/* Initialize VMI state for any already-created vCPUs */
	kvm_for_each_vcpu(i, vcpu, kvm) {
		r = kvm_vmi_vcpu_init(vcpu);
		if (r)
			goto err_rollback;
	}

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
	kvm_arch_vmi_session_cleanup(vmi);
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

	/* Mask to known flags */
	resp &= KVM_VMI_RESPONSE_MASK;

	trace_kvm_vmi_event_response(vcpu->vcpu_id, event_type, resp);

	/* Restore GP registers if agent modified them */
	if (resp & KVM_VMI_RESPONSE_SET_REGS)
		kvm_vmi_restore_regs(vcpu, &event->regs);

	/* Dispatch to arch-specific response handler */
	kvm_vmi_handle_event_response(vcpu, event_type, resp);

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

	slot->response = 0;
	slot->view_id = 0;

	/* Publish event: ensure all writes are visible before prod update */
	smp_wmb();
	WRITE_ONCE(hdr->req_prod, prod + 1);

	/* Signal agent */
	eventfd_signal(vcpu_vmi->event_fd_ctx);

	/*
	 * Release vcpu->mutex and unload vCPU state before blocking so the
	 * agent can call standard KVM vCPU ioctls on the duplicated vCPU fd
	 * while the vCPU is parked. kvm_arch_vmi_block_begin()/_end() shed and
	 * re-take any per-vCPU read-side lock the arch run loop holds (the SRCU
	 * read lock on x86; nothing on arm64), so synchronize_srcu() in
	 * kvm_vmi_release() can complete.
	 */
	kvm_arch_vmi_block_begin(vcpu);
	vcpu_put(vcpu);
	mutex_unlock(&vcpu->mutex);

	/*
	 * Safe to access vcpu_vmi here: kvm_vmi_release() sets
	 * teardown=true and wakes this waitqueue before call_srcu(),
	 * so the wait completes while the struct is still alive.
	 *
	 * Check teardown FIRST. kvm_vmi_free_ring() sets teardown=true before it
	 * __free_page()s the ring, so once teardown is observed @hdr points into
	 * a freed page and must NOT be dereferenced; the short-circuit keeps this
	 * wakeup off the freed page. (The producer "top section" above is kept off
	 * it by vcpu->mutex, which kvm_vmi_deliver_via_ring() holds at that point.)
	 */
	wait_event(vcpu_vmi->wq,
		vcpu_vmi->teardown ||
		READ_ONCE(hdr->req_cons) > prod);

	mutex_lock(&vcpu->mutex);
	vcpu_load(vcpu);
	kvm_arch_vmi_block_end(vcpu);

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
	 * Escape on session_teardown, not the ring-scoped teardown flag: a
	 * KVM_VMI_TEARDOWN_RING leaves teardown=true on a live session, so
	 * keying off it would let this vCPU spin out of a later pause. Only
	 * kvm_vmi_release() sets session_teardown, and it wakes this waitqueue
	 * before call_srcu(), so the wait completes while the struct is alive.
	 */
	wait_event(vcpu_vmi->pause_wq,
		atomic_read(&vcpu_vmi->pause_count) == 0 ||
		vcpu_vmi->session_teardown);

	/*
	 * Don't touch vcpu_vmi past this point - call_srcu() may
	 * have freed it while we were outside SRCU.
	 */
	mutex_lock(&vcpu->mutex);
	vcpu_load(vcpu);
}

/*
 * vmi_fd ioctl handlers
 */

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

	/*
	 * Precondition: the caller has paused the VM, so this vCPU is parked in
	 * kvm_vmi_vcpu_pause_wait() with vcpu->mutex droppable. That lets the
	 * mutex_lock() below acquire promptly instead of deadlocking against an
	 * arm64 WFI-halted vCPU that would otherwise hold the mutex.
	 */
	WARN_ON_ONCE(!kvm_vmi_vcpu_paused(vcpu));

	/*
	 * Take vcpu->mutex to exclude the kvm_vmi_deliver_via_ring() producer
	 * top section that writes the ring page in HOST mode -- pausing the VM
	 * does not wait for it. KVM_REQ_OUTSIDE_GUEST_MODE only forces vCPUs
	 * out of GUEST mode, but that section runs post-vmexit with vcpu->mode
	 * already OUTSIDE_GUEST_MODE, so kvm_make_all_cpus_request() skips it.
	 * The mutex is the barrier that waits for that writer before we free
	 * the page. (Other ring accessors check the teardown flag set below.)
	 */
	mutex_lock(&vcpu->mutex);

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

	mutex_unlock(&vcpu->mutex);
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

	/*
	 * Pause the VM so every vCPU parks in the run-loop pause check with
	 * vcpu->mutex dropped before kvm_vmi_free_ring() takes it. A WFI-halted
	 * vCPU holds vcpu->mutex across KVM_RUN and a bare kick can't drop it
	 * on arm64, so free_ring would otherwise deadlock. close(vmi_fd) is
	 * safe only because release() pauses first; this ioctl does not.
	 */
	kvm_vmi_pause_vm(kvm);
	kvm_vmi_free_ring(vcpu);
	kvm_vmi_unpause_vm(kvm);
	return 0;
}

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
	if (!vcpu_vmi)
		return -EINVAL;

	/*
	 * Serialize against kvm_vmi_free_ring(), which __free_page()s the ring
	 * and NULLs ->ring WITHOUT holding vcpu->mutex. We take vcpu->mutex here
	 * to exclude free_ring. kvm_vmi_ioctl() is .unlocked_ioctl,
	 * so a concurrent KVM_VMI_TEARDOWN_RING on this same vmi_fd can free the
	 * ring between a lock-free !ring check and the req_cons write below ->
	 * use-after-free on the freed ring page. The ack caller is an agent
	 * thread, not a vCPU, so the teardown path (which sets teardown=true and
	 * calls wake_up()) does not park it; only this mutex excludes the freer. Taking it cannot deadlock:
	 * the ack path runs in process context holding no other lock (vcpu->mutex
	 * is outermost), and the vCPU thread drops vcpu->mutex in
	 * kvm_vmi_deliver_via_ring() before blocking on the very ack this advances.
	 */
	mutex_lock(&vcpu->mutex);

	/* Re-check under the lock: free_ring may have torn the ring down. */
	if (vcpu_vmi->teardown || !vcpu_vmi->ring) {
		mutex_unlock(&vcpu->mutex);
		return -EINVAL;
	}

	/*
	 * Advance the consumer index. The agent has already written the response
	 * to the ring slot; this makes it visible to the blocked vCPU thread.
	 */
	smp_wmb();
	WRITE_ONCE(vcpu_vmi->ring->req_cons, vcpu_vmi->ring->req_cons + 1);

	/* Wake the blocked vCPU */
	wake_up(&vcpu_vmi->wq);

	mutex_unlock(&vcpu->mutex);
	return 0;
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
	struct kvm_vmi *vmi;
	u32 event = ctrl->event;
	int r = 0;
	int srcu_idx;

	/*
	 * Take kvm->srcu before vmi->lock
	 * so the kvm_vmi_get() here and the nested one in the arch
	 * kvm_arch_vmi_control_event() hook both deref kvm->vmi under SRCU,
	 * not bare under vmi->lock. control_event never blocks, so holding
	 * SRCU across the whole call is fine.
	 */
	srcu_idx = srcu_read_lock(&kvm->srcu);
	vmi = kvm_vmi_get(kvm);

	if (!vmi) {
		r = -EINVAL;
		goto out_srcu;
	}

	if (event >= KVM_VMI_NUM_EVENTS) {
		r = -EINVAL;
		goto out_srcu;
	}

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
out_srcu:
	srcu_read_unlock(&kvm->srcu, srcu_idx);
	return r;
}

/*
 * The single VMI teardown-quiesce primitive: park every vCPU off its
 * vcpu->mutex so a non-run-loop teardown thread can take that mutex. All
 * teardown paths route through this (release, teardown_ring, free_ring's
 * precondition). A bare kvm_vcpu_kick() does not drop the mutex on an arm64
 * WFI-halted vCPU, so both requests below are needed.
 *
 * Increments pause_count on all vCPUs, then handles three vCPU states:
 *  - In guest mode: KVM_REQ_OUTSIDE_GUEST_MODE forces a VM-exit and
 *    waits for acknowledgement (Dekker barrier pattern).
 *  - Halted/sleeping (HLT, kvm_vcpu_block): KVM_REQ_UNBLOCK wakes
 *    them (KVM_REQ_OUTSIDE_GUEST_MODE has KVM_REQUEST_NO_WAKEUP).
 *  - Not in KVM_RUN: vcpu->mutex is already free.
 *
 * After return, vCPUs reach the pause check at the top of vcpu_run() and
 * release vcpu->mutex. KVM_GET_REGS from the VMI agent serializes on
 * vcpu->mutex, so no explicit barrier is needed here.
 */
int kvm_vmi_pause_vm(struct kvm *kvm)
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

int kvm_vmi_unpause_vm(struct kvm *kvm)
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

/*
 * KVM_VMI_GET_MEM_INFO: report the guest RAM extent.
 *
 * Returns the exclusive upper-bound GFN of guest RAM, the maximum of
 * base_gfn + npages over all memslots. The agent rejects reads of frames at or
 * above this bound (which the VMM did not back with RAM) instead of faulting
 * the vmi_fd mmap. KVM has no memslot-enumeration ioctl, so the agent cannot
 * otherwise learn the layout the VMM programmed.
 */
static int kvm_vmi_get_mem_info(struct kvm *kvm, struct kvm_vmi_mem_info *info)
{
	struct kvm_memory_slot *memslot;
	struct kvm_memslots *slots;
	gfn_t max_gfn = 0;
	int bkt, idx;

	idx = srcu_read_lock(&kvm->srcu);
	slots = kvm_memslots(kvm);
	kvm_for_each_memslot(memslot, bkt, slots) {
		gfn_t end = memslot->base_gfn + memslot->npages;

		if (end > max_gfn)
			max_gfn = end;
	}
	srcu_read_unlock(&kvm->srcu, idx);

	info->max_gfn = max_gfn;
	info->pad = 0;
	return 0;
}

static void free_vcpu_vmi(struct rcu_head *head)
{
	kfree(container_of(head, struct kvm_vcpu_vmi, rcu_head));
}

/**
 * kvm_vmi_release - Tear down the VMI session when vmi_fd is closed.
 *
 * Clears event monitoring state, resets arch-specific config, frees the
 * per-vCPU ring state, detaches each per-vCPU VMI struct, NULLs the kvm->vmi
 * pointer, then waits for an SRCU grace period before freeing the kvm_vmi
 * allocation.  The per-vCPU structs are freed via call_srcu() so the kfree
 * outlives any in-flight lock-free SRCU reader.  Alternate-view teardown is
 * added by a later commit.
 */
static int kvm_vmi_release(struct inode *inode, struct file *file)
{
	struct kvm *kvm = file->private_data;
	struct kvm_vmi *vmi;
	struct kvm_vcpu *vcpu;
	unsigned long i;
	int srcu_idx;

	trace_kvm_vmi_session(false);

	/*
	 * kvm_vmi_get() must run under kvm->srcu (or kvm->lock); take srcu just
	 * for the deref. The VMI session is torn down only here, on the last
	 * vmi_fd put, so the returned pointer stays valid for the rest of this
	 * function without holding srcu -- and we must not hold it across the
	 * synchronize_srcu() below.
	 */
	srcu_idx = srcu_read_lock(&kvm->srcu);
	vmi = kvm_vmi_get(kvm);
	srcu_read_unlock(&kvm->srcu, srcu_idx);

	if (!vmi)
		goto out;

	/*
	 * Pause every vCPU so it parks with vcpu->mutex dropped before the
	 * mutex_lock()s below (free_ring later) take
	 * it. A WFI-halted or in-guest vCPU holds vcpu->mutex across KVM_RUN,
	 * and a bare kick can't drop it on arm64, so those would deadlock and
	 * wedge close(vmi_fd) in 'D'. The pause escape keys on
	 * session_teardown, which the loop below sets only after free_ring
	 * returns, so every vCPU stays parked through the whole teardown.
	 */
	kvm_vmi_pause_vm(kvm);

	/* Clear VM-wide event monitoring state */
	vmi->enabled_events = 0;
	kvm_arch_vmi_session_reset(vmi);

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
		/*
		 * Now release the parked vCPU: free_ring() ran while it was
		 * still parked. Set session_teardown and clear pause_count, and
		 * wake; the vCPU sees pause_count==0 and exits the pause check.
		 * Order pause_count=0 before NULLing vcpu->vmi so the woken
		 * run-loop pause check does not spin awaiting the NULL.
		 */
		vcpu_vmi->session_teardown = true;
		atomic_set(&vcpu_vmi->pause_count, 0);
		wake_up(&vcpu_vmi->pause_wq);
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
	case KVM_VMI_ACK_EVENT: {
		struct kvm_vmi_vcpu ack;

		if (copy_from_user(&ack, argp, sizeof(ack)))
			return -EFAULT;
		return kvm_vmi_ack_event(kvm, &ack);
	}
	case KVM_VMI_CONTROL_EVENT: {
		struct kvm_vmi_control_event ctrl;

		if (copy_from_user(&ctrl, argp, sizeof(ctrl)))
			return -EFAULT;
		return kvm_vmi_control_event(kvm, &ctrl);
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
	case KVM_VMI_GET_MEM_INFO: {
		struct kvm_vmi_mem_info info = {};
		int r;

		r = kvm_vmi_get_mem_info(kvm, &info);
		if (r)
			return r;
		if (copy_to_user(argp, &info, sizeof(info)))
			return -EFAULT;
		return 0;
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
	bool same_mm;
	int srcu_idx;
	int r;

	/* gfn_to_hva() walks the memslots; hold kvm->srcu across the lookup. */
	srcu_idx = srcu_read_lock(&kvm->srcu);
	hva = gfn_to_hva(kvm, gfn);
	srcu_read_unlock(&kvm->srcu, srcu_idx);
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
	 *
	 * get_user_pages_remote() with locked==NULL requires mmap_lock held but
	 * does not drop it. The page-fault path that invokes this .fault handler
	 * already holds the faulting VMA's mm (vmf->vma->vm_mm) mmap_lock for
	 * read. So when GUP below would walk that very mm -- i.e. kvm->mm ==
	 * vmf->vma->vm_mm, the single-process case where one task both created
	 * the VM and mmap'd its own guest memory (the selftests) -- re-taking it
	 * here would be a recursive read_lock (deadlock-prone if a writer queues).
	 * Only acquire it when GUP walks a different mm than the fault path holds
	 * -- the normal reactor case, where a separate agent process maps and
	 * faults the guest's memory.
	 *
	 * Key the test on vmf->vma->vm_mm (the mm whose mmap_lock the fault path
	 * actually holds), NOT current->mm (the faulting *task*). They coincide
	 * for every path that can reach here today: a VM_PFNMAP VMA is faulted
	 * only by a direct CPU access in the task's own address space, because GUP
	 * rejects VM_PFNMAP in check_vma_flags() before ever calling .fault, so no
	 * foreign-current remote faulter (process_vm_readv, /proc/pid/mem, ptrace)
	 * reaches this handler. But vmf->vma->vm_mm is the only correct expression
	 * of "is the lock already held": should the VMA's flags or vm_ops ever
	 * change to admit a remote faulter, current->mm would mis-detect the held
	 * lock and reintroduce the recursive read_lock.
	 */
	same_mm = kvm->mm == vmf->vma->vm_mm;
	if (!same_mm)
		mmap_read_lock(kvm->mm);
	r = get_user_pages_remote(kvm->mm, hva, 1,
				  FOLL_WRITE, &page, NULL);
	if (!same_mm)
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
