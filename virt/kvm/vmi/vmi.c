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

	vmi = kzalloc_obj(*vmi, GFP_KERNEL_ACCOUNT);
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

	vcpu_vmi = kzalloc_obj(*vcpu_vmi, GFP_KERNEL_ACCOUNT);
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
 * kvm_vmi_release - Tear down the VMI session when vmi_fd is closed.
 *
 * Clears event monitoring state, resets arch-specific config, NULLs
 * the kvm->vmi pointer, then waits for an SRCU grace period before
 * freeing the kvm_vmi allocation.  Per-vCPU VMI state cleanup is
 * deferred to kvm_vmi_destroy() (the VM-destroy path); view and ring
 * teardown will be added in later commits.
 */
static int kvm_vmi_release(struct inode *inode, struct file *file)
{
	struct kvm *kvm = file->private_data;
	struct kvm_vmi *vmi;
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

	/* Clear VM-wide event monitoring state */
	vmi->enabled_events = 0;
	kvm_arch_vmi_session_reset(vmi);

	rcu_assign_pointer(kvm->vmi, NULL);
	synchronize_srcu(&kvm->srcu);

	kfree(vmi);

out:
	kvm_put_kvm(kvm);
	return 0;
}

static long kvm_vmi_ioctl(struct file *file, unsigned int ioctl,
			  unsigned long arg)
{
	switch (ioctl) {
	default:
		return -ENOTTY;
	}
}

static const struct file_operations kvm_vmi_fops = {
	.owner = THIS_MODULE,
	.release = kvm_vmi_release,
	.unlocked_ioctl = kvm_vmi_ioctl,
	.llseek = noop_llseek,
};
