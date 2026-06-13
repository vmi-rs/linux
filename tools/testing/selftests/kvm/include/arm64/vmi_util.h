/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * KVM VMI test utilities (arm64)
 *
 * Shared helper functions for VMI selftests using the ring-based event
 * delivery via vmi_fd. These arch-neutral helpers mirror the x86 harness
 * (tools/testing/selftests/kvm/include/x86/vmi_util.h). The arm64-specific
 * helpers (vmi_control_sysreg, vmi_inject_event) are added by their
 * implementing commits (system-register monitoring, event injection).
 */
#ifndef SELFTEST_KVM_VMI_UTIL_H
#define SELFTEST_KVM_VMI_UTIL_H

#include <linux/kvm.h>
#include <linux/kvm_vmi.h>
#include <stdint.h>

#include "kvm_util.h"

/* Per-vCPU ring state for test use */
struct vmi_test_ring {
	int vmi_fd;
	int ring_fd;
	int event_fd;
	int ack_fd;
	struct kvm_vmi_ring_header *ring;
	struct kvm_vmi_ring_event *slots;
	uint32_t local_cons;	/* local consumer index tracking */
};

struct vmi_vcpu_thread_arg {
	struct kvm_vcpu *vcpu;
	volatile int done;
};

/*
 * Force VMI test guests to run at EL1. Call before creating the VM.
 *
 * On a nested-capable host (kvm-arm.mode=nested) the selftest framework
 * auto-promotes guests to vEL2 (KVM_ARM_VCPU_HAS_EL2; see vm_supports_el2()),
 * which changes the EL1 system-register / HVC / exception-injection and
 * stage-2 view semantics these tests rely on. VMI targets a guest OS running
 * at EL1 (mirroring the x86 series); introspecting a vEL2 guest hypervisor
 * (e.g. Windows with VBS) is future work. Opt out via the framework's NV knob.
 */
void vmi_force_el1_guests(void);

int vmi_create(struct kvm_vm *vm);
void vmi_setup_ring(int vmi_fd, uint32_t vcpu_id, struct vmi_test_ring *r);
struct kvm_vmi_ring_event *vmi_wait_event(struct vmi_test_ring *r);
struct kvm_vmi_ring_event *vmi_wait_event_timeout(struct vmi_test_ring *r,
						  int timeout_ms);
void vmi_ack_event(struct vmi_test_ring *r, uint32_t vcpu_id);
void vmi_control_event(int vmi_fd, uint32_t event, int enable);
int vmi_control_event_err(int vmi_fd, uint32_t event, int enable);
uint32_t vmi_create_view(int vmi_fd, uint8_t default_access);
void vmi_destroy_view(int vmi_fd, uint32_t view_id);
int vmi_destroy_view_err(int vmi_fd, uint32_t view_id);
void vmi_switch_view(int vmi_fd, uint32_t view_id);
void vmi_set_mem_access(int vmi_fd, uint32_t view_id, uint64_t gfn,
			uint8_t access);
void vmi_change_gfn(int vmi_fd, uint32_t view_id, uint64_t old_gfn,
		    uint64_t new_gfn);
uint64_t vmi_alloc_gfn(int vmi_fd);
void vmi_free_gfn(int vmi_fd, uint64_t gfn);
void vmi_pause_vm(int vmi_fd);
void vmi_unpause_vm(int vmi_fd);
void vmi_pause_vcpu(int vmi_fd, uint32_t vcpu_id);
void vmi_unpause_vcpu(int vmi_fd, uint32_t vcpu_id);
/*
 * Issue KVM_VMI_INJECT_EVENT. Returns 0 on success, or -errno on failure
 * (so callers can assert specific validation errors, e.g. == -EINVAL).
 */
int vmi_inject_event(int vmi_fd, struct kvm_vmi_inject_event *inject);
void vmi_teardown_ring(struct vmi_test_ring *r);
void *vmi_vcpu_thread_fn(void *arg);
int vmi_test_setup(struct kvm_vm **vm, struct kvm_vcpu **vcpu,
		   void (*guest_fn)(void), struct vmi_test_ring *ring);
void vmi_test_teardown(struct kvm_vm *vm, int vmi_fd,
		       struct vmi_test_ring *ring);

#endif /* SELFTEST_KVM_VMI_UTIL_H */
