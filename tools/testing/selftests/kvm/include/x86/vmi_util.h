/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * KVM VMI test utilities
 *
 * Shared helper functions for VMI selftests using the
 * ring-based event delivery via vmi_fd.
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

int vmi_create(struct kvm_vm *vm);
void vmi_setup_ring(int vmi_fd, uint32_t vcpu_id, struct vmi_test_ring *r);
struct kvm_vmi_ring_event *vmi_wait_event(struct vmi_test_ring *r);
struct kvm_vmi_ring_event *vmi_wait_event_timeout(struct vmi_test_ring *r,
						  int timeout_ms);
void vmi_ack_event(struct vmi_test_ring *r, uint32_t vcpu_id);
void vmi_control_event(int vmi_fd, uint32_t event, int enable);
int vmi_control_event_err(int vmi_fd, uint32_t event, int enable);
void vmi_pause_vm(int vmi_fd);
void vmi_unpause_vm(int vmi_fd);
void vmi_pause_vcpu(int vmi_fd, uint32_t vcpu_id);
void vmi_unpause_vcpu(int vmi_fd, uint32_t vcpu_id);
void vmi_inject_event(int vmi_fd, uint32_t vcpu_id, uint8_t vector,
		      uint8_t type, uint32_t error_code, int has_error,
		      uint8_t insn_len);
void vmi_teardown_ring(struct vmi_test_ring *r);
void *vmi_vcpu_thread_fn(void *arg);
int vmi_test_setup(struct kvm_vm **vm, struct kvm_vcpu **vcpu,
		   void (*guest_fn)(void), struct vmi_test_ring *ring);
void vmi_test_teardown(struct kvm_vm *vm, int vmi_fd,
		       struct vmi_test_ring *ring);

#endif /* SELFTEST_KVM_VMI_UTIL_H */
