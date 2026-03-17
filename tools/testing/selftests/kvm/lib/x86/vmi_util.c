// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI test utilities
 *
 * Shared helper functions for VMI selftests using the
 * ring-based event delivery via vmi_fd.
 */
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <pthread.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

/*
 * Create a VMI session. Returns vmi_fd.
 */
int vmi_create(struct kvm_vm *vm)
{
	int fd;

	fd = __vm_ioctl(vm, KVM_CREATE_VMI, NULL);
	TEST_ASSERT(fd >= 0, "KVM_CREATE_VMI failed: %d", fd);
	return fd;
}

/*
 * Set up a ring for a vCPU. Allocates eventfds, calls setup ioctl,
 * mmaps the ring page.
 */
void vmi_setup_ring(int vmi_fd, uint32_t vcpu_id, struct vmi_test_ring *r)
{
	struct kvm_vmi_setup_ring setup = {};
	int ret;

	setup.vcpu_id = vcpu_id;
	setup.event_fd = eventfd(0, EFD_CLOEXEC);
	TEST_ASSERT(setup.event_fd >= 0, "eventfd() for event_fd failed");
	setup.ack_fd = eventfd(0, EFD_CLOEXEC);
	TEST_ASSERT(setup.ack_fd >= 0, "eventfd() for ack_fd failed");

	ret = ioctl(vmi_fd, KVM_VMI_SETUP_RING, &setup);
	TEST_ASSERT(ret == 0, "KVM_VMI_SETUP_RING failed: %d (errno=%d)",
		    ret, errno);

	r->vmi_fd = vmi_fd;
	r->event_fd = setup.event_fd;
	r->ack_fd = setup.ack_fd;
	r->ring_fd = setup.ring_fd;

	r->ring = mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE,
		       MAP_SHARED, setup.ring_fd, 0);
	TEST_ASSERT(r->ring != MAP_FAILED, "mmap ring_fd failed");
	r->slots = (struct kvm_vmi_ring_event *)((char *)r->ring +
		    sizeof(struct kvm_vmi_ring_header));
	r->local_cons = 0;
}

/*
 * Wait for a ring event. Blocks on event_fd, returns pointer to the
 * ring event slot.
 */
struct kvm_vmi_ring_event *vmi_wait_event(struct vmi_test_ring *r)
{
	uint64_t val;
	int ret;

	ret = read(r->event_fd, &val, sizeof(val));
	TEST_ASSERT(ret == sizeof(val), "read event_fd failed: %d", ret);
	return &r->slots[r->local_cons % r->ring->num_slots];
}

/*
 * Wait for a ring event with timeout (milliseconds).
 * Returns pointer to event, or NULL on timeout.
 */
struct kvm_vmi_ring_event *vmi_wait_event_timeout(struct vmi_test_ring *r,
						  int timeout_ms)
{
	struct pollfd pfd = { .fd = r->event_fd, .events = POLLIN };
	uint64_t val;
	int ret;

	ret = poll(&pfd, 1, timeout_ms);
	if (ret <= 0)
		return NULL;
	ret = read(r->event_fd, &val, sizeof(val));
	TEST_ASSERT(ret == sizeof(val), "read event_fd failed");
	return &r->slots[r->local_cons % r->ring->num_slots];
}

/*
 * Acknowledge a ring event. The caller should have already written
 * the response field in the ring event slot.
 */
void vmi_ack_event(struct vmi_test_ring *r, uint32_t vcpu_id)
{
	struct kvm_vmi_vcpu ack = { .vcpu_id = vcpu_id };
	int ret;

	r->local_cons++;
	ret = ioctl(r->vmi_fd, KVM_VMI_ACK_EVENT, &ack);
	TEST_ASSERT(ret == 0, "KVM_VMI_ACK_EVENT failed: %d", ret);
}

/*
 * Control event via vmi_fd.
 */
void vmi_control_event(int vmi_fd, uint32_t event, int enable)
{
	struct kvm_vmi_control_event ctl = {};
	int ret;

	ctl.event = event;
	ctl.enable = enable;

	ret = ioctl(vmi_fd, KVM_VMI_CONTROL_EVENT, &ctl);
	TEST_ASSERT(ret == 0, "KVM_VMI_CONTROL_EVENT failed: %d", ret);
}

/* Variant that returns errno instead of asserting */
int vmi_control_event_err(int vmi_fd, uint32_t event, int enable)
{
	struct kvm_vmi_control_event ctl = {};

	ctl.event = event;
	ctl.enable = enable;

	return ioctl(vmi_fd, KVM_VMI_CONTROL_EVENT, &ctl);
}

void vmi_teardown_ring(struct vmi_test_ring *r)
{
	if (r->ring && r->ring != MAP_FAILED)
		munmap(r->ring, getpagesize());
	if (r->ring_fd >= 0)
		close(r->ring_fd);
	if (r->event_fd >= 0)
		close(r->event_fd);
	if (r->ack_fd >= 0)
		close(r->ack_fd);
}

/*
 * Thread function for running a vCPU. Loops calling vcpu_run()
 * until the guest reaches GUEST_DONE or is signaled to stop.
 * Handles GUEST_SYNC by continuing, GUEST_ABORT by failing.
 * VMI events are handled in-kernel via the ring -- they do not
 * cause vcpu_run() to return.
 */
void *vmi_vcpu_thread_fn(void *arg)
{
	struct vmi_vcpu_thread_arg *targ = arg;
	struct ucall uc;

	while (!targ->done) {
		vcpu_run(targ->vcpu);

		switch (get_ucall(targ->vcpu, &uc)) {
		case UCALL_DONE:
			targ->done = 1;
			return NULL;
		case UCALL_ABORT:
			REPORT_GUEST_ASSERT(uc);
			return NULL;
		case UCALL_SYNC:
			/* Guest sync point -- continue running */
			break;
		default:
			break;
		}
	}
	return NULL;
}

/*
 * Common test setup: create VM, create VMI session, setup ring.
 * Returns vmi_fd. Caller should call vmi_test_teardown() to clean up.
 */
int vmi_test_setup(struct kvm_vm **vm, struct kvm_vcpu **vcpu,
		   void (*guest_fn)(void), struct vmi_test_ring *ring)
{
	int vmi_fd;

	*vm = vm_create_with_one_vcpu(vcpu, guest_fn);
	vmi_fd = vmi_create(*vm);
	vmi_setup_ring(vmi_fd, 0, ring);

	return vmi_fd;
}

void vmi_test_teardown(struct kvm_vm *vm, int vmi_fd,
		       struct vmi_test_ring *ring)
{
	vmi_teardown_ring(ring);
	close(vmi_fd);
	kvm_vm_free(vm);
}
