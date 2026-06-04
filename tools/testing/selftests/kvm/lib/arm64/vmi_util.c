// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI test utilities (arm64)
 *
 * Shared helper functions for VMI selftests using the ring-based event
 * delivery via vmi_fd. These arch-neutral helpers mirror the x86 harness
 * (tools/testing/selftests/kvm/lib/x86/vmi_util.c). The arm64-specific
 * helpers (vmi_control_sysreg, vmi_inject_event) are added by their
 * implementing commits (system-register monitoring, event injection).
 */
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <pthread.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <stdlib.h>

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

void vmi_control_sysreg(int vmi_fd, uint8_t reg, uint8_t onchangeonly,
			uint64_t bitmask, int enable)
{
	struct kvm_vmi_control_event ctl = {};
	int ret;

	ctl.event = KVM_VMI_EVENT_SYSREG;
	ctl.enable = enable;
	ctl.arch.sysreg.reg = reg;
	ctl.arch.sysreg.onchangeonly = onchangeonly;
	ctl.arch.sysreg.bitmask = bitmask;

	ret = ioctl(vmi_fd, KVM_VMI_CONTROL_EVENT, &ctl);
	TEST_ASSERT(ret == 0, "KVM_VMI_CONTROL_EVENT(SYSREG) failed: %d", ret);
}

int vmi_inject_event(int vmi_fd, struct kvm_vmi_inject_event *inject)
{
	int ret = ioctl(vmi_fd, KVM_VMI_INJECT_EVENT, inject);

	return ret < 0 ? -errno : ret;
}

/*
 * View management helpers via vmi_fd.
 */
uint32_t vmi_create_view(int vmi_fd, uint8_t default_access)
{
	struct kvm_vmi_view view = {};
	int ret;

	view.default_access = default_access;
	ret = ioctl(vmi_fd, KVM_VMI_CREATE_VIEW, &view);
	TEST_ASSERT(ret == 0, "KVM_VMI_CREATE_VIEW failed: %d (errno=%d)",
		    ret, errno);
	TEST_ASSERT(view.view_id > 0, "Expected view_id > 0, got %u",
		    view.view_id);
	return view.view_id;
}

void vmi_destroy_view(int vmi_fd, uint32_t view_id)
{
	struct kvm_vmi_view view = { .view_id = view_id };
	int ret;

	ret = ioctl(vmi_fd, KVM_VMI_DESTROY_VIEW, &view);
	TEST_ASSERT(ret == 0, "KVM_VMI_DESTROY_VIEW failed: %d", ret);
}

int vmi_destroy_view_err(int vmi_fd, uint32_t view_id)
{
	struct kvm_vmi_view view = { .view_id = view_id };

	return ioctl(vmi_fd, KVM_VMI_DESTROY_VIEW, &view);
}

void vmi_switch_view(int vmi_fd, uint32_t view_id)
{
	struct kvm_vmi_switch_view sv = {
		.view_id = view_id,
	};
	int ret;

	ret = ioctl(vmi_fd, KVM_VMI_SWITCH_VIEW, &sv);
	TEST_ASSERT(ret == 0, "KVM_VMI_SWITCH_VIEW(view_id=%u) failed: %d errno=%d",
		    view_id, ret, errno);
}

void vmi_set_mem_access(int vmi_fd, uint32_t view_id, uint64_t gfn,
			uint8_t access)
{
	struct kvm_vmi_mem_access ma = {};
	int ret;

	ma.view_id = view_id;
	ma.access = access;
	ma.gfn = gfn;

	ret = ioctl(vmi_fd, KVM_VMI_SET_MEM_ACCESS, &ma);
	TEST_ASSERT(ret == 0, "KVM_VMI_SET_MEM_ACCESS failed: %d", ret);
}

void vmi_set_mem_access_autostep(int vmi_fd, uint32_t view_id, uint64_t gfn,
				 uint8_t access, uint16_t autostep_mask)
{
	struct kvm_vmi_mem_access ma = {};
	int ret;

	ma.view_id = view_id;
	ma.access = access;
	ma.gfn = gfn;
	ma.autostep_mask = autostep_mask;

	ret = ioctl(vmi_fd, KVM_VMI_SET_MEM_ACCESS, &ma);
	TEST_ASSERT(ret == 0, "KVM_VMI_SET_MEM_ACCESS(autostep) failed: %d errno=%d",
		    ret, errno);
}

int __vmi_change_gfn_err(int vmi_fd, uint32_t view_id, uint64_t old_gfn,
			 uint64_t new_gfn)
{
	struct kvm_vmi_change_gfn change = {
		.view_id = view_id,
		.old_gfn = old_gfn,
		.new_gfn = new_gfn,
	};

	if (ioctl(vmi_fd, KVM_VMI_CHANGE_GFN, &change) < 0)
		return -errno;
	return 0;
}

void vmi_change_gfn(int vmi_fd, uint32_t view_id, uint64_t old_gfn,
		    uint64_t new_gfn)
{
	int ret = __vmi_change_gfn_err(vmi_fd, view_id, old_gfn, new_gfn);

	TEST_ASSERT(ret == 0, "KVM_VMI_CHANGE_GFN failed: %d", ret);
}

uint64_t vmi_alloc_gfn(int vmi_fd)
{
	struct kvm_vmi_alloc_gfn alloc = {};
	int ret;

	ret = ioctl(vmi_fd, KVM_VMI_ALLOC_GFN, &alloc);
	TEST_ASSERT(ret == 0,
		    "KVM_VMI_ALLOC_GFN failed: %d (errno=%d)", ret, errno);
	return alloc.gfn;
}

void vmi_free_gfn(int vmi_fd, uint64_t gfn)
{
	struct kvm_vmi_free_gfn free_req = { .gfn = gfn };
	int ret;

	ret = ioctl(vmi_fd, KVM_VMI_FREE_GFN, &free_req);
	TEST_ASSERT(ret == 0,
		    "KVM_VMI_FREE_GFN failed: %d (errno=%d)", ret, errno);
}

/*
 * Pause/unpause helpers.
 */
void vmi_pause_vm(int vmi_fd)
{
	int ret;

	ret = ioctl(vmi_fd, KVM_VMI_PAUSE_VM);
	TEST_ASSERT(ret == 0, "KVM_VMI_PAUSE_VM failed: %d", ret);
}

void vmi_unpause_vm(int vmi_fd)
{
	int ret;

	ret = ioctl(vmi_fd, KVM_VMI_UNPAUSE_VM);
	TEST_ASSERT(ret == 0, "KVM_VMI_UNPAUSE_VM failed: %d", ret);
}

void vmi_pause_vcpu(int vmi_fd, uint32_t vcpu_id)
{
	struct kvm_vmi_vcpu v = { .vcpu_id = vcpu_id };
	int ret;

	ret = ioctl(vmi_fd, KVM_VMI_PAUSE_VCPU, &v);
	TEST_ASSERT(ret == 0, "KVM_VMI_PAUSE_VCPU failed: %d", ret);
}

void vmi_unpause_vcpu(int vmi_fd, uint32_t vcpu_id)
{
	struct kvm_vmi_vcpu v = { .vcpu_id = vcpu_id };
	int ret;

	ret = ioctl(vmi_fd, KVM_VMI_UNPAUSE_VCPU, &v);
	TEST_ASSERT(ret == 0, "KVM_VMI_UNPAUSE_VCPU failed: %d", ret);
}

/*
 * Clean up ring resources.
 */
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
 * Force VMI test guests to run at EL1 (opt out of the framework's vEL2
 * auto-promotion on a nested host). See the declaration in vmi_util.h.
 */
void vmi_force_el1_guests(void)
{
	setenv("NV", "0", 1);
}

/*
 * Common test setup: create VM, create VMI session, setup ring.
 * Returns vmi_fd. Caller should call vmi_test_teardown() to clean up.
 */
int vmi_test_setup(struct kvm_vm **vm, struct kvm_vcpu **vcpu,
		   void (*guest_fn)(void), struct vmi_test_ring *ring)
{
	int vmi_fd;

	vmi_force_el1_guests();
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
