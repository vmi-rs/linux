// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM VMI I/O instruction monitoring test
 *
 * Tests I/O port access interception via ring-based event delivery.
 *
 * Note: With ring-based delivery, enabling IO event monitoring intercepts
 * ALL IO instructions including ucall IO. The ring handler auto-ALLOWs
 * events on non-target ports and only checks port 0x80.
 */
#include <linux/kvm.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "vmi_util.h"

static void guest_io(void)
{
	GUEST_SYNC(1);

	/* OUT to port 0x80 (POST code port, commonly used for debug) */
	__asm__ __volatile__("outb %0, $0x80" : : "a"((uint8_t)0x42));

	GUEST_SYNC(2);

	GUEST_DONE();
}

static void test_io_basic(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct vmi_test_ring ring;
	struct vmi_vcpu_thread_arg targ;
	pthread_t thread;
	struct kvm_vmi_ring_event *ev;
	int vmi_fd;
	int found_port_80 = 0;

	vmi_fd = vmi_test_setup(&vm, &vcpu, guest_io, &ring);

	/* Enable IO monitoring */
	vmi_control_event(vmi_fd, KVM_VMI_EVENT_IO, 1);

	/* Start vCPU thread */
	targ.vcpu = vcpu;
	targ.done = 0;
	pthread_create(&thread, NULL, vmi_vcpu_thread_fn, &targ);

	/*
	 * Process ring events until we find port 0x80 or timeout.
	 * Auto-ALLOW events on other ports (ucall IO, etc.).
	 */
	while (!targ.done && !found_port_80) {
		ev = vmi_wait_event_timeout(&ring, 5000);
		if (ev == NULL)
			break;

		TEST_ASSERT(ev->type == KVM_VMI_EVENT_IO,
			    "Expected IO event, got %u", ev->type);

		if (ev->arch.io.port == 0x80) {
			found_port_80 = 1;
			TEST_ASSERT(ev->arch.io.in == 0,
				    "Expected OUT (in=0), got %u",
				    ev->arch.io.in);
			TEST_ASSERT(ev->arch.io.bytes == 1,
				    "Expected 1-byte OUT, got %u",
				    ev->arch.io.bytes);
		}

		ev->response = KVM_VMI_RESPONSE_CONTINUE;
		vmi_ack_event(&ring, 0);
	}

	TEST_ASSERT(found_port_80,
		    "Should have received IO event for port 0x80");

	/* Drain remaining IO events until guest completes */
	while (!targ.done) {
		ev = vmi_wait_event_timeout(&ring, 5000);
		if (ev == NULL)
			break;
		ev->response = KVM_VMI_RESPONSE_CONTINUE;
		vmi_ack_event(&ring, 0);
	}

	pthread_join(thread, NULL);

	vmi_test_teardown(vm, vmi_fd, &ring);
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_VMI));

	test_io_basic();

	return 0;
}
