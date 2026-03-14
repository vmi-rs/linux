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
