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

int vmi_create(struct kvm_vm *vm);

#endif /* SELFTEST_KVM_VMI_UTIL_H */
