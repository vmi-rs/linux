/* SPDX-License-Identifier: GPL-2.0 */
#if !defined(_TRACE_KVM_VMI_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_KVM_VMI_H

#include <linux/tracepoint.h>
#include <uapi/linux/kvm_vmi.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM kvm_vmi

/*
 * Trace VMI session create/release.
 */
TRACE_EVENT(kvm_vmi_session,
	TP_PROTO(bool is_create),
	TP_ARGS(is_create),

	TP_STRUCT__entry(
		__field(bool,	is_create)
	),

	TP_fast_assign(
		__entry->is_create = is_create;
	),

	TP_printk("%s", __entry->is_create ? "create" : "release")
);

#endif /* _TRACE_KVM_VMI_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH trace/events
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE kvm_vmi

/* This part must be outside protection */
#include <trace/define_trace.h>
