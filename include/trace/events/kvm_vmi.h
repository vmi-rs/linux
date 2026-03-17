/* SPDX-License-Identifier: GPL-2.0 */
#if !defined(_TRACE_KVM_VMI_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_KVM_VMI_H

#include <linux/tracepoint.h>
#include <uapi/linux/kvm_vmi.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM kvm_vmi

#define kvm_vmi_response_flags				\
	{ KVM_VMI_RESPONSE_DENY,		"DENY" },	\
	{ KVM_VMI_RESPONSE_SET_REGS,		"SET_REGS" }

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

/*
 * Trace event delivery - fires when an event is placed in the ring.
 * This is the most important tracepoint for latency analysis.
 */
TRACE_EVENT(kvm_vmi_event_deliver,
	TP_PROTO(unsigned int vcpu_id, unsigned int event_type, __u64 data),
	TP_ARGS(vcpu_id, event_type, data),

	TP_STRUCT__entry(
		__field(unsigned int,	vcpu_id)
		__field(unsigned int,	event_type)
		__field(__u64,		data)
	),

	TP_fast_assign(
		__entry->vcpu_id = vcpu_id;
		__entry->event_type = event_type;
		__entry->data = data;
	),

	TP_printk("vcpu %u event %u data 0x%llx",
		  __entry->vcpu_id,
		  __entry->event_type,
		  __entry->data)
);

/*
 * Trace event response - fires when the agent's response is applied.
 */
TRACE_EVENT(kvm_vmi_event_response,
	TP_PROTO(unsigned int vcpu_id, unsigned int event_type, __u32 response),
	TP_ARGS(vcpu_id, event_type, response),

	TP_STRUCT__entry(
		__field(unsigned int,	vcpu_id)
		__field(unsigned int,	event_type)
		__field(__u32,		response)
	),

	TP_fast_assign(
		__entry->vcpu_id = vcpu_id;
		__entry->event_type = event_type;
		__entry->response = response;
	),

	TP_printk("vcpu %u event %u response %s",
		  __entry->vcpu_id,
		  __entry->event_type,
		  __print_flags(__entry->response, "|", kvm_vmi_response_flags))
);

#endif /* _TRACE_KVM_VMI_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH trace/events
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE kvm_vmi

/* This part must be outside protection */
#include <trace/define_trace.h>
