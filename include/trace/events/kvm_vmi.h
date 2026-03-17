/* SPDX-License-Identifier: GPL-2.0 */
#if !defined(_TRACE_KVM_VMI_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_KVM_VMI_H

#include <linux/tracepoint.h>
#include <uapi/linux/kvm_vmi.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM kvm_vmi

#define kvm_vmi_response_flags				\
	{ KVM_VMI_RESPONSE_DENY,		"DENY" },	\
	{ KVM_VMI_RESPONSE_SET_REGS,		"SET_REGS" },	\
	{ KVM_VMI_RESPONSE_SWITCH_VIEW,		"SWITCH_VIEW" }

#define kvm_vmi_access_flags					\
	{ KVM_VMI_ACCESS_R,		"R" },			\
	{ KVM_VMI_ACCESS_W,		"W" },			\
	{ KVM_VMI_ACCESS_X,		"X" }

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

/*
 * Trace VM/vCPU pause and unpause.
 * vcpu_id == -1 means VM-wide operation.
 */
TRACE_EVENT(kvm_vmi_pause,
	TP_PROTO(int vcpu_id, bool is_pause),
	TP_ARGS(vcpu_id, is_pause),

	TP_STRUCT__entry(
		__field(int,	vcpu_id)
		__field(bool,	is_pause)
	),

	TP_fast_assign(
		__entry->vcpu_id = vcpu_id;
		__entry->is_pause = is_pause;
	),

	TP_printk("%s %s%d",
		  __entry->is_pause ? "pause" : "unpause",
		  __entry->vcpu_id == -1 ? "vm" : "vcpu ",
		  __entry->vcpu_id == -1 ? 0 : __entry->vcpu_id)
);

/*
 * Trace view creation.
 */
TRACE_EVENT(kvm_vmi_view_create,
	TP_PROTO(__u32 view_id, __u8 default_access),
	TP_ARGS(view_id, default_access),

	TP_STRUCT__entry(
		__field(__u32,	view_id)
		__field(__u8,	default_access)
	),

	TP_fast_assign(
		__entry->view_id = view_id;
		__entry->default_access = default_access;
	),

	TP_printk("view %u access %s",
		  __entry->view_id,
		  __print_flags(__entry->default_access, "|",
				kvm_vmi_access_flags))
);

/*
 * Trace view destruction.
 */
TRACE_EVENT(kvm_vmi_view_destroy,
	TP_PROTO(__u32 view_id),
	TP_ARGS(view_id),

	TP_STRUCT__entry(
		__field(__u32,	view_id)
	),

	TP_fast_assign(
		__entry->view_id = view_id;
	),

	TP_printk("view %u", __entry->view_id)
);

/*
 * Trace vCPU view switch.
 */
TRACE_EVENT(kvm_vmi_view_switch,
	TP_PROTO(unsigned int vcpu_id, __u32 old_view, __u32 new_view),
	TP_ARGS(vcpu_id, old_view, new_view),

	TP_STRUCT__entry(
		__field(unsigned int,	vcpu_id)
		__field(__u32,		old_view)
		__field(__u32,		new_view)
	),

	TP_fast_assign(
		__entry->vcpu_id = vcpu_id;
		__entry->old_view = old_view;
		__entry->new_view = new_view;
	),

	TP_printk("vcpu %u view %u -> %u",
		  __entry->vcpu_id, __entry->old_view, __entry->new_view)
);

#endif /* _TRACE_KVM_VMI_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH trace/events
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE kvm_vmi

/* This part must be outside protection */
#include <trace/define_trace.h>
