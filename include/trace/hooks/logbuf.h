/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM logbuf

#define TRACE_INCLUDE_PATH trace/hooks

#if !defined(_TRACE_HOOK_LOGBUF_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_HOOK_LOGBUF_H

#include <trace/hooks/vendor_hooks.h>

struct printk_ringbuffer;
struct printk_record;

/*
 * Record hooks run after commit with a private, bounded snapshot of the record.
 * The snapshot and its buffers are valid only during the synchronous callback;
 * modifying them does not modify the committed log. Use the ringbuffer reader
 * protocol to inspect other records, which can be concurrently reused. Callbacks
 * must not sleep and must respect printk recursion/NMI context constraints.
 */
DECLARE_RESTRICTED_HOOK(android_rvh_logbuf,
	TP_PROTO(struct printk_ringbuffer *rb, struct printk_record *r),
	TP_ARGS(rb, r), true)

DECLARE_HOOK(android_vh_logbuf,
	TP_PROTO(struct printk_ringbuffer *rb, struct printk_record *r),
	TP_ARGS(rb, r))

DECLARE_HOOK(android_vh_logbuf_pr_cont,
	TP_PROTO(struct printk_record *r, size_t text_len),
	TP_ARGS(r, text_len))

#endif /* _TRACE_HOOK_LOGBUF_H */
/* This part must be outside protection */
#include <trace/define_trace.h>
