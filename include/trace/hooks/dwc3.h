/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM dwc3

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH trace/hooks

#if !defined(_TRACE_HOOK_DWC3_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_HOOK_DWC3_H

#include <trace/hooks/vendor_hooks.h>

struct usb_hcd;

#ifndef SOFT_RESET_PHASE
#define SOFT_RESET_PHASE
enum soft_reset_phase {
	PRE_SOFT_RESET,
	SOFT_RESET_INITIATED,
	POST_SOFT_RESET
};
#endif /* SOFT_RESET_PHASE */

/*
 * Generic xHCI reset callback; the historical name is also used for PCI hosts.
 * Callers can hold the host spinlock with interrupts disabled. Callbacks must
 * not sleep or retain the borrowed hcd. POST does not imply reset succeeded or
 * that the controller-not-ready handshake has completed.
 */
DECLARE_HOOK(android_vh_dwc3_xhci_soft_reset,
	     TP_PROTO(struct usb_hcd *hcd, enum soft_reset_phase phase),
	     TP_ARGS(hcd, phase));

#endif /* _TRACE_HOOK_DWC3_H */
/* This part must be outside protection */
#include <trace/define_trace.h>
