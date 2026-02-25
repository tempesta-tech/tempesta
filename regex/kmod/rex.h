/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* SPDX-FileCopyrightText: Copyright 2022 G-Core Labs S.A. */

#ifndef REX_ABI_USER_H
#define REX_ABI_USER_H

#if !defined(__bpf__)
#include <linux/types.h>
#include <linux/bpf.h>
#define __ksym
#endif

#include "fw/str.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Structure describing a match event.
 */
struct rex_event {
	unsigned int expression;
	unsigned long long from;
	unsigned long long to;
	unsigned long long flags;
};

/* handler_flags */
enum {
	REX_SINGLE_SHOT = 1 << 0,
};

/**
 * Attributes for bpf_scan_bytes() and bpf_xdp_scan_bytes().
 *
 * @database_id:	Numeric database handle taken from configfs (in).
 * @handler_flags:	Customize match handler behaviour (in).
 * @event_count:	Output number of events (inout).
 * @last_event:		Space to store match details. (out).
 */
struct rex_scan_attr {
	__u32 database_id;
	__u32 handler_flags;
	__u32 nr_events;
	struct rex_event last_event;
};

int rex_scan_tfwstr(const TfwStr *str, struct rex_scan_attr *attr) __ksym;

#if defined(__KERNEL__) || defined(__bpf__)

/**
 * Scan any buffer against regex pattern database.
 *
 * @buf:		A pointer to a valid buffer.
 * @buf__sz:		Number of bytes to scan.
 * @scan_attr:		Input/output match attributes.
 */
int bpf_scan_bytes(const void *buf, __u32 buf__sz,
		   struct rex_scan_attr *scan_attr) __ksym;

/**
 * Scan @len packet bytes starting from @offset against pattern database.
 * Similar to bpf_scan_bytes() but use XDP offsets to trick BPF verifier
 *
 * @xdp_md:		A pointer to struct xdp_buff* actually.
 * @scan_attr:		Input/output match attributes.
 */
int bpf_xdp_scan_bytes(const struct xdp_md *xdp_md, __u32 offset, __u32 len,
		       struct rex_scan_attr *scan_attr) __ksym;

#endif /* __KERNEL__ or __bpf__ */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif // REX_ABI_USER_H
