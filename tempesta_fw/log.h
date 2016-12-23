/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2016 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#ifndef __TFW_LOG_H__
#define __TFW_LOG_H__

#include <linux/kernel.h>

#define TFW_BANNER	"[tempesta] "

/*
 * We have different verbosity levels for debug messages.
 * They are controlled by the DEBUG macro which is usually passed via the
 * compiler option.
 *   -DDEBUG or -DDEBUG=1 enables the debug logging via TFW_DBG().
 *   -DDEBUG=2 - same as above, but also enables TFW_DBG2().
 *   -DDEBUG=3 - same as above plus TFW_DBG3().
 *   ...etc
 * Currently there are only 3 levels:
 *   1 [USER]    - information required to understand system behavior under
 *                 some load, only key events (e.g. new connections) should
 *                 be logged. The events could not be logged on normal level,
 *                 because we expect too many such events. This level should
 *                 be used only for events interesting to common system
 *                 administrator;
 *   2 [SUPPORT] - key events at lower (component) levels (e.g. TDB or SS).
 *                 Only events required for technical support should be logged
 *                 on this level;
 *   3 [DEVELOP] - verbose loging, used for engineer debugging internal
 *                 algorithms and so on. Typically for single slow connection
 *                 cases.
 */

#define __TFW_DBG1(...) pr_debug(TFW_BANNER "  " __VA_ARGS__)
#define __TFW_DBG2(...) pr_debug(TFW_BANNER "    " __VA_ARGS__)
#define __TFW_DBG3(...) pr_debug(TFW_BANNER "      " __VA_ARGS__)

#if defined(DEBUG) && (DEBUG >= 1)
#define TFW_DBG(...) __TFW_DBG1(__VA_ARGS__)
#else
#define TFW_DBG(...)
#endif

#if defined(DEBUG) && (DEBUG >= 2)
#define TFW_DBG2(...) __TFW_DBG2(__VA_ARGS__)
#else
#define TFW_DBG2(...)
#endif

#if defined(DEBUG) && (DEBUG >= 3)
#define TFW_DBG3(...) __TFW_DBG3(__VA_ARGS__)
#else
#define TFW_DBG3(...)
#endif

#if defined(DEBUG) && (DEBUG == 3)
#define TFW_ERR(...)	__CALLSTACK_MSG(KERN_ERR TFW_BANNER		\
					"ERROR: " __VA_ARGS__)
#define TFW_WARN(...)	__CALLSTACK_MSG(KERN_WARNING TFW_BANNER		\
					"Warning: " __VA_ARGS__)
#define TFW_LOG(...)	pr_info(TFW_BANNER __VA_ARGS__)
#else
#include <linux/net.h>
#define TFW_ERR(...)	net_err_ratelimited(TFW_BANNER "ERROR: " __VA_ARGS__)
#define TFW_WARN(...)	net_warn_ratelimited(TFW_BANNER "Warning: " __VA_ARGS__)
#define TFW_LOG(...)	net_info_ratelimited(TFW_BANNER __VA_ARGS__)
#endif

/*
 * Print an IP address into a buffer (allocated on stack) and then evaluate
 * an expression where the buffer may be used.
 * Usage:
 *   struct sockaddr *sockaddr_in;
 *   TFW_WITH_ADDR_FMT(addr, str, printk("formatted addr: %s\n", str);
 */
#define TFW_WITH_ADDR_FMT(addr_ptr, fmtd_addr_var_name, action_expr)	\
do {									\
	char fmtd_addr_var_name[TFW_ADDR_STR_BUF_SIZE] = { 0 };		\
	tfw_addr_ntop(addr_ptr, fmtd_addr_var_name,			\
		      sizeof(fmtd_addr_var_name));			\
	action_expr;							\
} while (0)

/* The same as above, but for IPv6 only (struct in6_addr). */
#define TFW_WITH_ADDR6_FMT(addr_ptr, fmtd_addr_var_name, action_expr)	\
do {									\
	char fmtd_addr_var_name[TFW_ADDR_STR_BUF_SIZE] = { 0 };		\
	tfw_addr_fmt_v6(addr_ptr, 0, fmtd_addr_var_name);		\
	action_expr;							\
} while (0)

/* Log a debug message and append an IP address to it.*/
#define TFW_DBG_ADDR(msg, addr_ptr)					\
	TFW_WITH_ADDR_FMT(addr_ptr, addr_str,				\
			  TFW_DBG("%s: %s\n", msg, addr_str))
#define TFW_DBG_ADDR6(msg, addr_ptr)					\
	TFW_WITH_ADDR6_FMT(addr_ptr, addr_str,				\
			   TFW_DBG("%s: %s\n", msg, addr_str))

/* Log an info message and append an IP address to it.*/
#define TFW_LOG_ADDR(msg, addr_ptr)					\
	TFW_WITH_ADDR_FMT(addr_ptr, addr_str,				\
			  TFW_LOG("%s: %s\n", msg, addr_str))
#define TFW_LOG_ADDR6(msg, addr_ptr)					\
	TFW_WITH_ADDR6_FMT(addr_ptr, addr_str,				\
			   TFW_LOG("%s: %s\n", msg, addr_str))

/* Log a warning message and append an IP address to it.*/
#define TFW_WARN_ADDR(msg, addr_ptr)					\
	TFW_WITH_ADDR_FMT(addr_ptr, addr_str,				\
			  TFW_WARN("%s: %s\n", msg, addr_str))
#define TFW_WARN_ADDR6(msg, addr_ptr)					\
	TFW_WITH_ADDR6_FMT(addr_ptr, addr_str,				\
			   TFW_WARN("%s: %s\n", msg, addr_str))

/* Log an error message and appen an IP address to it. */
#define TFW_ERR_ADDR(msg, addr_ptr)					\
	TFW_WITH_ADDR_FMT(addr_ptr, addr_str,				\
			  TFW_ERR("%s: %s\n", msg, addr_str))
#define TFW_ERR_ADDR6(msg, addr_ptr)					\
	TFW_WITH_ADDR6_FMT(addr_ptr, addr_str,				\
			   TFW_ERR("%s: %s\n", msg, addr_str))

/*
 * Keep SS debug primitives separate.
 */
#define SS_BANNER	"[sync_sockets] "

#if defined(DEBUG) && (DEBUG >= 2)
#define __CALLSTACK_MSG(...)						\
do {									\
	printk(__VA_ARGS__);						\
	__WARN();							\
} while (0)

#define SS_DBG(...)	pr_debug(SS_BANNER "  " __VA_ARGS__)
#define SS_ERR(...)	__CALLSTACK_MSG(KERN_ERR SS_BANNER		\
					"ERROR: " __VA_ARGS__)
#define SS_WARN(...)	__CALLSTACK_MSG(KERN_WARNING SS_BANNER		\
					"Warning: " __VA_ARGS__)
#else
#include <linux/net.h>
#define SS_DBG(...)
#define SS_ERR(...)	net_err_ratelimited(SS_BANNER "ERROR: " __VA_ARGS__)
#define SS_WARN(...)	net_warn_ratelimited(SS_BANNER "Warning: " __VA_ARGS__)
#endif

#endif /* __TFW_LOG_H__ */
