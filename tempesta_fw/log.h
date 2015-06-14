/**
 *		Tempesta FW
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
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
 * Currently there are only 3 levels, but they may be added in future as needed.
 *
 * Also -DDEBUG disables rate limiting of non-debug messages, but this is a
 * temporary thing that will be removed when logger modules will be implemented.
 */

#define __TFW_DBG1(...) pr_debug(TFW_BANNER "  " __VA_ARGS__)
#define __TFW_DBG2(...) pr_debug(TFW_BANNER "    " __VA_ARGS__)
#define __TFW_DBG3(...) pr_debug(TFW_BANNER "      " __VA_ARGS__)

#ifdef DEBUG
#define TFW_DBG_LVL (DEBUG + 0)
#else
#define TFW_DBG_LVL 0
#endif

#if (TFW_DBG_LVL >= 1)
#define TFW_DBG(...) __TFW_DBG1(__VA_ARGS__)
#else
#define TFW_DBG(...)
#endif

#if (TFW_DBG_LVL >= 2)
#define TFW_DBG2(...) __TFW_DBG2(__VA_ARGS__)
#else
#define TFW_DBG2(...)
#endif

#if (TFW_DBG_LVL >= 3)
#define TFW_DBG3(...) __TFW_DBG3(__VA_ARGS__)
#else
#define TFW_DBG3(...)
#endif

#ifdef DEBUG
#define TFW_ERR(...)	printk(TFW_BANNER "ERROR: " __VA_ARGS__)
#define TFW_WARN(...)	printk(TFW_BANNER "Warning: " __VA_ARGS__)
#define TFW_LOG(...)	printk(TFW_BANNER __VA_ARGS__)
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
#define TFW_WITH_ADDR_FMT(addr_ptr, fmtd_addr_var_name, action_expr)  \
do { \
	char fmtd_addr_var_name[TFW_ADDR_STR_BUF_SIZE]; \
	tfw_addr_ntop(addr_ptr, fmtd_addr_var_name, sizeof(fmtd_addr_var_name)); \
	action_expr; \
} while (0)

/* Log a debug message and append an IP address to it.*/
#define TFW_DBG_ADDR(msg, addr_ptr) \
	TFW_WITH_ADDR_FMT(addr_ptr, addr_str, TFW_DBG("%s: %s\n", msg, addr_str))

/* Log an info message and append an IP address to it.*/
#define TFW_LOG_ADDR(msg, addr_ptr) \
	TFW_WITH_ADDR_FMT(addr_ptr, addr_str, TFW_LOG("%s: %s\n", msg, addr_str))

/* Log a warning message and append an IP address to it.*/
#define TFW_WARN_ADDR(msg, addr_ptr) \
	TFW_WITH_ADDR_FMT(addr_ptr, addr_str, TFW_WARN("%s: %s\n", msg, addr_str))

/* Log an error message and appen an IP address to it. */
#define TFW_ERR_ADDR(msg, addr_ptr) \
	TFW_WITH_ADDR_FMT(addr_ptr, addr_str, TFW_ERR("%s: %s\n", msg, addr_str))

/*
 * Keep SS debug primitives separate.
 */
#define SS_BANNER	"[sync_sockets] "

#ifdef DEBUG
#define SS_DBG(...)	pr_debug(SS_BANNER "  " __VA_ARGS__)
#define SS_ERR(...)	pr_err(SS_BANNER "ERROR: " __VA_ARGS__)
#define SS_WARN(...)	pr_warn(SS_BANNER "Warning: " __VA_ARGS__)
#define SS_LOG(...)	pr_info(SS_BANNER __VA_ARGS__)
#else
#include <linux/net.h>
#define SS_DBG(...)
#define SS_ERR(...)	net_err_ratelimited(SS_BANNER "ERROR: " __VA_ARGS__)
#define SS_WARN(...)	net_warn_ratelimited(SS_BANNER "Warning: " __VA_ARGS__)
#define SS_LOG(...)	net_info_ratelimited(SS_BANNER __VA_ARGS__)
#endif

#endif /* __TFW_LOG_H__ */
