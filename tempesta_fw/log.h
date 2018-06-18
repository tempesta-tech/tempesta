/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2018 Tempesta Technologies, Inc.
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

#define BANNER	"tempesta"
#include "lib/log.h"
/* TODO remvoe the defefines after moving to unified logging. */
#define TFW_ERR(...)		T_ERR(__VA_ARGS__)
#define TFW_ERR_NL(...)		T_ERR_NL(__VA_ARGS__)
#define TFW_WARN(...)		T_WARN(__VA_ARGS__)
#define TFW_WARN_NL(...)	T_WARN_NL(__VA_ARGS__)
#define TFW_LOG(...)		T_LOG(__VA_ARGS__)
#define TFW_LOG_NL(...)		T_LOG_NL(__VA_ARGS__)
#define TFW_ERR(...)		T_ERR(__VA_ARGS__)
#define TFW_DBG(...)		T_DBG(__VA_ARGS__)
#define TFW_DB2(...)		T_DBG2(__VA_ARGS__)
#define TFW_DBG3(...)		T_DBG3(__VA_ARGS__)

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
			  T_DBG("%s: %s\n", msg, addr_str))
#define TFW_DBG_ADDR6(msg, addr_ptr)					\
	TFW_WITH_ADDR6_FMT(addr_ptr, addr_str,				\
			   T_DBG("%s: %s\n", msg, addr_str))

/* Log an info message and append an IP address to it.*/
#define TFW_LOG_ADDR(msg, addr_ptr)					\
	TFW_WITH_ADDR_FMT(addr_ptr, addr_str,				\
			  T_LOG("%s: %s\n", msg, addr_str))
#define TFW_LOG_ADDR6(msg, addr_ptr)					\
	TFW_WITH_ADDR6_FMT(addr_ptr, addr_str,				\
			   T_LOG("%s: %s\n", msg, addr_str))

/* Log a warning message and append an IP address to it.*/
#define TFW_WARN_ADDR(msg, addr_ptr)					\
	TFW_WITH_ADDR_FMT(addr_ptr, addr_str,				\
			  T_WARN("%s: %s\n", msg, addr_str))
#define TFW_WARN_ADDR6(msg, addr_ptr)					\
	TFW_WITH_ADDR6_FMT(addr_ptr, addr_str,				\
			   T_WARN("%s: %s\n", msg, addr_str))

/* Log an error message and appen an IP address to it. */
#define TFW_ERR_ADDR(msg, addr_ptr)					\
	TFW_WITH_ADDR_FMT(addr_ptr, addr_str,				\
			  T_ERR("%s: %s\n", msg, addr_str))
#define TFW_ERR_ADDR6(msg, addr_ptr)					\
	TFW_WITH_ADDR6_FMT(addr_ptr, addr_str,				\
			   T_ERR("%s: %s\n", msg, addr_str))

#endif /* __TFW_LOG_H__ */
