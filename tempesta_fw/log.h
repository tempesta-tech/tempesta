/**
 *		Tempesta FW
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
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

#define TFW_BANNER		"[tempesta] "

#ifdef DEBUG
#define TFW_DBG(...)	pr_debug(TFW_BANNER "  " __VA_ARGS__)
#else
#define TFW_DBG(...)
#endif

#define TFW_LOG(...)	net_info_ratelimited(TFW_BANNER __VA_ARGS__)
#define TFW_WARN(...)	net_warn_ratelimited(TFW_BANNER "Warning: " __VA_ARGS__)
#define TFW_ERR(...)	net_err_ratelimited(TFW_BANNER "ERROR: " __VA_ARGS__)


/*
 * Print an IP address into a buffer (allocated on stack) and then evaluate
 * an expression where the buffer may be used.
 * Usage:
 *   struct sockaddr *sockaddr_in;
 *   TFW_WITH_ADDR_FMT(addr, str, printk("formatted addr: %s\n", str);
 */
#define TFW_WITH_ADDR_FMT(addr_ptr, fmtd_addr_var_name, action_expr)  \
do { \
	char fmtd_addr_var_name[MAX_ADDR_LEN]; \
	tfw_inet_ntop(addr_ptr, fmtd_addr_var_name); \
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


#endif /* __TFW_LOG_H__ */
