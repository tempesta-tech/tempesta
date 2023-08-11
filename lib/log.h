/**
 *		Tempesta kernel library
 *
 * Copyright (C) 2015-2023 Tempesta Technologies, INC.
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
#ifndef __LIB_LOG_H__
#define __LIB_LOG_H__

#ifdef __KERNEL__
#include <linux/err.h>
#else
#define MAX_ERRNO 4095
#endif

/*
 * Return codes.
 */
enum {
	/* Generic error. Connection should be closed with TCP_FIN. */
	T_BAD		= -MAX_ERRNO + 4,
	/*
	 * The message must be dropped. Connection should be alive or closed
	 * with TCP FIN depending on whether we can communicate with this
	 * client or not.
	 */
	T_DROP          = -MAX_ERRNO + 3,
	/*
	 * The message must be blocked (typically on a security event).
	 * Tempesta send TCP RST in this case.
	 */
	T_BLOCK		= -MAX_ERRNO + 2,
	/* The message should be stashed (made by callback). */
	T_POSTPONE	= -MAX_ERRNO + 1,
	/* The message looks good and we can safely pass it. */
	T_OK		= 0,
};

/*
 * BANNER variable must be defined before including the file!
 *
 * We have different verbosity levels for debug messages.
 * They are controlled by the DEBUG macro which is usually passed via the
 * compiler option.
 *   -DDEBUG or -DDEBUG=1 enables the debug logging via T_DBG().
 *   -DDEBUG=2 - same as above, but also enables T_DBG2().
 *   -DDEBUG=3 - same as above plus T_DBG3().
 *   ...etc
 *
 * Currently there are only 4 levels:
 *   1 [USER]    - information required to understand system behavior under
 *                 some load, only key events (e.g. new connections) should
 *                 be logged. The events could not be logged on normal level,
 *                 because we expect too many such events. This level should
 *                 be used only for events interesting to common system
 *                 administrator;
 *   2 [SUPPORT] - key events at lower (component) levels (e.g. TDB or SS).
 *                 Only events required for technical support should be logged
 *                 on this level;
 *   3 [DEVELOP] - extended logging, used for engineer debugging internal
 *                 algorithms and so on. Typically for single slow connection
 *                 cases.
 *   4 [VERBOSE] - all of the above + verbose dumping of internal structures
 *                 content, e.g. SKB queues, rbtree, etc.
 */
#define __BNR		"[tempesta " BANNER "] "
#define __T_DBG1(...) 	pr_debug(__BNR "  " __VA_ARGS__)
#define __T_DBG2(...) 	pr_debug(__BNR "    " __VA_ARGS__)
#define __T_DBG3(...)	pr_debug(__BNR "      " __VA_ARGS__)

#if defined(DEBUG) && (DEBUG >= 1)
#define T_DBG(...) 	__T_DBG1(__VA_ARGS__)
#else
#define T_DBG(...)
#endif

#if defined(DEBUG) && (DEBUG >= 2)
#define T_DBG2(...)	__T_DBG2(__VA_ARGS__)
#else
#define T_DBG2(...)
#endif

#if defined(DEBUG) && (DEBUG >= 3)
#define T_DBG3(...)	__T_DBG3(__VA_ARGS__)

#define T_DBG3_BUF(str, buf, len)					\
do {									\
	T_DBG3("dump '" str "' (ptr=%pk, %lu bytes):\n",		\
	       buf, (size_t)(len));					\
	print_hex_dump_bytes(__BNR "        ", DUMP_PREFIX_OFFSET, buf, len);\
} while (0)

#define T_DBG3_SL(str, sglist, sgn, off, len)				\
do {									\
	int __o = 0, __i, __n = (int)(len);				\
	struct scatterlist *__s = NULL;					\
	T_DBG3(str " (sgn=%u sglist=%pK len=%lu):\n", sgn, sglist, len);\
	for_each_sg(sglist, __s, sgn, __i) {				\
		if (!__n)						\
			break;						\
		if (off >= __o + __s->length) {				\
			__o += __s->length;				\
		} else {						\
			int __d = off - __o;				\
			int __bytes = min_t(int, __n, __s->length - __d); \
			T_DBG3("=> segment %d, ptr=%pK len=%u\n",	\
			       __i, __s, __s->length);			\
			T_DBG3_BUF("data", sg_virt(__s) + __d, __bytes); \
			__o = off;					\
			__n -= __bytes;					\
		}							\
	}								\
} while (0)

#define __CALLSTACK_MSG(...)						\
do {									\
	printk(__VA_ARGS__);						\
	__WARN();							\
} while (0)

#define T_ERR(...)	__CALLSTACK_MSG(KERN_ERR __BNR "ERROR: " __VA_ARGS__)
#define T_WARN(...)	__CALLSTACK_MSG(KERN_WARNING __BNR		\
					"Warning: " __VA_ARGS__)
#define T_LOG(...)	pr_info(__BNR __VA_ARGS__)
/* Non-limited printing. */
#define T_ERR_NL(...)	T_ERR(__VA_ARGS__)
#define T_WARN_NL(...)	T_WARN(__VA_ARGS__)
#define T_LOG_NL(...)	T_LOG(__VA_ARGS__)

#else /* DEBUG < 3 */
#include <linux/net.h>
#define T_ERR(...)	net_err_ratelimited(__BNR "ERROR: " __VA_ARGS__)
#define T_WARN(...)	net_warn_ratelimited(__BNR "Warning: "	__VA_ARGS__)
#define T_LOG(...)	net_info_ratelimited(__BNR __VA_ARGS__)
#define T_DBG3(...)
#define T_DBG3_BUF(...)
#define T_DBG3_SL(...)
/* Non-limited printing. */
#define T_ERR_NL(...)	pr_err(__BNR "ERROR: " __VA_ARGS__)
#define T_WARN_NL(...)	pr_warn(__BNR "Warning: " __VA_ARGS__)
#define T_LOG_NL(...)	pr_info(__BNR __VA_ARGS__)
#endif

#if defined(DEBUG) && (DEBUG >= 4)
#define T_DBGV(...)	pr_debug(__BNR "#     " __VA_ARGS__)
#else
#define T_DBGV(...)
#endif

#endif /* __LIB_LOG_H__ */
