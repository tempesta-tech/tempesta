/**
 *		Tempesta kernel library
 *
 * Copyright (C) 2015-2024 Tempesta Technologies, INC.
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
#ifndef __LIB_ERROR_CODE_H__
#define __LIB_ERROR_CODE_H__

#ifdef __KERNEL__
#include <linux/err.h>
#else
#define MAX_ERRNO 4095
#endif

/*
 * Return codes.
 */
enum {
	/* Compression error during hpack decoding. */
	T_COMPRESSION	= -MAX_ERRNO + 7,
	/*
	 * Generic error. Connection should be shutdown gracefully
	 * with TCP_FIN.
	 */
	T_BAD		 = -MAX_ERRNO + 6,
	/*
	 * The message must be dropped. Connection should be alive or closed
	 * with TCP FIN depending on whether we can communicate with this
	 * client or not.
	 */
	T_DROP		 = -MAX_ERRNO + 5,
	/*
	 * The message must be blocked (typically on a security event).
	 * Tempesta send TCP FIN in this case.
	 */
	T_BLOCK_WITH_FIN = -MAX_ERRNO + 4,
	/*
	 * The message must be blocked (typically on a security event).
	 * Tempesta send TCP RST in this case.
	 */
	T_BLOCK_WITH_RST = -MAX_ERRNO + 3,
	/*
	 * The message must be blocked (typically on a security event).
	 * Sending TCP RST or TCP FIN depends on block action setting.
	 */
	T_BLOCK		 = -MAX_ERRNO + 2,
	/* The message should be stashed (made by callback). */
	T_POSTPONE	 = -MAX_ERRNO + 1,
	/* The message looks good and we can safely pass it. */
	T_OK		 = 0,
};

static inline int
tfw_handle_error(int r, int *save_err_code, bool was_stopped)
{
	if (likely(r == T_OK || r == T_POSTPONE || r == T_DROP)) {
		return r;
	} else if (unlikely(*save_err_code != T_OK || was_stopped)) {
		/*
		 * Error occurs when connection was already stopped
		 * close it with TCP RST.
		 */
		r = T_BLOCK_WITH_RST;
		*save_err_code = T_OK;
	}
	return r;
}

#endif /* __LIB_ERROR_CODE_H__ */
