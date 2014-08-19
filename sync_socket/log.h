/**
 * Synchronous Socket API.
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
#ifndef __SS_LOG_H__
#define __SS_LOG_H__

#define SS_BANNER		"[sync_socket] "

#ifdef DEBUG
#define SS_DBG(...)							\
do {									\
	printk(KERN_ERR SS_BANNER "  " __VA_ARGS__);			\
} while (0)
#else
#define SS_DBG(...)
#endif

#define SS_LOG(...)							\
do {									\
	if (net_ratelimit())						\
		printk(KERN_INFO SS_BANNER __VA_ARGS__);		\
} while (0)

#define SS_WARN(...)							\
do {									\
	if (net_ratelimit())						\
		printk(KERN_WARNING SS_BANNER "Warning: " __VA_ARGS__);	\
} while (0)

#define SS_ERR(...)							\
do {									\
	if (net_ratelimit())						\
		printk(KERN_ERR SS_BANNER "ERROR: " __VA_ARGS__);	\
} while (0)

#endif /* __SS_LOG_H__ */
