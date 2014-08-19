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

#endif /* __TFW_LOG_H__ */
