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
#ifndef __TFW_CFG_PRIVATE_H__
#define __TFW_CFG_PRIVATE_H__

/* The lib.h is included for IF_DEBUG and and DEBUG_EXPORT_SYMBOL.
 * Hope functions declared in lib.h are generic enough to not form a circular
 * dependency with the configuration system. */
#include "lib.h"

/* A regular logger module may use the configuration subsystem
 * so we are using printk() internally to avoid circular dependencies. */
#define LOG_BANNER "tfw_cfg: "
#define DBG(...) pr_debug(LOG_BANNER __VA_ARGS__)
#define LOG(...) pr_info(LOG_BANNER __VA_ARGS__)
#define ERR(...) pr_err(LOG_BANNER __VA_ARGS__)

/* Common limits. */
#define TFW_CFG_NAME_MAX_LEN (1 << 6)
#define TFW_CFG_PATH_MAX_LEN (1 << 8)
#define TFW_CFG_STR_MAX_LEN  (1 << 16)
#define TFW_CFG_TEXT_MAX_LEN (1 << 24)
#define TFW_CFG_NODE_MAX_VALS     (1 << 8)
#define TFW_CFG_NODE_MAX_ATTRS    (1 << 8)
#define TFW_CFG_NODE_MAX_CHILDREN (1 << 10)

#endif /* __TFW_CFG_PRIVATE_H__ */
