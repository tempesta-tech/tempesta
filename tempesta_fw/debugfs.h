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
#ifndef __TFW_DEBUGFS_H__
#define __TFW_DEBUGFS_H__

typedef int (*tfw_debugfs_handler_t)(bool is_input, char *buf, size_t size);

int tfw_debugfs_bind(const char *path, tfw_debugfs_handler_t handler_fn);

int tfw_debugfs_init(void);
void tfw_debugfs_exit(void);


#endif	/* __TFW_DEBUGFS_H__ */

