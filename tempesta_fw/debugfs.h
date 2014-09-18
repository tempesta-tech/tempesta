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
#ifndef __TFW_DEBUGFS_H__
#define __TFW_DEBUGFS_H__

typedef void (*tfw_debugfs_trigger_t)(void);

void tfw_debugfs_set_trigger(const char *path, tfw_debugfs_trigger_t fn);

int tfw_debugfs_init(void);
void tfw_debugfs_exit(void);

#endif	/* __TFW_DEBUGFS_H__ */

