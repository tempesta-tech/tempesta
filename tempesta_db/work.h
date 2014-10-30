/**
 *		Tempesta DB
 *
 * Delayed work definitions.
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
#ifndef __WORK_H__
#define __WORK_H__

#include <linux/workqueue.h>

#include "tdb.h"

/* Work to open new database file. */
typedef struct tdb_work_t {
	struct work_struct	work;
	TDB			*db;
	unsigned long		fsize;
	unsigned int		rsize;
} TdbWork;

#endif /* __WORK_H__ */
