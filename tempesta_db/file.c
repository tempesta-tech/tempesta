/**
 *		Tempesta DB
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
#include "file.h"

/**
 * Open, mmap and mlock the specified file to be able to read and
 * write to it in softirqs.
 *
 * The function must not be called from softirq!
 */
int
tdb_file_open(TDB *db)
{
	unsigned long addr;
	struct mm_struct *mm = current->mm;
	/* Must be called from kernel thread context. */
	BUG_ON(mm != &init_mm);

	strcat(db->path, "/" TDB_FNAME);

	db->filp = filp_open(db->path, O_CREAT | O_RDWR, 0600);
	if (IS_ERR(db->filp))
		return PTR_ERR(db->filp);
	if (!db->filp || !db->filp->f_dentry)
		return -ENOENT;

	/* mmap and mlock the file to make it accessible from softirq. */
	addr = do_mmap_pgoff();
	if (IS_ERR((void *)addr))

	db->map = addr;

	return 0;
}

void
tdb_file_close(TDB *db)
{
	/* TODO */
}


