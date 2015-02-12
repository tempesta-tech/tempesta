/**
 *		Tempesta DB
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015 Tempesta Technologies.
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
#include <linux/fs.h>
#include <linux/mman.h>
#include <linux/sched.h>

#include "file.h"

/**
 * Open, mmap and mlock the specified file to be able to read and
 * write to it in softirqs.
 *
 * The function must not be called from softirq!
 *
 * FIXME database header must be extent aligned, so mmap must map file by
 * aligned address.
 */
int
tdb_file_open(TDB *db, unsigned long size)
{
	unsigned long addr, populate;
	struct mm_struct *mm = current->mm;
	struct file *filp;

	/* Must be called from kernel thread context. */
	BUG_ON(mm != &init_mm);

	strcat(db->path, "/" TDB_FNAME);

	filp = filp_open(db->path, O_CREAT | O_RDWR, 0600);
	if (IS_ERR(filp))
		return PTR_ERR(filp);
	if (!filp || !filp->f_dentry)
		return -ENOENT;

	/* Allocate continous extents. */
	if (filp->f_op->fallocate) {
		struct inode *inode = file_inode(filp);
		sb_start_write(inode->i_sb);
		filp->f_op->fallocate(filp, 0, 0, size);
		sb_end_write(inode->i_sb);
	}

	down_write(&init_mm.mmap_sem);

	/*
	 * mmap() and mlock() the file to make it accessible from softirq.
	 * Use MAP_SHARED to synchronize the mapping with underlying file.
	 */
	addr = do_mmap_pgoff(filp, 0, size, PROT_READ|PROT_WRITE,
			     MAP_SHARED|MAP_POPULATE|MAP_LOCKED, 0, &populate);

	up_write(&init_mm.mmap_sem);

	if (IS_ERR((void *)addr)) {
		filp_close(filp, NULL);
		return (long)addr;
	}
	if (populate)
		mm_populate(addr, populate);

	db->filp = filp;
	db->hdr = (TdbHdr *)addr;

	return 0;
}

void
tdb_file_close(TDB *db)
{
	if (!db->hdr)
		return;

	vm_munmap((unsigned long)db->hdr, db->hdr->dbsz);

	filp_close(db->filp, NULL);

	db->filp = NULL;
	db->hdr = NULL;
}


