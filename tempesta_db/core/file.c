/**
 *		Tempesta DB
 *
 * File mapping and IO.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
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
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/tempesta.h>
#include <linux/topology.h>
#include <linux/writeback.h>

#include "file.h"

/**
 * Node of list of free/user memory areas.
 * Used for best-fit memory allocation.
 */
typedef struct marea_t {
	struct marea_t		*prev, *next; /* NULL-terminated list */
	unsigned long		start;
	unsigned long		pages;
	unsigned long		flags;
} MArea;

#define MA_F_USED		0x1
#define MA_FREE(ma)		(!((ma)->flags & MA_F_USED))

static DEFINE_MUTEX(map_mtx);
static MArea mas[MAX_NUMNODES];

/**
 * Find and return best fit free memory area.
 */
static MArea *
ma_get_best_fit(unsigned long len, int node)
{
	MArea *ma, *best_fit = NULL;
	unsigned long req_pages = len / PAGE_SIZE;

	for (ma = &mas[node]; ma; ma = ma->next) {
		if (MA_FREE(ma)
		    && ma->pages > req_pages
		    && (!best_fit || best_fit->pages > ma->pages))
			best_fit = ma;
	}

	return best_fit;
}

/**
 * Split @len length memory area from @ma.
 */
static MArea *
ma_split(MArea *ma, unsigned long len)
{
	unsigned long req_pages = len / PAGE_SIZE;
	MArea *ret;

	BUG_ON(ma->pages < req_pages);
	BUG_ON(!MA_FREE(ma));

	if (ma->pages == req_pages) {
		ma->flags |= MA_F_USED;
		return ma;
	}

	/* ma is larger than we need, split it. */
	ret = kmalloc(sizeof(MArea), GFP_KERNEL);
	if (!ret)
		return NULL;

	ma->pages -= req_pages;

	ret->pages = req_pages;
	ret->flags = MA_F_USED;
	/* @ret is the tail of @ma. */
	ret->start = ma->start + ma->pages * PAGE_SIZE;
	ret->prev = ma;
	ret->next = ma->next;
	if (ret->next)
		ret->next->prev = ret;
	ma->next = ret;

	return ret;
}

static MArea *
ma_lookup(unsigned long addr, int node)
{
	MArea *ma;

	for (ma = &mas[node]; ma; ma = ma->next)
		if (ma->start == addr)
			return ma;
	return NULL;
}

/**
 * Merge two free memory areas if they aren't the same.
 */
static MArea *
__ma_merge(MArea *left, MArea *right)
{
	if (!MA_FREE(left) || !MA_FREE(right))
		return left;
	BUG_ON(left->start == right->start);

	left->pages += right->pages;

	left->next = right->next;
	if (right->next)
		right->next->prev = left;

	kfree(right);

	return left;
}

/**
 * Free a memory area and merge it with free siblings if possible.
 * Never tries to free staticaly allocated MArea.
 */
static void
__ma_free(MArea *ma)
{
	ma->flags &= ~MA_F_USED;
	if (ma->prev)
		ma = __ma_merge(ma->prev, ma);
	if (ma->next)
		__ma_merge(ma, ma->next);
}

static void
ma_free(unsigned long addr, int node)
{
	MArea *ma;

	ma = ma_lookup(addr, node);
	if (!ma) {
		TDB_ERR("Cannot find memory area for %#lx address at node %d\n",
			addr, node);
		return;
	}
	__ma_free(ma);
}

/**
 * Map file to reserved set of unswappable pages.
 */
static unsigned long
tempesta_map_file(struct file *file, unsigned long len, int node)
{
	mm_segment_t oldfs;
	MArea *ma;
	loff_t off = 0;
	unsigned long addr = -ENOMEM;

	BUG_ON(len & ~TDB_EXT_MASK);
	if (file->f_inode->i_size != len) {
		TDB_ERR("Bad file size %lld while expected is %lu\n",
			file->f_inode->i_size, len);
		return -EBADF;
	}

	mutex_lock(&map_mtx);

	ma = ma_get_best_fit(len, node);
	if (!ma) {
		TDB_ERR("Cannot allocate %lu pages at node %d\n",
			len / PAGE_SIZE, node);
		goto err;
	}

	ma = ma_split(ma, len);
	if (!ma)
		goto err;

	get_file(file);

	oldfs = get_fs();
	set_fs(get_ds());

	addr = vfs_read(file, (char *)ma->start, len, &off);
	if (addr != len) {
		TDB_ERR("Cannot read %lu bytes to addr %p, ret = %ld\n",
			len, (void *)ma->start, addr);
		fput(file);
		__ma_free(ma);
		goto err_fs;
	}

	addr = ma->start;
err_fs:
	set_fs(oldfs);
err:
	mutex_unlock(&map_mtx);

	return addr;
}

/**
 * Syncronize memory mapping with the file.
 * Called from process context.
 */
static void
tempesta_unmap_file(struct file *file, unsigned long addr, unsigned long len,
		    int node)
{
	mm_segment_t oldfs;
	MArea *ma;
	loff_t off = 0;
	ssize_t r;

	mutex_lock(&map_mtx);

	ma = ma_lookup(addr, node);
	if (!ma) {
		TDB_ERR("Cannot sync memory area for %#lx address at node %d\n",
		     addr, node);
		goto err;
	}

	oldfs = get_fs();
	set_fs(get_ds());

	r = vfs_write(file, (void *)ma->start, len, &off);
	if (r != len) {
		TDB_ERR("Cannot sync mapping %lx of size %lu pages\n",
			ma->start, ma->pages);
		goto err_fs;
	}

err_fs:
	set_fs(oldfs);
err:
	fput(file);
	ma_free(addr, node);

	mutex_unlock(&map_mtx);
}

/**
 * Open, mmap and mlock the specified file to be able to read and
 * write to it in softirqs.
 * Use MAP_SHARED to synchronize the mapping with underlying file.
 *
 * The function must not be called from softirq!
 */
int
tdb_file_open(TDB *db, unsigned long size)
{
	unsigned long ret, addr;
	struct file *filp;
	struct inode *inode;

	filp = filp_open(db->path, O_CREAT | O_RDWR, 0600);
	if (IS_ERR(filp)) {
		TDB_ERR("Cannot open db file %s\n", db->path);
		return PTR_ERR(filp);
	}
	BUG_ON(!filp || !filp->f_path.dentry);

	if (!filp->f_op->fallocate) {
		TDB_ERR("TDB requires filesystem with fallocate support\n");
		filp_close(db->filp, NULL);
		return -EBADF;
	}

	/* Allocate continous extents. */
	inode = file_inode(filp);
	sb_start_write(inode->i_sb);
	ret = filp->f_op->fallocate(filp, 0, 0, size);
	sb_end_write(inode->i_sb);
	if (ret) {
		TDB_ERR("Cannot fallocate file, %ld\n", ret);
		filp_close(db->filp, NULL);
		return ret;
	}

	addr = tempesta_map_file(filp, size, db->node);
	if (IS_ERR((void *)addr)) {
		TDB_ERR("Cannot map file\n");
		filp_close(filp, NULL);
		return (int)addr;
	}

	db->filp = filp;
	db->hdr = (TdbHdr *)addr;

	file_accessed(filp);

	return 0;
}

void
tdb_file_close(TDB *db)
{
	if (!db->hdr || !db->hdr->dbsz)
		return;

	tempesta_unmap_file(db->filp, (unsigned long)db->hdr, db->hdr->dbsz,
			    db->node);

	filp_close(db->filp, NULL);
}

int
tdb_init_mappings(void)
{
	int node;
	TempestaMapping *tm;

	for_each_node_with_cpus(node) {
		if (tempesta_get_mapping(node, &tm)) {
			TDB_ERR("Cannot get mapping for node %d\n", node);
			return -ENOMEM;
		}
		mas[node].start = tm->addr;
		mas[node].pages = tm->pages;
	}
	return 0;
}
