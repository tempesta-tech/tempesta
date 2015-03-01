/**
 *		Tempesta DB
 *
 * File mapping and IO.
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
	ret->start = ma->start + (ma->pages - req_pages) * PAGE_SIZE;
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
	struct iovec iov;
	struct kiocb kiocb;
	MArea *ma;
	unsigned long addr = -ENOMEM;
	ssize_t r;

	BUG_ON(len & ~TDB_EXT_MASK);
	BUG_ON(file->f_inode->i_size != len);

	mutex_lock(&map_mtx);

	ma = ma_get_best_fit(len, node);
	if (!ma) {
		TDB_ERR("cannot allocate %lu pages at node %d\n",
			len / PAGE_SIZE, node);
		goto err;
	}

	ma = ma_split(ma, len);
	if (!ma)
		goto err;

	get_file(file);

	iov = (struct iovec) {
		.iov_base = (void *)ma->start,
		.iov_len = len,
	};
	init_sync_kiocb(&kiocb, file);
	kiocb.ki_left = len;
	kiocb.ki_nbytes = len;
	r = file->f_op->aio_read(&kiocb, &iov, 1, 0);
	if (r == -EIOCBQUEUED) {
		r = wait_on_sync_kiocb(&kiocb);
	}
	else if (r != len) {
		TDB_ERR("cannot read %lu bytes to addr %p, ret = %ld\n",
			len, r, (void *)ma->start);
		fput(file);
		__ma_free(ma);
		goto err;
	}

	addr = ma->start;
err:
	mutex_unlock(&map_mtx);

	return addr;
}

/**
 * Called from process context.
 */
static void
tempesta_unmap_file(struct file *file, unsigned long addr, unsigned long len,
		    int node)
{
	int o;
	MArea *ma;
	struct address_space *mapping = file->f_mapping;
	struct writeback_control wbc = {
		.nr_to_write	= LONG_MAX,
		.range_start	= 0,
		.range_end	= LLONG_MAX,
		.sync_mode	= WB_SYNC_ALL,
	};

	mutex_lock(&map_mtx);

	/* Syncronize memory mapping with the file. */
	BUG_ON(!mapping->a_ops->writepage); /* Don't use the filesystem. */
	ma = ma_lookup(addr, node);
	if (!ma) {
		TDB_ERR("Cannot sync memory area for %#lx address at node %d\n",
		     addr, node);
		goto err;
	}
	for (o = 0; o < len; o += PAGE_SIZE) {
		struct page *page = virt_to_page(ma->start + o);
		/* FIXME replace by direct IO. */
		if (mapping->a_ops->writepage(page, &wbc) < 0) {
			TDB_ERR("Cannot sync page %lu from mapping %lx"
				" of size %lu pages\n",
				o / PAGE_SIZE, ma->start, ma->pages);
			goto err;
		}
	}

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
tdb_file_open(TDB *db, unsigned long size, int node)
{
	unsigned long addr;
	struct file *filp;

	filp = filp_open(db->path, O_CREAT | O_RDWR, 0600);
	if (IS_ERR(filp)) {
		TDB_ERR("cannot open db file %s\n", db->path);
		return PTR_ERR(filp);
	}
	BUG_ON(!filp || !filp->f_dentry);

	/* Allocate continous extents. */
	if (filp->f_op->fallocate) {
		struct inode *inode = file_inode(filp);
		sb_start_write(inode->i_sb);
		filp->f_op->fallocate(filp, 0, 0, size);
		sb_end_write(inode->i_sb);
	}

	addr = tempesta_map_file(filp, size, node);
	if (IS_ERR((void *)addr)) {
		TDB_ERR("cannot map file\n");
		filp_close(filp, NULL);
		return (int)addr;
	}

	db->filp = filp;
	db->hdr = (TdbHdr *)addr;

	file_accessed(filp);

	return 0;
}

void
tdb_file_close(TDB *db, int node)
{
	if (!db->hdr || db->hdr->dbsz)
		return;

	tempesta_unmap_file(db->filp, (unsigned long)db->hdr, db->hdr->dbsz,
			    node);

	filp_close(db->filp, NULL);

	db->filp = NULL;
	db->hdr = NULL;
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
