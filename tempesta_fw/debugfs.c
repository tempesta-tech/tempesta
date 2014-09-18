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

#include <linux/string.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/debugfs.h>

#include "tempesta.h"
#include "debugfs.h"
#include "log.h"

struct dentry *tfw_debugfs_root;


static struct dentry *
lookup_file(const char *name, const struct dentry *parent)
{
	struct path path;
	int ret = vfs_path_lookup(parent, NULL, name, 0, &path);

	return (ret ? NULL : path.dentry);
}


static struct dentry *
force_create(const char *name, void *data,
                    const struct file_operations *fops)
{
	int ret;
	size_t name_size;
	char *buf, *pos, *component;
	struct dentry *parent, *child;

	/* Copy the path to a temorary buffer. */
	name_size = strlen(name) + 1;
	buf = kmalloc(name_size, GFP_KERNEL);
	BUG_ON(ZERO_OR_NULL_PTR(buf));
	strlcpy(buf, name, name_size);

	/* Eat the leading slash to allow specify either /foo/bar or foo/bar */
	pos = buf;
	if (*pos == '/')
		++pos;

	/* Walk over the path and create non-existing directories. */
	parent = tfw_debugfs_root;
	component = pos;
	do {
		if (*pos != '/')
			continue;

		*pos = '\0';
		child = lookup_file(component, parent);
		if (!child) {
			child = debugfs_create_dir(component, parent);
			BUG_ON(!parent);
		}
		parent = child;
		component = pos + 1;
	} while (*(++pos));
	

	/* Remove the file if it already exists. */
	child = lookup_file(component, parent);
	if (child) {
		TFW_DBG("Removing debugfs file: %s\n", name);
		debugfs_remove(child);
	}

	/* Create the actual file. */
	child = debugfs_create_file(component, S_IRWXU, parent, data, fops);
	if (IS_ERR_OR_NULL(child)) {
		int err = PTR_ERR(child);
		TFW_WARN("Can't create debugfs file: %s (%d)\n", name, err);
	} else {
		TFW_DBG("Created debugfs file: %s\n", name);
	}

	kfree(buf);

	return child;
}


static ssize_t
op_trigger_read(struct file *f, char __user *b, size_t s, loff_t *p)
{
	tfw_debugfs_trigger_t trigger_fn = f->private_data;
	if (trigger_fn)
		trigger_fn();

	return 0;
}

static ssize_t
op_trigger_write(struct file *f, const char __user *b, size_t s, loff_t *p)
{
	tfw_debugfs_trigger_t trigger_fn = f->private_data;
	if (trigger_fn)
		trigger_fn();

	return s;
}

void tfw_debugfs_set_trigger(const char *path, tfw_debugfs_trigger_t fn)
{
	static const struct file_operations fops = {
		.open = simple_open,
		.llseek = default_llseek,
		.read = op_trigger_read,
		.write = op_trigger_write
	};

	force_create(path, fn, &fops);
}


int tfw_debugfs_init(void)
{
	int ret = 0;

	tfw_debugfs_root = debugfs_create_dir("tempesta", NULL);
	if (IS_ERR_OR_NULL(tfw_debugfs_root)) {
		ret = (int)PTR_ERR(tfw_debugfs_root);
		TFW_WARN("Can't create debugfs directory (%d)\n", ret);
	}

	return ret;
}

void tfw_debugfs_exit(void)
{
	if (tfw_debugfs_root) {
		debugfs_remove_recursive(tfw_debugfs_root);
		tfw_debugfs_root = NULL;
	}
}