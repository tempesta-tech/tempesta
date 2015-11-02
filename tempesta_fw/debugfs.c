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

#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/string.h>
#include <linux/version.h>

#include "debugfs.h"
#include "log.h"

#ifdef DEBUG

#if LINUX_VERSION_CODE > KERNEL_VERSION(3,10,10)
extern int
vfs_path_lookup(struct dentry *dentry, struct vfsmount *mnt, const char *name,
		unsigned int flags, struct path *path);
#endif

/* The root directory for the Tempesta debugfs module.
 * All paths are referenced relative to this root. */
struct dentry *tfw_debugfs_root;

/* Name of the directory which is created in the debugfs upon initialization. */
#define TFW_DEBUGFS_ROOT_NAME "tempesta"

/**
 * Initialize the debugfs wrapper by creating a directory in the debugfs
 * where all files owned by the Tempesta FW are hosted.
 */
int
tfw_debugfs_init(void)
{
	int ret = 0;

	tfw_debugfs_root = debugfs_create_dir(TFW_DEBUGFS_ROOT_NAME, NULL);

	if (IS_ERR_OR_NULL(tfw_debugfs_root)) {
		ret = (int)PTR_ERR(tfw_debugfs_root);
		TFW_WARN("Can't create debugfs directory (%d)\n", ret);
	}

	return ret;
}

/**
 * Delete the Tempesta's debugfs directory with all files recursively.
 */
void
tfw_debugfs_exit(void)
{
	if (tfw_debugfs_root) {
		debugfs_remove_recursive(tfw_debugfs_root);
		tfw_debugfs_root = NULL;
	}
}

/**
 * Look up for a file (or directory) in VFS.
 */
static struct dentry *
lookup_file(const char *path, struct dentry *parent)
{
	int ret;
	struct path p;

	BUG_ON(!parent);
	ret = vfs_path_lookup(parent, NULL, path, 0, &p);

	return (ret ? NULL : p.dentry);
}

/**
 * Create a file in the debugfs, also create parent directories if needed and
 * remove the old file if it exists.
 *
 * @param path  Path to a file to be created.
 *              The path is always treated relative to the Tempesta root
 *              directory in the debugfs (see tfw_debugfs_root).
 * @param data  A pointer to some data which is saved in 'file' and 'inode'
 *              structures. It may be retrieved by any function in @fops as
 *              file->private_data or file->f_inode->i_private (it is copied
 *              into both places).
 * @param fops  A set of functions that handle system calls on the created file.
 *
 *
 * The function creates a file in the debugfs, but does it in a robust way:
 *  - the file is replaced if it already exists
 *  - all parent directories are created if they don't exist
 *
 * Returns: An ERR_PTR if the file is not created.
 */
static struct dentry *
create_with_parents(const char *path, void *data,
		    const struct file_operations *fops)
{
	size_t name_size;
	char *buf, *pos, *component;
	struct dentry *parent, *child;

	/* Copy the path to a temporary buffer where it can be modified. */
	name_size = strlen(path) + 1;
	buf = kmalloc(name_size, GFP_KERNEL);
	BUG_ON(ZERO_OR_NULL_PTR(buf));
	strlcpy(buf, path, name_size);

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
		TFW_DBG("Removing already existing debugfs file: %s\n", path);
		debugfs_remove(child);
	}

	/* Create the actual file. */
	child = debugfs_create_file(component, S_IRWXU, parent, data, fops);
	if (IS_ERR_OR_NULL(child)) {
		int err = PTR_ERR(child);
		TFW_WARN("Can't create debugfs file: %s (%d)\n", path, err);
	} else {
		TFW_DBG("Created debugfs file: %s\n", path);
	}

	kfree(buf);

	return child;
}

/**
 * A state maintained between open() and release() calls.
 *
 * Usage of this structure depens on the data direction:
 *
 * 1. If a file is open()'ed for reading (@is_input is false):
 * - open() allocates the @buf and invokes a callback that writes data to it.
 * - read() just copies data from the @buf to the user-space.
 * - write() returns an error.
 * - close() releases all the allocated memory.
 *
 * 2. If a file is open()'ed for writing (@is_input is true):
 * - open() allocates the @buf
 * - read() returns an error.
 * - write() copies data from user-space to the @buf.
 * - close() invokes a callback passing the @buf to it and releases the memory.
 *
 * The file may be open()'ed only for either reading or writing but not both.
 */
typedef struct {
	bool is_input;
	int len;
	int buf_size;
	char *buf;
} TfwDebugfsIoState;

static int
fop_open(struct inode *inode, struct file *file)
{
	fmode_t mode = file->f_mode;
	tfw_debugfs_handler_t fn = file->f_inode->i_private;
	TfwDebugfsIoState *state;

	if ((mode & FMODE_READ) && (mode & FMODE_WRITE)) {
		TFW_ERR("This debugfs file can't be opened in read-write mode");
		return -EPERM;
	}

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	BUG_ON(!state);

	/* Simply allocate a fixed-size buffer. The buffer doesn't expand, the
	 * data is cropped if it doesn't fit to it. Later on we may change it */
	state->buf_size = PAGE_SIZE;
	state->buf = kmalloc(state->buf_size, GFP_KERNEL);
	BUG_ON(!state->buf);

	if (mode & FMODE_WRITE)
		state->is_input = true;
	else
		state->len = fn(state->is_input, state->buf, state->buf_size);

	file->private_data = state;

	return 0;
}

static ssize_t
fop_read(struct file *file, char __user *user_buf, size_t count,
	 loff_t *ppos)
{
	TfwDebugfsIoState *state = file->private_data;

	if (state->is_input) {
		TFW_ERR("Can't read this debugfs file: "
			"it was open()'ed only for writing\n");
		return -EPERM;
	}

	if (state->len < 0)
		return state->len;

	return simple_read_from_buffer(user_buf, count, ppos,
				       state->buf,
				       state->len);
}

static ssize_t
fop_write(struct file *file, const char __user *user_buf,
	  size_t count,
	  loff_t *ppos)
{
	int len;
	TfwDebugfsIoState *state = file->private_data;

	if (!state->is_input) {
		TFW_ERR("Can't write to this debugfs file: "
			"it was open()'ed only for reading\n");
		return -EPERM;
	}

	/* copy data from user-space */
	len = simple_write_to_buffer(state->buf, (state->buf_size - 1),
				     ppos,
				     user_buf, count);
	if (len > 0) {
		state->len += len;
		state->buf[state->len] = '\0';
	}

	return len;
}

static int
fop_release(struct inode *inode, struct file *file)
{
	int ret = 0;
	tfw_debugfs_handler_t fn = file->f_inode->i_private;
	TfwDebugfsIoState *state = file->private_data;

	if (state->is_input)
		ret = fn(state->is_input, state->buf, state->len);

	kfree(state->buf);
	kfree(state);

	return ret;
}

/**
 * Create a file in debugfs and bind a function with it.
 *
 * @path  Path to of a file to be created.
 *        The path is always treated as relative to tempesta root directory
 *        in the debugfs. The file may exist, in this case it will be replaced.
 *        Parent directories may not exist (they will be created automatically).
 * @fn    A function that handles I/O (that is either receives or sends data to
 *        user-space).
 *
 * This function allows to bind a file (that may be read/written in user-space)
 * with a function (that works in kernel-space).
 *
 * Consider the following example:
 *
 * int my_io_handler(bool is_input, char *buf, size_t size)
 * {
 *         if (is_input) {
 *                 printk("got input data from user-space: %.*s", size, buf);
 *                 return 0;
 *         } else {
 *                 return snprintf("hello from kernel-space!\n");
 *         }
 * }
 *
 * tfw_debugfs_bind("/foo/bar", my_io_handler);
 *
 * The code binds the file /foo/bar with the function my_io_handler() and allows
 * to interact with the kernel function from a user-space shell like this:
 *   $ cat /sys/kernel/debug/tempesta/foo/bar
 *   hello from kernel-space!
 *   $ echo "hi from user-space" > /sys/kernel/debug/tempesta/foo/bar
 *   $ dmesg | head -n1
 *   got input data from user-space: hi from user-space
 *
 * When the file is open()'ed in read mode, the my_io_handler() is called with
 * is_input=false. In this case the function is requested to put some data to
 * the buffer. The buffer then is saved and returned to user-space during
 * subsequent read() calls until the file is close()'d.
 *
 * When the file is open()'ed in write mode, the data is accumulated in the
 * buffer during write() calls. When the file is close()'d, the my_io_handler()
 * is called to take the data received from user-space.
 *
 * Therefore, the handler function doesn't need to care about streaming, it
 * receives or sends the data "atomically" with a single big chunk.
 * This approach simplifies your code (no need to preserve state between calls),
 * but it is not very effective, so don't use it for large amounts of data.
 *
 * @return A status code: 0 if the file is created, -1 otherwise.
 */
int
tfw_debugfs_bind(const char *path, tfw_debugfs_handler_t fn)
{
	static const struct file_operations fops = {
		.llseek = default_llseek,
		.open = fop_open,
		.read = fop_read,
		.write = fop_write,
		.release = fop_release,
	};
	struct dentry *d;

	BUG_ON(!path || !fn);
	d = create_with_parents(path, fn, &fops);

	return IS_ERR_OR_NULL(d) ? -1 : 0;
}
EXPORT_SYMBOL(tfw_debugfs_bind);

#else /* ifdef DEBUG */

int tfw_debugfs_bind(const char *path, tfw_debugfs_handler_t handler_fn)
{
	return 0;
}
EXPORT_SYMBOL(tfw_debugfs_bind);

int tfw_debugfs_init(void)
{
	return 0;
}

void tfw_debugfs_exit(void)
{
}

#endif /* ifndef DEBUG */
