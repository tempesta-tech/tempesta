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

/* The root directory for the Tempesta debugfs module.
 * All paths are referenced relative to this root. */
struct dentry *tfw_debugfs_root;

/* Name of the directory which is created in the debugfs upon initialization. */
#define TFW_DEBUGFS_ROOT_NAME "tempesta"


/**
 * Initialize the Tempesta debugfs wrapper.
 *
 * Return: an error code or zero on success.
 */
int tfw_debugfs_init(void)
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
 * Shutdown the Tempesta debugfs wrapper.
 *
 * The function deletes all files and directories created by this wrapper
 * and releases all resources.
 */
void tfw_debugfs_exit(void)
{
	if (tfw_debugfs_root) {
		debugfs_remove_recursive(tfw_debugfs_root);
		tfw_debugfs_root = NULL;
	}
}

/**
 * Look up for a file in VFS.
 *
 * @param name    A string containing a path.
 * @param parent  A dentry that represents a parent directory where the
 *                file is searched. Must not be NULL.
 *
 * Return: A pointer to dentry if the file (or directory) is found,
 *         NULL if it is not found or an error occurred.
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
 * @param path  A string containing a path to the file.
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
 * Returns:  A pointer to dentry if the file is created.
 *           A NULL or an error pointer in case of error (it may be tested
 *           with IS_ERR_OR_NULL()).
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
 * The read() operation for files created by tfw_debugfs_set_trigger().
 *
 * The function simply invokes a trigger which is set by the file creator.
 * It doesn't read any data and always returns EOF.
 */
static ssize_t
op_trigger_read(struct file *f, char __user *b, size_t s, loff_t *p)
{
	tfw_debugfs_trigger_t trigger_fn = f->private_data;
	if (trigger_fn)
		trigger_fn();

	return 0;
}

/**
 * The write() operation for files created by tfw_debugfs_set_trigger()
 *
 * The function only invokes a trigger function set by the file creator.
 * It doesn't write any data, but always returns the size of the input buffer
 * as if all the data was written successfully.
 */
static ssize_t
op_trigger_write(struct file *f, const char __user *b, size_t s, loff_t *p)
{
	tfw_debugfs_trigger_t trigger_fn = f->private_data;
	if (trigger_fn)
		trigger_fn();

	return s;
}

/**
 * Create a file in debugfs so that the given function is invoked on any
 * read or write to the file.
 *
 * @path  A path to a file to be created. If the file already exists, it is
 *        replaced. All parent directories are created if they don't exist.
 *        The path is always treated as relative to the Tempesta root directory
 *        in the debugfs (see tfw_debugfs_root).
 * @fn    The trigger function which is called on any read or write to the file.
 *        The function doesn't take any arguments or return any value.
 *
 * This function provides a simple way to trigger kernel functions from
 * userspace via the debugfs. It creates a file and binds read()/write()
 * operations so that the given @fn is called on any such operation without
 * actual reading or writing any data.
 *
 * For example, consider this code:
 *   void say_hello(void)
 *   {
 *           printk("hello from kernel\n");
 *   }
 *   tfw_debugfs_set_trigger("/foo/bar/hello", say_hello);
 *
 * It will create the file foo/bar/hello with all parent directories under
 * the tempesta debugfs root directory. Then from a user-space shell you may do:
 *   echo > /sys/kernel/debug/tempesta/foo/bar/hello
 *   cat /sys/kernel/debug/tempesta/foo/bar/hello
 * 
 * Both will trigger the say_hello() and you may see the message in the 'dmesg'.
 */
void tfw_debugfs_set_trigger(const char *path, tfw_debugfs_trigger_t fn)
{
	static const struct file_operations fops = {
		.open = simple_open,
		.llseek = default_llseek,
		.read = op_trigger_read,
		.write = op_trigger_write
	};

	create_with_parents(path, fn, &fops);
}
EXPORT_SYMBOL(tfw_debugfs_set_trigger);


/**
 * A state maintained between open() and release() operations for files
 * created by tfw_debugfs_set_handlers().
 *
 * @buf       A buffer passed to read/write handlers (the kernel-space buffer).
 * @buf_size  Size of the allocated @buf.
 * @data_len  Count of bytes written to the @buf.
 */
typedef struct {
	char *buf;
	size_t buf_size;
	size_t data_len;
} TfwDebugfsIoState;

/**
 * The open() operation for files created by tfw_debugfs_set_handlers().
 *
 * The function is called when the file is opened. It allocates a buffer
 * and puts the pointer to the file->private_data from where it can be
 * retrieved by read/write operations.
 *
 * Note that this is not a default behavior for debugfs operations.
 * By default the simple_open() is called that copies inode->i_private to
 * file->private_data, and we replace this behavior, so now you can't assume
 * that the data passed to debugfs_file_create() will be located ad the
 * file->private_data (although the data is still accessible via the inode).
 */
static int
handlerio_fop_open(struct inode *inode, struct file *file)
{
	TfwDebugfsIoState *state = kzalloc(sizeof(*state), GFP_KERNEL);
	BUG_ON(!state);

	/* For simplicity we are allocating one size buffer.
	 * Later on we may want to resize it dynamically. */
	state->buf_size = PAGE_SIZE;
	state->buf = kmalloc(state->buf_size, GFP_KERNEL);
	BUG_ON(!state->buf);

	file->private_data = state;

	return 0;
}

/**
 * The release() operation for files created by tfw_debugfs_set_handlers().
 *
 * The function is called when the file is closed.
 * It releases memory allocated by handlerio_fop_open().
 */
static  int
handlerio_fop_release (struct inode *inode, struct file *file)
{
	TfwDebugfsIoState *state = file->private_data;

	kfree(state->buf);
	kfree(state);

	return 0;
}

/**
 * The read() operation for files created by tfw_debugfs_set_handlers().
 *
 * The function is called when the file is read from user-space.
 * It calls a handler set by the tfw_debugfs_set_handlers() and returns
 * output buffer of the handler to the user-space.
 *
 * The handler is invoked only once after the file is open()'ed.
 * Once the buffer is written by the handler it is saved and then used for all
 * subsequent read() calls until the file is closed. So the handler doesn't
 * need to handle the position of the file, it just provides one big buffer and
 * this function streams it to the user-space.
 */
static ssize_t
handlerio_fop_read(struct file *file, char __user *user_buf, size_t count,
	           loff_t *ppos)
{
	int buf_size, len, ret;
	char *buf;
	TfwDebugfsIoState *state = file->private_data;
	TfwDebugfsHandlers *handlers = file->f_inode->i_private;
	tfw_debugfs_handler_t read_handler = handlers->read;

	if (!read_handler) {
		return -EPERM;
	}

	buf = state->buf;
	buf_size = state->buf_size;
	len = state->data_len;

	/* call the handler only once */
	if (!len) {
		len = read_handler(buf, buf_size);
		if (len <= 0)
			return len;
	}
	state->data_len = len;

	/* copy requested sub-buffer to the user-space */
	ret = simple_read_from_buffer(user_buf, count, ppos, buf, len);

	return ret;
}

/**
 * The write() operation for files created by tfw_debugfs_set_handlers().
 *
 * The function is called when the file is written from user-space.
 * It invokes the handler which is set by tfw_debugfs_set_handlers() and
 * passes the buffer copied from the user space to the handler.
 */
static ssize_t
handlerio_fop_write(struct file *file, const char __user *user_buf,
		    size_t count, loff_t *ppos)
{
	int buf_size, len;
	char *buf;
	TfwDebugfsIoState *state = file->private_data;
	TfwDebugfsHandlers *handlers = file->f_inode->i_private;
	tfw_debugfs_handler_t write_handler = handlers->write;

	if (!write_handler) {
		return -EPERM;
	}

	buf = state->buf;
	buf_size = state->buf_size - 1;

	/* copy data from user-space */
	len = simple_write_to_buffer(buf, buf_size, ppos, user_buf, count);

	if (len > 0) {
		state->data_len = len;

		/* Call the handler and ensure the input data is terminated. */
		buf[len] = '\0';
		write_handler(buf, len);
	}

	return len;
}


/**
 * Create a file in the debugfs and bind read/write handler functions with it.
 *
 * @param path      A string that contains a path to a file to be created.
 *                  The file will be replaced if it already exists, and all
 *                  parent directories will be created automatically if they
 *                  don't exist. Also path is always treated as relative to the
 *                  Tempesta root directory in the debugfs.
 * @param handlers  A structure that contains pointers to functions that are
 *                  called when the file is read or written from the user-space.
 *                  The pointer is saved and referenced while the file exists,
 *                  so the structure must not be allocated on the stack.
 *                  The pointer must not be null, but any of the function
 *                  pointers inside may be null, in this case an error will be
 *                  returned on a corresponding system call.
 *
 * This function allows to create a file in the debugfs and hookup functions
 * to it for handling reads and writes on the file.
 *
 * Consider the example:
 *   ssize_t handle_read(char *buf, size_t buf_size)
 *   {
 *           return snprintf(buf, buf_size, "hello from kernel\n");
 *   }
 *
 *   ssize_t handle_write(char *data, size_t data_len)
 *   {
 *           return printk("got data from user-space: %.*s", data_len, data);
 *   }
 *
 *   static TfwDebugfsHandlers handlers = { handle_read, handle_write };
 *   tfw_debugfs_set_handlers("/foo/bar/baz", &handlers);
 *
 * The code above will create the file "foo/bar/baz" under the Tempesta debugfs
 * root directory. Non-existing parent directories are created automatically.
 * Then you may do some read/write from user-space and the handlers will be
 * invoked in the kernel-space:
 *   $ cat /sys/kernel/debug/foo/bar/baz
 *   hello from kernel
 *   $ echo "hello from user" > /sys/kernel/debug/foo/bar/baz
 *   $ dmesg | head -n1
 *   got data from user-space: hello from user
 */
void tfw_debugfs_set_handlers(const char *path, TfwDebugfsHandlers *handlers)
{
	static const struct file_operations fops = {
		.llseek = default_llseek,
		.open = handlerio_fop_open,
		.release = handlerio_fop_release,
		.read = handlerio_fop_read,
		.write = handlerio_fop_write,
	};

	BUG_ON(!handlers);
	BUG_ON(!handlers->read && !handlers->write);

	create_with_parents(path, handlers, &fops);
}
EXPORT_SYMBOL(tfw_debugfs_set_handlers);
