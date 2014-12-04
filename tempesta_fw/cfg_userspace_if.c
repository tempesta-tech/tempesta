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

#include <linux/kernel.h>
#include <net/net_namespace.h>

#include "cfg_mod.h"
#include "cfg_parser.h"
#include "cfg_private.h"


#define STATE_MAX 32
#define STATE_DEFAULT_VAL "stop"
#define CFG_PATH_MAX 255
#define CFG_PATH_DEFAULT_VAL "/etc/tempesta.conf"

static struct {
	char state[STATE_MAX + 1];
	char cfg_path[CFG_PATH_MAX + 1];
} tfw_cfg_sysctl_bufs = {
	.state = STATE_DEFAULT_VAL,
	.cfg_path = CFG_PATH_DEFAULT_VAL,
};

/*
 * The buffer where the whole configuration is stored.
 * Currently it is allocated as one big continious chunk of memory which is bad.
 * TODO: Fix the parser to be able to stream data into it by small chunks.
 */
static char cfg_text_buf[65535];
#define CFG_BUF_READ_BLOCK_SIZE PAGE_SIZE

/**
 * Read contents of the whole configuration file to cfg_text_buf.
 * The file path is specified via sysctl (tempesta.cfg_path).
 *
 * If there is no file the function returns 0 and leaves the buffer empty.
 * This is not an error, it means that only default values should be used
 * without any external configuration.
 */
static int
read_cfg_file(void)
{
	const char *path = tfw_cfg_sysctl_bufs.cfg_path;
	struct file *fp;
	mm_segment_t oldfs;
	loff_t offset = 0;
	size_t bytes_read, read_size, remaining_space;
	int ret = 0;

	DBG("reading configuration file: %s\n", path);

	oldfs = get_fs();
	set_fs(get_ds());

	fp = filp_open(path, O_RDONLY, 0);
	if (IS_ERR_OR_NULL(fp)) {
		ERR("can't open file: %s (err: %ld)\n", path, PTR_ERR(fp));
		goto out;
	}

	do {
		remaining_space = sizeof(cfg_text_buf) - offset - 1;
		read_size = min(remaining_space, CFG_BUF_READ_BLOCK_SIZE);

		bytes_read = vfs_read(fp, cfg_text_buf + offset, read_size, \
				      &offset);

		if (bytes_read < 0) {
			ret = bytes_read;
			ERR("can't read file: %s (err: %d)\n", path, ret);
			goto out;
		}
	} while (bytes_read);

out:
	cfg_text_buf[offset] = '\0';
	DBG("configuration file contents:\n%s\n", cfg_text_buf);

	if (!IS_ERR_OR_NULL(fp))
		filp_close(fp, NULL);
	set_fs(oldfs);

	return ret;
}

/**
 * Read the configuration file via VFS, parse it and start all modules pushing
 * the new configuration to them.
 */
static int
start_modules_with_new_cfg(void)
{
	TfwCfgNode *parsed_cfg;
	int ret = 0;

	DBG("parsing new configuration and starting all modules\n");

	ret = read_cfg_file();
	if (ret)
		return ret;

	parsed_cfg = tfw_cfg_parse(cfg_text_buf);
	if (!parsed_cfg) {
		ERR("can't parse configuration data\n");
		return -EINVAL;
	}

	ret = tfw_cfg_mod_start_all(parsed_cfg);
	if (ret)
		ERR("can't start modules, err: %d\n", ret);

	return ret;
}

/**
 * Process "start" and "stop" commands (received from sysctl as strings).
 * Do corresponding actions if the state changed from "start" to "stop"
 * and vise versa.
 */
static int
handle_state_change(const char *old_state, const char *new_state)
{
	bool is_changed = strcasecmp(old_state, new_state);
	bool is_start = !strcasecmp(new_state, "start");
	bool is_stop = !strcasecmp(new_state, "stop");

	LOG("got state via sysctl: %s\n", new_state);

	if (!is_changed) {
		LOG("the state '%s' isn't changed, nothing to do\n", new_state);
		return 0;
	}

	if (is_start) {
		int ret;

		LOG("starting...");
		ret = start_modules_with_new_cfg();
		if (ret)
			ERR("failed to start\n");

		return ret;
	}

	if (is_stop) {
		LOG("stopping...");
		tfw_cfg_mod_stop_all();
		return 0;
	}

	/* Neither "start" or "stop"? */
	return -EINVAL;
}

/**
 * Syctl handler for tempesta.state.
 */
static int
handle_sysctl_state_io(ctl_table *ctl, int is_write, void __user *user_buf,
		       size_t *lenp, loff_t *ppos)
{
	int r = 0;

	if (is_write) {
		char new_state_buf[ctl->maxlen];
		char *new_state, *old_state;
		size_t copied_data_len;

		copied_data_len = min((size_t)ctl->maxlen, *lenp);
		r = copy_from_user(new_state_buf, user_buf, copied_data_len);
		if (r)
			return r;

		new_state_buf[copied_data_len] = '\0';
		new_state = strim(new_state_buf);
		old_state = ctl->data;

		r = handle_state_change(old_state, new_state);
		if (r)
			return r;
	}

	r = proc_dostring(ctl, is_write, user_buf, lenp, ppos);

	return r;
}

static ctl_table tfw_cfg_sysctl_tbl[] = {
	{
		.procname	= "cfg_path",
		.data		= tfw_cfg_sysctl_bufs.cfg_path,
		.maxlen		= sizeof(tfw_cfg_sysctl_bufs.cfg_path) - 1,
		.mode		= 0644,
		.proc_handler	= proc_dostring,
	},
	{
		.procname	= "state",
		.data		= tfw_cfg_sysctl_bufs.state,
		.maxlen		= sizeof(tfw_cfg_sysctl_bufs.state) - 1,
		.mode		= 0644,
		.proc_handler	= handle_sysctl_state_io,
	},
	{}
};

static struct ctl_table_header *tfw_cfg_sysctl_hdr;

int
tfw_cfg_if_init(void)
{
	tfw_cfg_sysctl_hdr = register_net_sysctl(&init_net, "net/tempesta",
						 tfw_cfg_sysctl_tbl);
	if (!tfw_cfg_sysctl_hdr) {
		ERR("can't register sysctl table\n");
		return -1;
	}

	return 0;
}

void
tfw_cfg_if_exit(void)
{
	handle_state_change(tfw_cfg_sysctl_bufs.state, "stop");
	unregister_net_sysctl_table(tfw_cfg_sysctl_hdr);
}
