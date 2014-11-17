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

#include "cfg_private_log.h"
#include "cfg_mod.h"
#include "cfg_parser.h"


#define CFG_BUF_SIZE 65536
#define CFG_BUF_READ_BLOCK_SIZE 4096

#define STATE_MAX 32
#define STATE_DEFAULT_VAL "stop"

#define CFG_PATH_MAX 255
#define CFG_PATH_DEFAULT_VAL "/etc/tempesta.conf"

static struct {
	char state[STATE_MAX + 1];
	char cfg_path[CFG_PATH_MAX + 1]; /* TODO: implement this */
	char cfg_text[CFG_BUF_SIZE + 1];
} tfw_cfg_sysctl_bufs = {
	.state = STATE_DEFAULT_VAL,
	.cfg_path = CFG_PATH_DEFAULT_VAL,
};

static TfwCfgNode *parsed_cfg;


#if 0  /* TODO: implement this */
static const char *
read_cfg_file(void)
{
	const char *path = tfw_cfg_sysctl_bufs.cfg_path;
	char *buf;
	struct file *fp;
	int bytes_read, read_size, remaining_space;
	loff_t offset;

	fp = filp_open(path, O_RDONLY, 0);

	if (IS_ERR_OR_NULL(fp)) {
		ERR("can't open file: %s (err: %ld)\n", path, PTR_ERR(fp));
		return NULL;
	}

	buf = kmalloc(CFG_BUF_SIZE, GFP_KERNEL);
	if (!buf) {
		ERR("can't allocate memory\n");
		goto out_err;
	}

	do {
		remaining_space = CFG_BUF_SIZE - offset - 1;
		read_size = min(remaining_space, CFG_BUF_READ_BLOCK_SIZE);

		bytes_read = kernel_read(fp, offset, buf + offset, read_size);
		offset += bytes_read;

		if (bytes_read < 0) {
			ERR("can't read file: %s (err: %d)\n", path, bytes_read);
			goto out_err;
		}
	} while (bytes_read);

	buf[offset] = '\0';
	filp_close(fp, NULL);

	return buf;

out_err:
	kfree(buf);
	filp_close(fp, NULL);
	return NULL;
}
#endif

static int
start_modules_with_new_cfg(void)
{
	int ret;
	const char *cfg_text;

	DBG("parsing new configuration and starting all modules\n")

	cfg_text = tfw_cfg_sysctl_bufs.cfg_text;
	if (!*cfg_text) {
		ERR("no configuration found\n");
		return -EINVAL;
	}

	BUG_ON(parsed_cfg);
	parsed_cfg = tfw_cfg_parse(cfg_text);
	if (!parsed_cfg) {
		ERR("parse error\n");
		return -EINVAL;
	}

	ret = tfw_cfg_mod_publish_new_cfg(parsed_cfg);
	if (ret) {
		ERR("can't apply new configuration\n");
		goto out_cleanup;
	}

	ret = tfw_cfg_mod_start_all();;
	if (ret) {
		ERR("can't start modules\n");
		goto out_cleanup;
	}

	return 0;

out_cleanup:
	tfw_cfg_node_free(parsed_cfg);
	return ret;
}

static int
handle_state_change(const char *old_state, const char *new_state)
{
	bool is_changed = strcasecmp(old_state, new_state);
	bool is_start = !strcasecmp(new_state, "start");
	bool is_stop = !strcasecmp(new_state, "stop");

	LOG("got state via sysctl: %s\n", new_state);

	if (!is_changed) {
		LOG("the state (%s) isn't changed, nothing to do\n", new_state);
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
	{
		.procname	= "cfg",
		.data 		= tfw_cfg_sysctl_bufs.cfg_text,
		.maxlen		= sizeof(tfw_cfg_sysctl_bufs.cfg_text - 1),
		.mode		= 0644,
		.proc_handler	= proc_dostring,
	},
	{}
};

static struct ctl_table_header *tfw_cfg_sysctl_hdr;


int
tfw_cfg_if_init(void)
{
	tfw_cfg_sysctl_hdr = register_net_sysctl(&init_net, "net/tempesta2",
						 tfw_cfg_sysctl_tbl);
	if (!tfw_cfg_sysctl_hdr) {
		ERR("can't register sysctl table\n");
		return -1;
	}

	return start_modules_with_new_cfg();
}

void
tfw_cfg_if_exit(void)
{
	handle_state_change(tfw_cfg_sysctl_bufs.state, "stop");
	unregister_net_sysctl_table(tfw_cfg_sysctl_hdr);
}


