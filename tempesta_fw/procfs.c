/**
 *		Tempesta FW
 *
 * Copyright (C) 2016 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include "procfs.h"

DEFINE_PER_CPU_ALIGNED(TfwPerfStat, tfw_perfstat);

static struct proc_dir_entry *tfw_procfs_tempesta;
static struct proc_dir_entry *tfw_procfs_perfstat;

void
tfw_perfstat_collect(TfwPerfStat *stat)
{
	int cpu;

	/*
	 * Collecting values this way is safe on a 64-bit architecture.
	 * Note that CPU hot-plugging are not supported, at least not
	 * consciously. For that reason only online CPUs are examined.
	 */
	for_each_online_cpu(cpu) {
		TfwPerfStat *pcp_stat = per_cpu_ptr(&tfw_perfstat, cpu);

		/* Client related statistics. */
		stat->clnt.rx_messages += pcp_stat->clnt.rx_messages;
		stat->clnt.msgs_forward += pcp_stat->clnt.msgs_forward;
		stat->clnt.msgs_parserr += pcp_stat->clnt.msgs_parserr;
		stat->clnt.msgs_filtout += pcp_stat->clnt.msgs_filtout;
		stat->clnt.msgs_otherr += pcp_stat->clnt.msgs_otherr;

		stat->clnt.conn_attempts += pcp_stat->clnt.conn_attempts;
		stat->clnt.conn_disconnects += pcp_stat->clnt.conn_disconnects;
		stat->clnt.conn_established += pcp_stat->clnt.conn_established;

		stat->clnt.rx_bytes += pcp_stat->clnt.rx_bytes;

		/* Server related statistics. */
		stat->serv.rx_messages += pcp_stat->serv.rx_messages;
		stat->serv.msgs_forward += pcp_stat->serv.msgs_forward;
		stat->serv.msgs_parserr += pcp_stat->serv.msgs_parserr;
		stat->serv.msgs_filtout += pcp_stat->serv.msgs_filtout;
		stat->serv.msgs_otherr += pcp_stat->serv.msgs_otherr;

		stat->serv.conn_attempts += pcp_stat->serv.conn_attempts;
		stat->serv.conn_disconnects += pcp_stat->serv.conn_disconnects;
		stat->serv.conn_established += pcp_stat->serv.conn_established;

		stat->serv.rx_bytes += pcp_stat->serv.rx_bytes;
	}
}

static int
tfw_perfstat_seq_show(struct seq_file *seq, void *off)
{
	int ret;
	TfwPerfStat stat;

	memset(&stat, 0, sizeof(stat));
	tfw_perfstat_collect(&stat);

	/* Client related statistics. */
	ret = seq_printf(seq, "Client messages received\t\t: %llu\n",
			 stat.clnt.rx_messages);
	if (ret)
		goto out;
	ret = seq_printf(seq, "Client messages forwarded\t\t: %llu\n",
			 stat.clnt.msgs_forward);
	if (ret)
		goto out;
	ret = seq_printf(seq, "Client messages parsing errors\t\t: %llu\n",
			 stat.clnt.msgs_parserr);
	if (ret)
		goto out;
	ret = seq_printf(seq, "Client messages filtered out\t\t: %llu\n",
			 stat.clnt.msgs_filtout);
	if (ret)
		goto out;
	ret = seq_printf(seq, "Client messages other errors\t\t: %llu\n",
			 stat.clnt.msgs_otherr);
	if (ret)
		goto out;
	ret = seq_printf(seq, "Client connections total\t\t: %llu\n",
			 stat.clnt.conn_established);
	if (ret)
		goto out;
	ret = seq_printf(seq, "Client connections active\t\t: %llu\n",
			 stat.clnt.conn_attempts - stat.clnt.conn_disconnects);
	if (ret)
		goto out;
	ret = seq_printf(seq, "Client RX bytes\t\t\t\t: %llu\n",
			 stat.clnt.rx_bytes);
	if (ret)
		goto out;

	/* Server related statistics. */
	ret = seq_printf(seq, "Server messages received\t\t: %llu\n",
			 stat.serv.rx_messages);
	if (ret)
		goto out;
	ret = seq_printf(seq, "Server messages forwarded\t\t: %llu\n",
			 stat.serv.msgs_forward);
	if (ret)
		goto out;
	ret = seq_printf(seq, "Server messages parsing errors\t\t: %llu\n",
			 stat.serv.msgs_parserr);
	if (ret)
		goto out;
	ret = seq_printf(seq, "Server messages filtered out\t\t: %llu\n",
			 stat.serv.msgs_filtout);
	if (ret)
		goto out;
	ret = seq_printf(seq, "Server messages other errors\t\t: %llu\n",
			 stat.serv.msgs_otherr);
	if (ret)
		goto out;
	ret = seq_printf(seq, "Server connections total\t\t: %llu\n",
			 stat.serv.conn_established);
	if (ret)
		goto out;
	ret = seq_printf(seq, "Server connections active\t\t: %llu\n",
			 stat.serv.conn_attempts - stat.serv.conn_disconnects);
	if (ret)
		goto out;
	ret = seq_printf(seq, "Server RX bytes\t\t\t\t: %llu\n",
			 stat.serv.rx_bytes);
	if (ret)
		goto out;

out:
	return ret;
}

static int
tfw_perfstat_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, tfw_perfstat_seq_show, PDE_DATA(inode));
}

static struct file_operations tfw_perfstat_fops = {
	.owner		= THIS_MODULE,
	.open		= tfw_perfstat_seq_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

int
tfw_procfs_init(void)
{
	tfw_procfs_tempesta = proc_mkdir("tempesta", NULL);
	if (!tfw_procfs_tempesta)
		goto out;

	tfw_procfs_perfstat = proc_create("perfstat", S_IRUGO,
					  tfw_procfs_tempesta,
					  &tfw_perfstat_fops);
	if (!tfw_procfs_perfstat)
		goto out_tempesta;

	return 0;

out:
	return -ENOMEM;
out_tempesta:
	remove_proc_entry("tempesta", NULL);
	goto out;
}

void
tfw_procfs_exit(void)
{
	remove_proc_entry("perfstat", tfw_procfs_tempesta);
	remove_proc_entry("tempesta", NULL);
}
