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

#include "apm.h"
#include "server.h"
#include "procfs.h"

/*
 * Common Tempesta statistics.
 */
DEFINE_PER_CPU_ALIGNED(TfwPerfStat, tfw_perfstat);

void
tfw_perfstat_collect(TfwPerfStat *stat)
{
#define SADD(x)	stat->x += pcp_stat->x

	int cpu;

	/*
	 * Collecting values this way is safe on a 64-bit architecture.
	 * Note that CPU hot-plugging are not supported, at least not
	 * consciously. For that reason only online CPUs are examined.
	 */
	for_each_online_cpu(cpu) {
		TfwPerfStat *pcp_stat = per_cpu_ptr(&tfw_perfstat, cpu);

		/* Ss statistics. */
		SADD(ss.pfl_hits);
		SADD(ss.pfl_misses);

		/* Cache statistics. */
		SADD(cache.hits);
		SADD(cache.misses);

		/* Client related statistics. */
		SADD(clnt.rx_messages);
		SADD(clnt.msgs_forwarded);
		SADD(clnt.msgs_fromcache);
		SADD(clnt.msgs_parserr);
		SADD(clnt.msgs_filtout);
		SADD(clnt.msgs_otherr);
		SADD(clnt.conn_attempts);
		SADD(clnt.conn_disconnects);
		SADD(clnt.conn_established);
		SADD(clnt.rx_bytes);

		/* Server related statistics. */
		SADD(serv.rx_messages);
		SADD(serv.msgs_forwarded);
		SADD(serv.msgs_parserr);
		SADD(serv.msgs_filtout);
		SADD(serv.msgs_otherr);
		SADD(serv.conn_attempts);
		SADD(serv.conn_disconnects);
		SADD(serv.conn_established);
		SADD(serv.rx_bytes);
	}
#undef SADD
}

static int
tfw_perfstat_seq_show(struct seq_file *seq, void *off)
{
#define SPRNE(m, e)	seq_printf(seq, m": %llu\n", e)
#define SPRN(m, c)	seq_printf(seq, m": %llu\n", stat.c)

	TfwPerfStat stat;

	memset(&stat, 0, sizeof(stat));
	tfw_perfstat_collect(&stat);

	/* Ss statistics. */
	SPRN("SS pfl hits\t\t\t\t", ss.pfl_hits);
	SPRN("SS pfl misses\t\t\t\t", ss.pfl_misses);

	/* Cache statistics. */
	SPRN("Cache hits\t\t\t\t", cache.hits);
	SPRN("Cache misses\t\t\t\t", cache.misses);

	/* Client related statistics. */
	SPRN("Client messages received\t\t", clnt.rx_messages);
	SPRN("Client messages forwarded\t\t", clnt.msgs_forwarded);
	SPRN("Client messages served from cache\t", clnt.msgs_fromcache);
	SPRN("Client messages parsing errors\t\t", clnt.msgs_parserr);
	SPRN("Client messages filtered out\t\t", clnt.msgs_filtout);
	SPRN("Client messages other errors\t\t", clnt.msgs_otherr);
	SPRN("Client connection attempts\t\t", clnt.conn_attempts);
	SPRN("Client established connections\t\t", clnt.conn_established);
	SPRNE("Client connections active\t\t",
	      stat.clnt.conn_established - stat.clnt.conn_disconnects);
	SPRN("Client RX bytes\t\t\t\t", clnt.rx_bytes);

	/* Server related statistics. */
	SPRN("Server messages received\t\t", serv.rx_messages);
	SPRN("Server messages forwarded\t\t", serv.msgs_forwarded);
	SPRN("Server messages parsing errors\t\t", serv.msgs_parserr);
	SPRN("Server messages filtered out\t\t", serv.msgs_filtout);
	SPRN("Server messages other errors\t\t", serv.msgs_otherr);
	SPRN("Server connection attempts\t\t", serv.conn_attempts);
	SPRN("Server established connections\t\t", serv.conn_established);
	SPRNE("Server connections active\t\t",
	      stat.serv.conn_established - stat.serv.conn_disconnects);
	SPRN("Server RX bytes\t\t\t\t", serv.rx_bytes);

	return 0;
#undef SPRN
#undef SPRNE
}

static int
tfw_perfstat_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, tfw_perfstat_seq_show, PDE_DATA(inode));
}

/*
 * Individual server statistics. Note that 50% percentile
 * is used to tell the median value.
 */
static const TfwPrcntl __read_mostly tfw_procfs_prcntl[] = {
	{50}, {75}, {90}, {95}, {99}
};

static int
tfw_srvstats_seq_show(struct seq_file *seq, void *off)
{
#define SPRNE(m, e)	seq_printf(seq, m": %dms\n", e)

	int i;
	TfwServer *srv = seq->private;
	TfwPrcntl prcntl[ARRAY_SIZE(tfw_procfs_prcntl)];
	TfwPrcntlStats pstats = { prcntl, ARRAY_SIZE(prcntl) };

	memcpy(prcntl, tfw_procfs_prcntl, sizeof(prcntl));

	tfw_apm_stats(srv->apm, &pstats);

	SPRNE("Minimal response time\t\t", pstats.min);
	SPRNE("Average response time\t\t", pstats.avg);
	SPRNE("Median  response time\t\t", prcntl[0].val);
	SPRNE("Maximum response time\t\t", pstats.max);
	seq_printf(seq, "Percentiles\n");
	for (i = 0; i < ARRAY_SIZE(prcntl); ++i)
		seq_printf(seq, "%02d%%:\t%dms\n", prcntl[i].ith,
			   prcntl[i].val);

	return 0;
#undef SPRNE
}

static int
tfw_srvstats_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, tfw_srvstats_seq_show, PDE_DATA(inode));
}

/*
 * Start/stop routines.
 */
static struct proc_dir_entry *tfw_procfs_tempesta;
static struct proc_dir_entry *tfw_procfs_perfstat;
static struct proc_dir_entry *tfw_procfs_srvstats;

static struct file_operations tfw_srvstats_fops = {
	.owner		= THIS_MODULE,
	.open		= tfw_srvstats_seq_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

#define TFW_PROCFS_SRV_CNT_MAX		256
static TfwServer *srvlst[TFW_PROCFS_SRV_CNT_MAX];
static int slsz = 0;

static int
tfw_procfs_srv_collect(TfwServer *srv)
{
	int i;

	if (slsz == TFW_PROCFS_SRV_CNT_MAX)
		return 0;
	for (i = 0; i < slsz; ++i)
		if (tfw_addr_ifmatch(&srvlst[i]->addr, &srv->addr))
			return 0;
	srvlst[slsz++] = srv;
	return 0;
}

static int
tfw_procfs_srv_create(TfwServer *srv)
{
	struct proc_dir_entry *pfs_srv;
	char srv_name[TFW_ADDR_STR_BUF_SIZE] = { 0 };

	tfw_addr_ntop(&srv->addr, srv_name, sizeof(srv_name));
	pfs_srv = proc_create_data(srv_name, S_IRUGO,
				   tfw_procfs_srvstats,
				   &tfw_srvstats_fops, srv);
	if (!pfs_srv)
		return -ENOENT;
	return 0;
}

static int
tfw_procfs_cfg_start(void)
{
	int i, ret;
	TfwPrcntl prcntl[ARRAY_SIZE(tfw_procfs_prcntl)];

	memcpy(prcntl, tfw_procfs_prcntl, sizeof(prcntl));

	if (!tfw_procfs_tempesta)
		return -ENOENT;
	if (tfw_apm_prcntl_verify(prcntl, ARRAY_SIZE(prcntl)))
		return -EINVAL;
	tfw_procfs_srvstats = proc_mkdir("servers", tfw_procfs_tempesta);
	if (!tfw_procfs_srvstats)
		return -ENOENT;
	if ((ret = tfw_sg_for_each_srv(tfw_procfs_srv_collect)) != 0)
		return ret;
	for (i = 0; i < slsz; ++i)
		if ((ret = tfw_procfs_srv_create(srvlst[i])))
			return ret;
	return 0;
}

static void
tfw_procfs_cfg_stop(void)
{
	remove_proc_subtree("servers", tfw_procfs_tempesta);
}

static TfwCfgSpec tfw_procfs_cfg_specs[] = {
	{},
};

TfwCfgMod tfw_procfs_cfg_mod = {
        .name  = "procfs",
        .start = tfw_procfs_cfg_start,
        .stop  = tfw_procfs_cfg_stop,
	.specs = tfw_procfs_cfg_specs,
};

/*
 * Init/exit routines.
 */
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
