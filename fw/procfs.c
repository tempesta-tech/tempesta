/**
 *		Tempesta FW
 *
 * Copyright (C) 2016-2025 Tempesta Technologies, Inc.
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
#include "lib/fault_injection_alloc.h"

/*
 * Common Tempesta statistics.
 */
DEFINE_PER_CPU_ALIGNED(TfwPerfStat, tfw_perfstat);

/**
 * Empty health monitor statistics ('health_stat' directive) with empty
 * response counters (@sum), but populated HTTP codes (@code). This serves as
 * a prototype for creating a new structure in TfwPerfStat when needed.
 *
 * If NULL it means that 'health_stat' directive is disabled.
 */
static TfwHMStats *health_stat_codes;

static void
tfw_perfstat_collect(TfwPerfStat *stat)
{
#define SADD(x)	stat->x += pcp_stat->x

	int cpu, i;

	/*
	 * Collecting values this way is safe on a 64-bit architecture.
	 * Note that CPU hot-plugging are not supported, at least not
	 * consciously. For that reason only online CPUs are examined.
	 */
	for_each_online_cpu(cpu) {
		TfwPerfStat *pcp_stat = per_cpu_ptr(&tfw_perfstat, cpu);

		/* Ss statistics. */
		SADD(ss.wq_full);

		/* Cache statistics. */
		SADD(cache.hits);
		SADD(cache.misses);
		SADD(cache.objects);
		SADD(cache.bytes);

		/* Client related statistics. */
		SADD(clnt.rx_messages);
		SADD(clnt.msgs_forwarded);
		SADD(clnt.msgs_fromcache);
		SADD(clnt.msgs_parserr);
		SADD(clnt.msgs_filtout);
		SADD(clnt.msgs_otherr);
		SADD(clnt.online);
		SADD(clnt.conn_attempts);
		SADD(clnt.conn_disconnects);
		SADD(clnt.conn_established);
		SADD(clnt.rx_bytes);
		SADD(clnt.streams_num_exceeded);
		SADD(clnt.priority_frame_exceeded);
		SADD(clnt.rst_frame_exceeded);
		SADD(clnt.settings_frame_exceeded);
		SADD(clnt.ping_frame_exceeded);
		SADD(clnt.wnd_update_frame_exceeded);

		/* Server related statistics. */
		SADD(serv.rx_messages);
		SADD(serv.msgs_forwarded);
		SADD(serv.msgs_parserr);
		SADD(serv.msgs_filtout);
		SADD(serv.msgs_otherr);
		SADD(serv.conn_attempts);
		SADD(serv.conn_disconnects);
		SADD(serv.conn_established);
		SADD(serv.conn_restricted);
		SADD(serv.rx_bytes);
		SADD(serv.tls_hs_successful);
		SADD(serv.tls_hs_failed);

		/*
		 * Health statistics (differs from health monitor statistics):
		 * total responses for tempesta
		 */
		if (stat->hm && pcp_stat->hm)
			for (i = 0; i < stat->hm->ccnt; ++i) {
				BUG_ON(stat->hm->rsums[i].code !=
				       pcp_stat->hm->rsums[i].code);
				stat->hm->rsums[i].total +=
					pcp_stat->hm->rsums[i].total;
			}
	}
#undef SADD
}

static int
tfw_perfstat_seq_show(struct seq_file *seq, void *off)
{
#define SPRNE(m, e)	seq_printf(seq, m": %llu\n", e)
#define SPRNED(m, e)	seq_printf(seq, m": %ums\n", e)
#define SPRN(m, c)	seq_printf(seq, m": %llu\n", stat.c)

	int i, ret;
	TfwPerfStat stat = {0};
	u64 serv_conn_active, serv_conn_sched;
	SsStat *ss_stat = tfw_kmalloc(sizeof(SsStat) * num_online_cpus(),
				      GFP_KERNEL);
	unsigned int val[T_PSZ] = { 0 };
	TfwPrcntlStats pstats = {.val = val};

	if (!ss_stat)
		T_WARN("Cannot allocate sync sockets statistics\n");

	if (health_stat_codes) {
		size_t alloc_sz = tfw_hm_stats_size(health_stat_codes->ccnt);

		stat.hm = tfw_kmalloc(alloc_sz, GFP_KERNEL);
		if (stat.hm)
			tfw_hm_stats_clone(stat.hm, health_stat_codes);
	}

	tfw_perfstat_collect(&stat);
	ret = tfw_apm_stats_global(&pstats);
	if (ret < 0) {
		seq_printf(seq, "Minimal response time\t\t: n/a\n");
		seq_printf(seq, "Average response time\t\t: n/a\n");
		seq_printf(seq, "Median  response time\t\t: n/a\n");
		seq_printf(seq, "Percentiles\n");
		for (i = TFW_PSTATS_IDX_ITH; i < ARRAY_SIZE(tfw_pstats_ith); ++i) {
			seq_printf(seq, "%02d%%:\t n/a\n", tfw_pstats_ith[i]);
		}
		goto skip_apm;
	}

	SPRNED("Minimal response time\t\t", pstats.val[TFW_PSTATS_IDX_MIN]);
	SPRNED("Average response time\t\t", pstats.val[TFW_PSTATS_IDX_AVG]);
	SPRNED("Median  response time\t\t", pstats.val[TFW_PSTATS_IDX_P50]);
	SPRNED("Maximum response time\t\t", pstats.val[TFW_PSTATS_IDX_MAX]);
	seq_printf(seq, "Percentiles\n");
	for (i = TFW_PSTATS_IDX_ITH; i < ARRAY_SIZE(tfw_pstats_ith); ++i) {
		seq_printf(seq, "%02d%%:\t%dms\n",
			   pstats.ith[i], pstats.val[i]);
	}

skip_apm:

	/* Ss statistics. */
	SPRN("SS work queue full\t\t\t\t", ss.wq_full);
	if (ss_stat) {
		int cpu;
		ss_get_stat(ss_stat);
		seq_printf(seq, "SS work queues sizes\t\t\t\t:");
		for_each_online_cpu(cpu)
			seq_printf(seq, " %u", ss_stat[cpu].rb_wq_sz);
		seq_printf(seq, "\nSS backlog's sizes\t\t\t\t:");
		for_each_online_cpu(cpu)
			seq_printf(seq, " %u", ss_stat[cpu].backlog_sz);
		seq_printf(seq, "\n");
		kfree(ss_stat);
	} else {
		seq_printf(seq, "SS work queues sizes\t\t\t\t: n/a\n");
		seq_printf(seq, "SS backlog's sizes\t\t\t\t: n/a\n");
	}

	/* Cache statistics. */
	SPRN("Cache hits\t\t\t\t\t", cache.hits);
	SPRN("Cache misses\t\t\t\t\t", cache.misses);
	SPRN("Cache objects\t\t\t\t\t", cache.objects);
	SPRN("Cache bytes\t\t\t\t\t", cache.bytes);

	/* Client related statistics. */
	SPRN("Client messages received\t\t\t", clnt.rx_messages);
	SPRN("Client messages forwarded\t\t\t", clnt.msgs_forwarded);
	SPRN("Client messages served from cache\t\t", clnt.msgs_fromcache);
	SPRN("Client messages parsing errors\t\t\t", clnt.msgs_parserr);
	SPRN("Client messages filtered out\t\t\t", clnt.msgs_filtout);
	SPRN("Client messages other errors\t\t\t", clnt.msgs_otherr);
	SPRN("Clients online\t\t\t\t\t", clnt.online);
	SPRN("Client connection attempts\t\t\t", clnt.conn_attempts);
	SPRN("Client established connections\t\t\t", clnt.conn_established);
	SPRNE("Client connections active\t\t\t",
	      stat.clnt.conn_established - stat.clnt.conn_disconnects);
	SPRN("Client RX bytes\t\t\t\t\t", clnt.rx_bytes);
	SPRN("Client max streams number exceeded\t\t", clnt.streams_num_exceeded);
	SPRN("Client priority frames number exceeded\t\t",
	     clnt.priority_frame_exceeded);
	SPRN("Client rst frames number exceeded\t\t",
	     clnt.rst_frame_exceeded);
	SPRN("Client settings frames number exceeded\t\t",
	     clnt.settings_frame_exceeded);
	SPRN("Client ping frames number exceeded\t\t", clnt.ping_frame_exceeded);
	SPRN("Client window update frames number exceeded\t",
	     clnt.wnd_update_frame_exceeded);

	/* Server related statistics. */
	serv_conn_active = stat.serv.conn_established
			   - stat.serv.conn_disconnects;
	serv_conn_sched = serv_conn_active - stat.serv.conn_restricted;

	SPRN("Server messages received\t\t\t", serv.rx_messages);
	SPRN("Server messages forwarded\t\t\t", serv.msgs_forwarded);
	SPRN("Server messages parsing errors\t\t\t", serv.msgs_parserr);
	SPRN("Server messages filtered out\t\t\t", serv.msgs_filtout);
	SPRN("Server messages other errors\t\t\t", serv.msgs_otherr);
	SPRN("Server connection attempts\t\t\t", serv.conn_attempts);
	SPRN("Server established connections\t\t\t", serv.conn_established);
	SPRNE("Server connections active\t\t\t", serv_conn_active);
	SPRNE("Server connections schedulable\t\t\t", serv_conn_sched);
	SPRN("Server RX bytes\t\t\t\t\t", serv.rx_bytes);
	SPRN("Server successful TLS handshakes\t\t", serv.tls_hs_successful);
	SPRN("Server failed TLS handshakes\t\t\t", serv.tls_hs_failed);

	if (stat.hm) {
		seq_printf(seq, "Tempesta health statistics:\n");
		for (i = 0; i < stat.hm->ccnt; ++i) {
			seq_printf(seq, "\tHTTP '%d' code\t: %llu\n",
				   stat.hm->rsums[i].code,
				   stat.hm->rsums[i].total);
		}
	}

	kfree(stat.hm);
	return 0;
#undef SPRN
#undef SPRNE
}

static int
tfw_perfstat_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, tfw_perfstat_seq_show, PDE_DATA(inode));
}

static int
tfw_srvstats_seq_show(struct seq_file *seq, void *off)
{
#define SPRNE(m, e)	seq_printf(seq, m": %ums\n", e)

	size_t i, rc;
	TfwSrvConn *srv_conn;
	TfwServer *srv = seq->private;
	unsigned int *qsize;
	unsigned int val[T_PSZ] = { 0 };
	TfwPrcntlStats pstats = {.val = val};
	TfwHMStats *hm_stats;

	if (!(qsize = tfw_kmalloc(sizeof(int) * srv->conn_n, GFP_KERNEL)))
		return -ENOMEM;

	tfw_apm_stats(srv->apmref, &pstats);

	SPRNE("Minimal response time\t\t", pstats.val[TFW_PSTATS_IDX_MIN]);
	SPRNE("Average response time\t\t", pstats.val[TFW_PSTATS_IDX_AVG]);
	SPRNE("Median  response time\t\t", pstats.val[TFW_PSTATS_IDX_P50]);
	SPRNE("Maximum response time\t\t", pstats.val[TFW_PSTATS_IDX_MAX]);

	seq_printf(seq, "Percentiles\n");
	for (i = TFW_PSTATS_IDX_ITH; i < ARRAY_SIZE(tfw_pstats_ith); ++i)
		seq_printf(seq, "%02d%%:\t%dms\n",
				pstats.ith[i], pstats.val[i]);

	i = rc = 0;
	list_for_each_entry(srv_conn, &srv->conn_list, list) {
		qsize[i++] = READ_ONCE(srv_conn->qsize);
		if (tfw_srv_conn_restricted(srv_conn))
			rc++;
	}

#ifdef DEBUG
	seq_printf(seq, "References\t\t\t: %lld\n",
			atomic64_read(&srv->refcnt));
#endif
	seq_printf(seq, "Total pinned sessions\t\t: %lld\n",
			atomic64_read(&srv->sess_n));
	seq_printf(seq, "Total schedulable connections\t: %zd\n",
			srv->conn_n - rc);

	seq_printf(seq, "HTTP health monitor is enabled\t: %d\n",
		   test_bit(TFW_SRV_B_HMONITOR, &srv->flags));
	seq_printf(seq, "HTTP availability\t\t: %d\n",
			!tfw_srv_suspended(srv));
	if ((hm_stats = tfw_apm_hm_stats(srv->apmref))) {
		seq_printf(seq, "\tTime until next health check\t: %u\n",
			   hm_stats->rtime);
		for (i = 0; i < hm_stats->ccnt; ++i)
			seq_printf(seq, "\tHTTP '%d' code\t: %u (%llu total)"
				   "\n", hm_stats->rsums[i].code,
				   hm_stats->rsums[i].tf_total,
				   hm_stats->rsums[i].total);
		kfree(hm_stats);
	}

	seq_printf(seq, "Maximum forwarding queue size\t: %u\n",
			srv->sg->max_qsize);
	for (i = 0; i < srv->conn_n; ++i)
		seq_printf(seq, "\tConnection %03zd queue size\t: %u\n",
				i, qsize[i]);

	kfree(qsize);

	return 0;
#undef SPRNE
}

static int
tfw_srvstats_seq_reconfig(struct seq_file *seq, void *off)
{
	/* Reference to server may be broken during reconfig. */
	seq_printf(seq,
		   "Per-Server statistics is unavailable during reconfiguration\n");

	return 0;
}

static int
tfw_srvstats_seq_open(struct inode *inode, struct file *file)
{
	if (!tfw_runstate_is_reconfig())
		return single_open(file, tfw_srvstats_seq_show, PDE_DATA(inode));
	return single_open(file, tfw_srvstats_seq_reconfig, PDE_DATA(inode));
}

static int
tfw_state_seq_show(struct seq_file *seq, void *off)
{
	const char *st;
	if (tfw_runstate_is_started()) {
		st = tfw_runstate_is_reconfig()
			? "reconfig\n"
			: (tfw_runstate_is_started_success()
			   ? "started\n" : "started (failed reconfig)");
	} else {
		st = "stopped\n";
	}
	seq_printf(seq, st);
	return  0;
}

static int
tfw_state_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, tfw_state_seq_show, NULL);
}

/*
 * Start/stop routines.
 */
static struct proc_dir_entry *tfw_procfs_tempesta;
static struct proc_dir_entry *tfw_procfs_state;
static struct proc_dir_entry *tfw_procfs_perfstat;
static struct proc_dir_entry *tfw_procfs_srvstats;
static struct proc_dir_entry *tfw_procfs_sgstats;

static struct proc_ops tfw_srvstats_fops = {
	.proc_flags	= PROC_ENTRY_PERMANENT,
	.proc_open	= tfw_srvstats_seq_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static int
tfw_procfs_srv_create(TfwServer *srv)
{
	struct proc_dir_entry *pfs_srv;
	char srv_name[TFW_ADDR_STR_BUF_SIZE] = { 0 };

	tfw_addr_ntop(&srv->addr, srv_name, sizeof(srv_name));
	pfs_srv = proc_create_data(srv_name, S_IRUGO,
				   tfw_procfs_sgstats,
				   &tfw_srvstats_fops, srv);

	return pfs_srv ? 0 : -ENOENT;
}

static int
tfw_procfs_sg_create(TfwSrvGroup *sg)
{
	if (!(tfw_procfs_sgstats = proc_mkdir(sg->name, tfw_procfs_srvstats)))
		return -ENOENT;
	return 0;
}

static int
tfw_procfs_cfgend(void)
{
	return 0;
}

static void
tfw_procfs_cleanup(void)
{
	remove_proc_subtree("servers", tfw_procfs_tempesta);
	tfw_procfs_srvstats = NULL;
}

static int
tfw_procfs_start(void)
{
	if (!tfw_procfs_tempesta)
		return -ENOENT;

	tfw_procfs_cleanup();
	if (!(tfw_procfs_srvstats = proc_mkdir("servers", tfw_procfs_tempesta)))
		return -ENOENT;

	return tfw_sg_for_each_srv(tfw_procfs_sg_create, tfw_procfs_srv_create);
}

static void
tfw_procfs_stop(void)
{
	tfw_procfs_cleanup();
}

static int
tfw_cfgop_health_stat(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int cpu;

	TFW_CFG_CHECK_VAL_N(>, 0, cs, ce);
	TFW_CFG_CHECK_NO_ATTRS(cs, ce);

	health_stat_codes = tfw_kzalloc(tfw_hm_stats_size(ce->val_n),
					GFP_KERNEL);
	if (!health_stat_codes)
		return -ENOMEM;
	if (tfw_hm_stats_init_from_cfg_entry(health_stat_codes, ce)) {
		kfree(health_stat_codes);
		health_stat_codes = NULL;
		return -EINVAL;
	}

	for_each_online_cpu(cpu) {
		TfwPerfStat *pcp_stat = per_cpu_ptr(&tfw_perfstat, cpu);
		pcp_stat->hm = tfw_kmalloc_node(tfw_hm_stats_size(ce->val_n),
						GFP_KERNEL, cpu_to_node(cpu));
		if (!pcp_stat->hm)
			return -ENOMEM;
		tfw_hm_stats_clone(pcp_stat->hm, health_stat_codes);
	}
	return 0;
}

static void
tfw_cfgop_cleanup_health_stat(TfwCfgSpec *cs)
{
	int cpu;

	kfree(health_stat_codes);
	health_stat_codes = NULL;

	for_each_online_cpu(cpu) {
		TfwPerfStat *pcp_stat = per_cpu_ptr(&tfw_perfstat, cpu);
		kfree(pcp_stat->hm);
		pcp_stat->hm = NULL;
	}
}

static TfwCfgSpec tfw_procfs_specs[] = {
	{
		.name       = "health_stat",
		.handler    = tfw_cfgop_health_stat,
		.cleanup    = tfw_cfgop_cleanup_health_stat,
		.allow_none = true,
	},
	{ 0 },
};

TfwMod tfw_procfs_mod = {
	.name	= "procfs",
	.cfgend	= tfw_procfs_cfgend,
	.start	= tfw_procfs_start,
	.stop	= tfw_procfs_stop,
	.specs	= tfw_procfs_specs,
};

/*
 * Init/exit routines.
 */
static struct proc_ops tfw_perfstat_fops = {
	.proc_flags	= PROC_ENTRY_PERMANENT,
	.proc_open	= tfw_perfstat_seq_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static struct proc_ops tfw_state_fops = {
	.proc_flags	= PROC_ENTRY_PERMANENT,
	.proc_open	= tfw_state_seq_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

int
tfw_procfs_init(void)
{
	tfw_procfs_tempesta = proc_mkdir("tempesta", NULL);
	if (!tfw_procfs_tempesta)
		goto out;

	tfw_procfs_state = proc_create("state", S_IRUGO,
					tfw_procfs_tempesta,
					&tfw_state_fops);
	if (!tfw_procfs_state)
		goto out_tempesta;

	tfw_procfs_perfstat = proc_create("perfstat", S_IRUGO,
					  tfw_procfs_tempesta,
					  &tfw_perfstat_fops);
	if (!tfw_procfs_perfstat)
		goto out_state;

	tfw_mod_register(&tfw_procfs_mod);

	return 0;

out_state:
	remove_proc_entry("state", NULL);
out_tempesta:
	remove_proc_entry("tempesta", NULL);
out:
	return -ENOMEM;
}

void
tfw_procfs_exit(void)
{
	tfw_mod_unregister(&tfw_procfs_mod);
	remove_proc_entry("perfstat", tfw_procfs_tempesta);
	remove_proc_entry("state", tfw_procfs_tempesta);
	remove_proc_entry("tempesta", NULL);
}
