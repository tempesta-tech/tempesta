/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2025 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#include <linux/types.h> /* must be the first */
#include <asm/fpu/api.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <net/net_namespace.h> /* for sysctl */
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/mm.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/rcupdate.h>
#include <linux/atomic.h>
#include <linux/printk.h>
#include <linux/cred.h>
#include <linux/cpumask.h>
#include <linux/maple_tree.h>
#include <linux/stacktrace.h>

#include "tempesta_fw.h"
#include "cfg.h"
#include "client.h"
#include "log.h"
#include "server.h"
#include "str.h"
#include "sync_socket.h"
#include "lib/fsm.h"

MODULE_AUTHOR(TFW_AUTHOR);
MODULE_DESCRIPTION(TFW_NAME);
MODULE_VERSION(TFW_VERSION);
MODULE_LICENSE("GPL");

#define T_SYSCTL_STBUF_LEN		32UL
#define NMAX 100

typedef void (*exit_fn)(void);

struct eee {
	char name[NMAX];
	exit_fn fn;	
};

struct eee exit_hooks[32];
size_t  exit_hooks_n;

typedef enum {
	TFW_STATE_STOPPED = 0,
	TFW_STATE_STARTED,
	TFW_STATE_STARTED_FAIL_RECONFIG,
} TfwState;

DEFINE_MUTEX(tfw_sysctl_mtx);
static TfwState tfw_state = TFW_STATE_STOPPED;
static bool tfw_reconfig = false;
static int tfw_ss_users = 0;
static atomic_t found = ATOMIC_INIT(0);

/*
 * The global list of all registered modules
 * (consists of TfwMod{} objects).
 */
static LIST_HEAD(tfw_mods);
static DEFINE_RWLOCK(tfw_mods_lock);

static DEFINE_PER_CPU(int, main_start_1);
static DEFINE_PER_CPU(int, main_start_2);
static DEFINE_PER_CPU(int, main_start_3);
static DEFINE_PER_CPU(int, main_start_4);
static DEFINE_PER_CPU(int, main_stop_1);
static DEFINE_PER_CPU(int, main_stop_2);
static DEFINE_PER_CPU(int, main_clean_1);
static DEFINE_PER_CPU(int, main_clean_2);

#define MM_DEBUG_MAX_VMAS	32
#define MM_DEBUG_HEXDUMP_SIZE	128

static const char *mm_counter_name(int idx)
{
	switch (idx) {
	case MM_FILEPAGES:
		return "MM_FILEPAGES";
	case MM_ANONPAGES:
		return "MM_ANONPAGES";
	case MM_SWAPENTS:
		return "MM_SWAPENTS";
	case MM_SHMEMPAGES:
		return "MM_SHMEMPAGES";
#ifdef MM_HUGETLB
	case MM_HUGETLB:
		return "MM_HUGETLB";
#endif
	default:
		return "UNKNOWN";
	}
}

static void debug_dump_mm_owner(struct mm_struct *mm)
{
	struct task_struct *owner;

	/*
	 * mm->owner существует при CONFIG_MEMCG.
	 * Доступ к нему должен быть защищён RCU.
	 */
#ifdef CONFIG_MEMCG
	rcu_read_lock();

	owner = rcu_dereference(mm->owner);
	if (owner) {
		pr_err("  owner=%px comm=%s pid=%d tgid=%d "
		       "state=0x%x flags=0x%x\n",
		       owner,
		       owner->comm,
		       task_pid_nr(owner),
		       task_tgid_nr(owner),
		       READ_ONCE(owner->__state),
		       READ_ONCE(owner->flags));

		pr_err("  owner.task.mm=%px owner.task.active_mm=%px\n",
		       READ_ONCE(owner->mm),
		       READ_ONCE(owner->active_mm));
	} else {
		pr_err("  owner=NULL\n");
	}

	rcu_read_unlock();
#else
	pr_err("  owner unavailable: CONFIG_MEMCG is disabled\n");
#endif
}

static void debug_dump_mm_exe_file(struct mm_struct *mm)
{
	struct file *exe_file;
	char buf[256];
	char *path;

	rcu_read_lock();

	exe_file = get_file_rcu(&mm->exe_file);
	if (!exe_file) {
		rcu_read_unlock();
		pr_err("  exe_file=NULL\n");
		return;
	}

	rcu_read_unlock();

	path = d_path(&exe_file->f_path, buf, sizeof(buf));
	if (IS_ERR(path))
		pr_err("  exe_file=%px path=<error:%ld>\n",
		       exe_file, PTR_ERR(path));
	else
		pr_err("  exe_file=%px path=%s inode=%lu\n",
		       exe_file,
		       path,
		       file_inode(exe_file)->i_ino);

	fput(exe_file);
}

static void
debug_dump_percpu_counter(struct percpu_counter *fbc)
{
	s64 online_sum;
	s64 possible_sum;
	int cpu;

	online_sum = READ_ONCE(fbc->count);
	possible_sum = READ_ONCE(fbc->count);

	pr_err("    base=%lld counters=%px "
	       "possible_cpus=%u online_cpus=%u\n",
	       (long long)READ_ONCE(fbc->count),
	       fbc->counters,
	       num_possible_cpus(),
	       num_online_cpus());

	for_each_possible_cpu(cpu) {
		s32 *ptr;
		s32 value;

		ptr = per_cpu_ptr(fbc->counters, cpu);
		value = READ_ONCE(*ptr);

		possible_sum += (s64)value;

		if (cpu_online(cpu))
			online_sum += (s64)value;

		pr_err("      cpu=%d online=%d ptr=%px "
		       "value=%d hex=%#010x\n",
		       cpu,
		       cpu_online(cpu),
		       ptr,
		       value,
		       (u32)value);
	}

	pr_err("    online_sum=%lld possible_sum=%lld "
	       "helper_sum=%lld\n",
	       (long long)online_sum,
	       (long long)possible_sum,
	       (long long)percpu_counter_sum(fbc));
}

static void
debug_dump_mm_rss(struct mm_struct *mm)
{
	int i;

	
	pr_err("  rss_stat=%px NR_MM_COUNTERS=%d\n",
	       mm->rss_stat, NR_MM_COUNTERS);

	for (i = 0; i < NR_MM_COUNTERS; i++) {
		s64 approx;
		s64 exact;
		unsigned long counter;

		approx = percpu_counter_read(&mm->rss_stat[i]);
		exact = percpu_counter_sum(&mm->rss_stat[i]);
		counter = get_mm_counter(mm, i);

		pr_err("  rss[%d] %-16s counter=%px "
		       "global=%lld exact=%lld counter %lu\n",
		       i,
		       mm_counter_name(i),
		       &mm->rss_stat[i],
		       approx,
		       exact,
		       counter);

		debug_dump_percpu_counter(&mm->rss_stat[i]);
	}

	pr_err("  rss total_vm=%lu pages=%llu bytes\n",
	       READ_ONCE(mm->total_vm),
	       (unsigned long long)READ_ONCE(mm->total_vm) << PAGE_SHIFT);

	pr_err("  rss hiwater_rss=%lu pages=%llu bytes\n",
	       READ_ONCE(mm->hiwater_rss),
	       (unsigned long long)READ_ONCE(mm->hiwater_rss) << PAGE_SHIFT);

	pr_err("  rss hiwater_vm=%lu pages=%llu bytes\n",
	       READ_ONCE(mm->hiwater_vm),
	       (unsigned long long)READ_ONCE(mm->hiwater_vm) << PAGE_SHIFT);
}

static void debug_dump_mm_vmas_locked(struct mm_struct *mm)
{
	struct vm_area_struct *vma;
	VMA_ITERATOR(vmi, mm, 0);
	unsigned int nr = 0;
	unsigned long total_pages = 0;

	pr_err("  VMA list, maximum %u entries:\n", MM_DEBUG_MAX_VMAS);

	for_each_vma(vmi, vma) {
		unsigned long pages;
		struct file *file;

		pages = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
		total_pages += pages;
		file = vma->vm_file;

		pr_err("    vma[%u]=%px [%016lx-%016lx] "
		       "pages=%lu flags=%#lx pgoff=%#lx "
		       "file=%px anon_vma=%px vm_ops=%px\n",
		       nr,
		       vma,
		       vma->vm_start,
		       vma->vm_end,
		       pages,
		       vma->vm_flags,
		       vma->vm_pgoff,
		       file,
		       vma->anon_vma,
		       vma->vm_ops);

		if (file) {
			char buf[192];
			char *path;

			path = d_path(&file->f_path, buf, sizeof(buf));
			if (!IS_ERR(path))
				pr_err("      file=%s inode=%lu mapping=%px\n",
				       path,
				       file_inode(file)->i_ino,
				       file->f_mapping);
			else
				pr_err("      file path error=%ld inode=%lu "
				       "mapping=%px\n",
				       PTR_ERR(path),
				       file_inode(file)->i_ino,
				       file->f_mapping);
		}

		nr++;
		if (nr >= MM_DEBUG_MAX_VMAS) {
			pr_err("    VMA output truncated after %u entries\n",
			       nr);
			break;
		}
	}

	pr_err("  iterated_vmas=%u iterated_pages=%lu\n",
	       nr, total_pages);
}

/*
 * Вызывать только для mm, на который уже удерживается корректная ссылка:
 *
 *     mm = get_task_mm(task);
 *     if (mm) {
 *             debug_dump_mm(mm, "before module unload");
 *             mmput(mm);
 *     }
 *
 * Если mm получен не через get_task_mm(), вызывающая сторона обязана
 * гарантировать, что struct mm_struct не будет освобождён во время dump.
 */
static void
debug_dump_mm(struct mm_struct *mm, const char *reason)
{
	bool mmap_locked;

	if (!mm) {
		pr_err("MM DEBUG: mm=NULL reason=%s current=%s[%d]\n",
		       reason ?: "<none>",
		       current->comm,
		       current->pid);
		return;
	}

	pr_err("============================================================\n");
	pr_err("MM DEBUG BEGIN: reason=%s\n", reason ?: "<none>");

	pr_err("  current=%px comm=%s pid=%d tgid=%d cpu=%d\n",
	       current,
	       current->comm,
	       current->pid,
	       current->tgid,
	       raw_smp_processor_id());

	pr_err("  mm=%px mm_users=%d mm_count=%d\n",
	       mm,
	       atomic_read(&mm->mm_users),
	       atomic_read(&mm->mm_count));

	pr_err("  sizeof(mm_struct)=%zu rss_stat offset=%zu addr=%px\n",
	       sizeof(*mm),
	       offsetof(struct mm_struct, rss_stat),
	       &mm->rss_stat);

	pr_err("  pgd=%px task_size=%#lx flags=%#lx\n",
	       READ_ONCE(mm->pgd),
	       READ_ONCE(mm->task_size),
	       READ_ONCE(mm->flags));

	pr_err("  map_count=%d locked_vm=%lu pinned_vm=%llu "
	       "data_vm=%lu exec_vm=%lu stack_vm=%lu\n",
	       READ_ONCE(mm->map_count),
	       READ_ONCE(mm->locked_vm),
	       (unsigned long long)atomic64_read(&mm->pinned_vm),
	       READ_ONCE(mm->data_vm),
	       READ_ONCE(mm->exec_vm),
	       READ_ONCE(mm->stack_vm));

	pr_err("  start_code=%#lx end_code=%#lx "
	       "start_data=%#lx end_data=%#lx\n",
	       READ_ONCE(mm->start_code),
	       READ_ONCE(mm->end_code),
	       READ_ONCE(mm->start_data),
	       READ_ONCE(mm->end_data));

	pr_err("  start_brk=%#lx brk=%#lx start_stack=%#lx\n",
	       READ_ONCE(mm->start_brk),
	       READ_ONCE(mm->brk),
	       READ_ONCE(mm->start_stack));

	pr_err("  arg_start=%#lx arg_end=%#lx "
	       "env_start=%#lx env_end=%#lx\n",
	       READ_ONCE(mm->arg_start),
	       READ_ONCE(mm->arg_end),
	       READ_ONCE(mm->env_start),
	       READ_ONCE(mm->env_end));

	pr_err("  mmap_base=%#lx mmap_legacy_base=%#lx\n",
	       READ_ONCE(mm->mmap_base),
	       READ_ONCE(mm->mmap_legacy_base));

	pr_err("  page_table_lock=%px mmap_lock=%px "
	       "mm_mt=%px\n",
	       &mm->page_table_lock,
	       &mm->mmap_lock,
	       &mm->mm_mt);

#ifdef CONFIG_MMU
	pr_err("  pgtables_bytes=%lu\n",
	       atomic_long_read(&mm->pgtables_bytes));
#endif

#ifdef CONFIG_MMU_NOTIFIER
	pr_err("  notifier_subscriptions=%px\n",
	       READ_ONCE(mm->notifier_subscriptions));
#endif

#ifdef CONFIG_NUMA_BALANCING
	pr_err("  numa_next_scan=%lu numa_scan_offset=%lu "
	       "numa_scan_seq=%d\n",
	       READ_ONCE(mm->numa_next_scan),
	       READ_ONCE(mm->numa_scan_offset),
	       READ_ONCE(mm->numa_scan_seq));
#endif

	pr_err("  cpumask=%*pbl\n",
	       cpumask_pr_args(mm_cpumask(mm)));

	debug_dump_mm_owner(mm);
	debug_dump_mm_exe_file(mm);
	debug_dump_mm_rss(mm);

	

	pr_err("CANARY %u %u", mm->canary1, mm->canary2);
;

	/*
	 * Не блокируемся бесконечно: при повреждённом mm mmap_lock тоже
	 * может быть испорчен или уже удерживаться текущим путём.
	 */
	mmap_locked = mmap_read_trylock(mm);
	if (mmap_locked) {
		debug_dump_mm_vmas_locked(mm);
		mmap_read_unlock(mm);
	} else {
		pr_err("  mmap_read_trylock() failed; VMA dump skipped\n");
	}

	pr_err("  current stack:\n");
	dump_stack();

	pr_err("MM DEBUG END: mm=%px reason=%s\n",
	       mm, reason ?: "<none>");
	pr_err("============================================================\n");
}

static inline bool
tfw_check_mm(struct mm_struct *mm, int *fail)
{
	bool rc = true;
	int i;

	for (i = 0; i < NR_MM_COUNTERS; i++) {
		if (!tfw_mm_check_rss_member(mm, i)) {
			rc = false;
			mm->error_was_found = true;
			*fail = i;
			break;
		}
	}

	return rc;
}

static inline void
tfw_check_all_mm(const char *prefix)
{
	struct mm_struct *mmA = NULL;
	struct task_struct *task;
	bool rc = true;
	int fail;

	if (atomic_read(&found))
		return;

	rcu_read_lock();

	for_each_process(task) {
		struct mm_struct *mm;

		mm = get_task_mm(task);
		if (!mm)
			continue; /* kernel thread */


		fail = -1;
		rc = tfw_check_mm(mm, &fail);
		if (!rc) {
			printk(KERN_ALERT "%s: FAILED TO CHECK MEM %s",
				prefix, task->comm);
			mmA = mm;
			BUG_ON(fail == -1);
			break;
		}
		/*
		 * Обычный mmput() здесь нельзя вызывать: мы под RCU.
		 * mmput_async() откладывает потенциально блокирующее
		 * освобождение mm в workqueue.
		 */
		mmput_async(mm);
	}

	rcu_read_unlock();

	if (!mmA)
		return;

	debug_dump_mm(mmA, "QQQ");
	if (!atomic_cmpxchg(&found, 0, 1)) {
		int ret = install_rss_watchpoint(mmA, fail);
		if (ret)
			atomic_set(&found, 0);

		pr_emerg("RSS pointers: original=%px current=%px\n",
        		mmA->rss_counters_original,
       			mmA->rss_stat[0].counters);

		debug_dump_pcpu_history(mmA->rss_stat[0].counters);
		if (mmA->rss_counters_original != mmA->rss_stat[0].counters)
        		debug_dump_pcpu_history(mmA->rss_counters_original);
	}

	mmput(mmA);
}

void
tfw_on_stall_impl(void)
{
	int *start_1 = this_cpu_ptr(&main_start_1);
	int *start_2 = this_cpu_ptr(&main_start_2);
	int *start_3 = this_cpu_ptr(&main_start_3);
	int *start_4 = this_cpu_ptr(&main_start_4);
	int *stop_1 = this_cpu_ptr(&main_stop_1);
	int *stop_2 = this_cpu_ptr(&main_stop_2);
	int *clean_1 = this_cpu_ptr(&main_clean_1);
	int *clean_2 = this_cpu_ptr(&main_clean_2);

	printk(KERN_ALERT "start %d %d %d %d stop %d %d clean %d %d\n",
		*start_1, *start_2, *start_3, *start_4, *stop_1,
		*stop_2, *clean_1, *clean_2);
}


/**
 * Return true if Tempesta is reconfiguring, and false otherwise.
 */
bool
tfw_runstate_is_reconfig(void)
{
	return READ_ONCE(tfw_reconfig);
}

bool
tfw_runstate_is_started_success(void)
{
	return READ_ONCE(tfw_state) == TFW_STATE_STARTED;
}

/**
 * Return true if Tempesta is started, and false otherwise.
 */
bool
tfw_runstate_is_started(void)
{
	return READ_ONCE(tfw_state) != TFW_STATE_STOPPED;
}

/**
 * Add @mod to the global list of registered modules.
 *
 * After the registration the module will start receiving
 * start/stop/setup/cleanup events and configuration updates.
 */
void
tfw_mod_register(TfwMod *mod)
{
	BUG_ON(!mod || !mod->name);
	T_DBG2("%s: %s\n", __func__, mod->name);

	write_lock(&tfw_mods_lock);
	INIT_LIST_HEAD(&mod->list);
	list_add_tail(&mod->list, &tfw_mods);
	write_unlock(&tfw_mods_lock);
}

/**
 * Remove the @mod from the global list.
 */
void
tfw_mod_unregister(TfwMod *mod)
{
	BUG_ON(!mod || !mod->name);
	T_DBG2("%s: %s\n", __func__, mod->name);

	write_lock(&tfw_mods_lock);
	list_del(&mod->list);
	write_unlock(&tfw_mods_lock);
}

TfwMod *
tfw_mod_find(const char *name)
{
	TfwMod *mod;

	read_lock(&tfw_mods_lock);
	list_for_each_entry(mod, &tfw_mods, list) {
		if (!name || !strcasecmp(name, mod->name)) {
			read_unlock(&tfw_mods_lock);
			return mod;
		}
	}
	read_unlock(&tfw_mods_lock);

	return NULL;
}

static void
tfw_cleanup(void)
{
	int *clean_1 = this_cpu_ptr(&main_clean_1);
        int *clean_2 = this_cpu_ptr(&main_clean_2);

	*clean_1 = *clean_2 = 1;

	(*clean_1)++;
	tfw_check_all_mm("tfw_cleanup START");
	tfw_cfg_cleanup(&tfw_mods);
	(*clean_1)++;

	if (!tfw_runstate_is_reconfig()) {
		tfw_check_all_mm("tfw_cleanup 111");
		(*clean_2)++;
		tfw_sg_wait_release();
		(*clean_2)++;
	}

	tfw_check_all_mm("tfw_cleanup FINISH");

	(*clean_1)++;
	T_DBG("New configuration is cleaned.\n");
}

static void
tfw_mods_stop(void)
{
	TfwMod *mod;
	bool ss_synced = false;

	tfw_check_all_mm("tfw_mods_stop START");

	ss_stop();

	T_DBG("Stopping all modules...\n");
	MOD_FOR_EACH_REVERSE(mod, &tfw_mods) {
		T_DBG2("mod_stop(): %s\n", mod->name);
		if (!mod->stop || !mod->started)
			continue;

		mod->stop();
		mod->started = 0;

		tfw_check_all_mm(mod->name);

		tfw_ss_users -= mod->sock_user;

		if (ss_synced || tfw_ss_users)
			continue;
		/*
		 * Wait until all network activity is stopped before data in
		 * modules can be cleaned up safely. We must do this between
		 * stopping modules using synchronous sockets and modules
		 * providing data structures for the first modules.
		 * In particular, we need to stop all networking activity after
		 * stopping sock_clnt and during the synchronization period the
		 * client database must provide valid references to stored
		 * clients.
		 */
		if (!ss_synchronize()) {
			tfw_cli_abort_all();
			/* Check that all the connections are terminated now. */
			WARN_ON(!ss_synchronize());
		}
		ss_synced = true;
	}
	BUG_ON(tfw_ss_users);

	tfw_check_all_mm("tfw_mods_stop FINISH");

	T_LOG("modules are stopped\n");
}

static void
tfw_stop(void)
{
	tfw_mods_stop();
	tfw_cleanup();
}

static int
tfw_mods_cfgstart(void)
{
	int ret;
	TfwMod *mod;

	tfw_check_all_mm("tfw_mods_cfgstart START");

	T_DBG2("Prepare the configuration processing...\n");
	MOD_FOR_EACH(mod, &tfw_mods) {
		if (!mod->cfgstart)
			continue;
		T_DBG2("mod_cfgstart(): %s\n", mod->name);
		if ((ret = mod->cfgstart())) {
			T_ERR_NL("Unable to prepare for the configuration "
				 "of module '%s': %d\n", mod->name, ret);
			return ret;
		}
	}
	T_DBG("Preparing for the configuration processing.\n");

	tfw_check_all_mm("tfw_mods_cfgstart FINISH");

	return 0;
}

static int
tfw_mods_start(void)
{
	int ret;
	TfwMod *mod;

	tfw_check_all_mm("tfw_mods_start START");

	T_DBG2("starting modules...\n");
	MOD_FOR_EACH(mod, &tfw_mods) {
		BUG_ON(mod->sock_user && (!mod->start || !mod->stop));

		if (!mod->start)
			continue;
		T_DBG2("mod_start(): %s\n", mod->name);

		tfw_check_all_mm(mod->name);

		if ((ret = mod->start())) {
			T_ERR_NL("Unable to start module '%s': %d\n",
				 mod->name, ret);

			tfw_check_all_mm("BAD 1111");

			if (mod->stop && !mod->started) {
				tfw_check_all_mm("BAD 2222");
				mod->stop();
				tfw_check_all_mm("BAD 3333");
			}
			return ret;
		}
		mod->started = 1;

		if (!tfw_runstate_is_reconfig())
			tfw_ss_users += mod->sock_user;
	}
	T_DBG("modules are started\n");

	tfw_check_all_mm("tfw_mods_start FINISH");

	return 0;
}

static int
tfw_mods_cfgend(void)
{
	int ret;
	TfwMod *mod;

	T_DBG2("Completing the configuration processing...\n");
	MOD_FOR_EACH(mod, &tfw_mods) {
		if (!mod->cfgend)
			continue;
		T_DBG2("mod_cfgend(): %s\n", mod->name);
		if ((ret = mod->cfgend())) {
			T_ERR_NL("Unable to complete the configuration "
				 "of module '%s': %d\n", mod->name, ret);
			return ret;
		}
	}
	T_LOG("Configuration processing is completed.\n");

	return 0;
}

static int
tfw_start(void)
{
	int ret;

	ss_start();
	if ((ret = tfw_mods_cfgstart()))
		goto cleanup;
	if ((ret = tfw_cfg_parse(&tfw_mods)))
		goto cleanup;
	if ((ret = tfw_mods_cfgend()))
		goto cleanup;
	if ((ret = tfw_mods_start())) {
		tfw_check_all_mm("BAD 4444444");
		goto stop_mods;
	}
	tfw_cfg_conclude(&tfw_mods);
	WRITE_ONCE(tfw_state, TFW_STATE_STARTED);

	T_LOG_NL("Tempesta FW is ready\n");

	return 0;
stop_mods:
	/*
	 * Live reconfiguration successfully parsed but failed just in the
	 * middle of replacing the old configuration. This cannot be fixed
	 * and Tempesta must be fully stopped and cleared.
	 */
	WRITE_ONCE(tfw_reconfig, false);
	tfw_mods_stop();
	WRITE_ONCE(tfw_state, TFW_STATE_STOPPED);
cleanup:
	T_WARN_NL("Configuration parsing has failed. Clean up...\n");
	if (READ_ONCE(tfw_state) == TFW_STATE_STARTED)
		WRITE_ONCE(tfw_state, TFW_STATE_STARTED_FAIL_RECONFIG);
	tfw_cleanup();
	return ret;
}

/**
 * Process command received from sysctl as string (either "start" or "stop").
 * Do corresponding actions, but only if the state is changed.
 */
static int
tfw_ctlfn_state_change(const char *new_state)
{
	T_DBG2("got state via sysctl: %s\n", new_state);

	if (!strcasecmp("start", new_state)) {
		int r;

		if (tfw_runstate_is_started()) {
			WRITE_ONCE(tfw_reconfig, true);
			T_LOG("Live reconfiguration of Tempesta.\n");
		}

		r = tfw_start();
		WRITE_ONCE(tfw_reconfig, false);

		return r;
	}

	if (!strcasecmp("stop", new_state)) {
		if (!tfw_runstate_is_started()) {
			T_WARN_NL("Trying to stop an inactive system\n");
			return -EINVAL;
		}

		tfw_stop();
		WRITE_ONCE(tfw_state, TFW_STATE_STOPPED);

		return 0;
	}

	T_ERR_NL("invalid state: '%s'. Should be either 'start' or 'stop'\n",
		 new_state);

	return -EINVAL;
}

/**
 * Syctl handler for tempesta.state read/write operations.
 */
static int
tfw_ctlfn_state_io(const struct ctl_table *ctl, int is_write,
		   void *user_buf, size_t *lenp, loff_t *ppos)
{
	int r = 0;
	static char new_state_buf[T_SYSCTL_STBUF_LEN] = {0};
	struct ctl_table tmp = *ctl;

	mutex_lock(&tfw_sysctl_mtx);

	if (is_write) {
		char buf[T_SYSCTL_STBUF_LEN] = {0};
		char start[T_SYSCTL_STBUF_LEN] = "start";
		char stop[T_SYSCTL_STBUF_LEN] = "stop";
		char start_fail_reconfig[T_SYSCTL_STBUF_LEN] =
			"start (failed reconfig)";

		tmp.data = buf;
		if ((r = proc_dostring(&tmp, is_write, user_buf, lenp, ppos)))
			goto out;

		r = tfw_ctlfn_state_change(buf);
		if (READ_ONCE(tfw_state) == TFW_STATE_STOPPED) {
			strscpy(new_state_buf, stop, T_SYSCTL_STBUF_LEN);
		} else if (READ_ONCE(tfw_state) == TFW_STATE_STARTED) {
			strscpy(new_state_buf, start, T_SYSCTL_STBUF_LEN);
		} else {
			strscpy(new_state_buf, start_fail_reconfig,
				T_SYSCTL_STBUF_LEN);
		}
	} else {
		tmp.data = new_state_buf;
		r = proc_dostring(&tmp, is_write, user_buf, lenp, ppos);
	}
out:
	mutex_unlock(&tfw_sysctl_mtx);
	return r;
}

/**
 * Wait until all objects of some specific type @obj_name are
 * destructed. The count of objects is specified in atomic @counter.
 * The maximum time to wait is @delay seconds. The function is called
 * after ss_synchronize(), after configuration cleanup: there shouldn't
 * be any active connections, but this is still possible.
 */
void
tfw_objects_wait_release(const atomic64_t *counter, int delay,
			 const char *obj_name)
{
	unsigned long tend = jiffies + HZ * delay;
	long last_n = atomic64_read(counter), curr_n;

	might_sleep();
	/*
	 * Wait in a cycle until all objects will be destroyed.
	 */
	while ((curr_n = atomic64_read(counter))) {
		schedule();
		if (time_is_after_jiffies(tend))
			continue;
		if (curr_n < 0) {
			T_ERR_NL("Bug in %s reference counting!\n", obj_name);
			break;
		}
		else if (curr_n == last_n) {
			T_ERR_NL("Got stuck in releasing of %s objects! "
				 "%ld objects was not released.\n",
				 obj_name, curr_n);
			break;
		}
		T_WARN_NL("pending for %s callbacks to complete for %ds, "
			  "%ld objects was released, %ld still exist\n",
			  obj_name, delay, last_n - curr_n, curr_n);
		tend = jiffies + HZ * delay;
		last_n = curr_n;
	}
}

static struct ctl_table_header *tfw_sysctl_hdr;
static struct ctl_table tfw_sysctl_tbl[] = {
	{
		.procname	= "state",
		.maxlen		= T_SYSCTL_STBUF_LEN - 1,
		.mode		= 0644,
		.proc_handler	= tfw_ctlfn_state_io,
	}
};

#define DO_INIT(mod)						\
do {								\
	extern int tfw_##mod##_init(void);			\
	extern void tfw_##mod##_exit(void);			\
	BUG_ON(exit_hooks_n >= ARRAY_SIZE(exit_hooks));		\
	T_DBG("init: %s\n", #mod);				\
	r = tfw_##mod##_init();					\
	if (r) {						\
		T_ERR_NL("can't initialize Tempesta FW module: '%s' (%d)\n", \
			   #mod, r);				\
		goto err;					\
	}							\
	exit_hooks[exit_hooks_n].fn = tfw_##mod##_exit;		\
	strncpy(exit_hooks[exit_hooks_n].name, #mod, NMAX);	\
	exit_hooks_n++;						\
} while (0)

static void
tfw_exit(void)
{
	int i;

	int *stop_1 = this_cpu_ptr(&main_stop_1);
	int *stop_2 = this_cpu_ptr(&main_stop_2);

	T_LOG_NL("exiting...\n");

	*stop_1 = *stop_2 = 1;

	tfw_check_all_mm("tfw_exit START");

	/* Let's put this under the same mutex as the sysctl callback
	 * to avoid concurrent shutdown calls */
	mutex_lock(&tfw_sysctl_mtx);
	(*stop_1)++;
	if (tfw_runstate_is_started()) {
		(*stop_2)++;
		T_WARN_NL("Tempesta FW is still running, shutting down...\n");
		(*stop_2)++;

		tfw_check_all_mm("tfw_exit 111");
		tfw_stop();
		tfw_check_all_mm("tfw_exit 222");
		(*stop_2)++;
		WRITE_ONCE(tfw_state, TFW_STATE_STOPPED);
		(*stop_2)++;
	}
	(*stop_1)++;
	mutex_unlock(&tfw_sysctl_mtx);
	(*stop_1)++;

	/* Wait for outstanding RCU callbacks to complete. */
	rcu_barrier();
	(*stop_1)++;

	for (i = exit_hooks_n - 1; i >= 0; --i) {
		exit_hooks[i].fn();
		tfw_check_all_mm(exit_hooks[i].name);
	}

	tfw_check_all_mm("tfw_exit FINISH");

	(*stop_2)++;

	TFW_PANIC = NULL;
	TFW_ON_STALL = NULL;

	unregister_net_sysctl_table(tfw_sysctl_hdr);

	atomic_set(&canary, 0);
}

static int __init
tfw_init(void)
{
	int r;

	T_LOG("Initializing Tempesta FW kernel module...\n");

#ifndef AVX2
	T_LOG("ATTENTION: TEMPESTA IS BUILT WITHOUT AVX2 SUPPORT, "
	      "PERFORMANCE IS DEGRADED.");
#endif

	tfw_sysctl_hdr = register_net_sysctl(&init_net, "net/tempesta",
					     tfw_sysctl_tbl);
	if (!tfw_sysctl_hdr) {
		T_ERR_NL("can't register sysctl table\n");
		return -1;
	}

	/* The order of initialization is highly important. */
	DO_INIT(pool);
	DO_INIT(cfg);
	DO_INIT(access_log);
	DO_INIT(apm);
	DO_INIT(vhost);

	/*
	 * Register in order TLS -> HTTP -> limits, for correct
	 * registration of FSM hooks.
	 */
	DO_INIT(tls);
	DO_INIT(http);
	DO_INIT(http_limits);
	DO_INIT(filter);
	DO_INIT(cache);
	DO_INIT(http_sess);
	DO_INIT(websocket);

	DO_INIT(sync_socket);
	DO_INIT(server);
	DO_INIT(client);
	DO_INIT(sock_srv);
	DO_INIT(sock_clnt);
	DO_INIT(procfs);
	DO_INIT(http_tbl);
	DO_INIT(sched_hash);
	DO_INIT(sched_ratio);

	TFW_PANIC = tfw_apm_on_panic;
	TFW_ON_STALL = tfw_on_stall_impl;

	return 0;
err:
	tfw_exit();
	return r;
}

module_init(tfw_init);
module_exit(tfw_exit);
