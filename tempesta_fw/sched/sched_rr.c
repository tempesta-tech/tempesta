#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/module.h>

#include "../sched.h"

MODULE_AUTHOR(TFW_AUTHOR);
MODULE_DESCRIPTION("Tempesta round-robin scheduler");
MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL");

typedef struct tfw_sched_rr_srv_entry_t {
	TfwServer *srv;
	struct list_head list;
} TfwSchedRrSrvEntry;

static LIST_HEAD(srv_list);

DEFINE_SPINLOCK(srv_list_spinlock);

static TfwSchedRrSrvEntry *
find_srv_entry(TfwServer *srv) {
	TfwSchedRrSrvEntry *srv_entry;

	list_for_each_entry(srv_entry, &srv_list, list) {
		if (srv == srv_entry->srv)
			return srv_entry;
	}

	return NULL;
}

TfwServer *
tfw_sched_rr_get_srv(TfwMsg *msg)
{
	TfwSchedRrSrvEntry *entry;

	BUG_ON(!msg);

	spin_lock(&srv_list_spinlock);

	entry = list_first_entry_or_null(&srv_list, TfwSchedRrSrvEntry, list);
	list_rotate_left(&srv_list);

	spin_unlock(&srv_list_spinlock);

	return (entry ? entry->srv : NULL);
}

int
tfw_sched_rr_add_srv(TfwServer *srv)
{
	int ret = 0;
	TfwSchedRrSrvEntry *new_entry;

	BUG_ON(!srv);

	new_entry = kzalloc(sizeof(*new_entry), GFP_KERNEL);
	if (!new_entry) {
		ret = -ENOMEM;
		goto out;
	}

	spin_lock(&srv_list_spinlock);
	if (find_srv_entry(srv)) {
		ret = -EEXIST;
	} else {
		new_entry->srv = srv;
		list_add(&new_entry->list, &srv_list);
	}
	spin_unlock(&srv_list_spinlock);

out:
	return ret;
}

int
tfw_sched_rr_del_srv(TfwServer *srv)
{
	bool entry_is_deleted = false;
	TfwSchedRrSrvEntry *srv_entry, *tmp_entry;

	BUG_ON(!srv);

	spin_lock(&srv_list_spinlock);
	list_for_each_entry_safe(srv_entry, tmp_entry, &srv_list, list) {
		if (srv == srv_entry->srv) {
			list_del(&srv_entry->list);
			kfree(srv_entry);
			entry_is_deleted = true;
		}
	}
	spin_unlock(&srv_list_spinlock);

	return (entry_is_deleted ? 0 : -ENOMEM);
}



TfwScheduler tfw_sched_rr_mod = {
	.name = "round-robin",
	.get_srv = tfw_sched_rr_get_srv,
	.add_srv = tfw_sched_rr_add_srv,
	.del_srv = tfw_sched_rr_del_srv
};

int tfw_sched_rr_init(void)
{
	return tfw_sched_register(&tfw_sched_rr_mod);
}
module_init(tfw_sched_rr_init);

void tfw_sched_rr_exit(void)
{
	TfwSchedRrSrvEntry *srv_entry, *tmp_entry;

	list_for_each_entry_safe(srv_entry, tmp_entry, &srv_list, list) {
		list_del(&srv_entry->list);
		kfree(srv_entry);
	}
}
module_exit(tfw_sched_rr_exit);