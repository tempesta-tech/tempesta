#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/module.h>

#include "../sched.h"
#include "../debugfs.h"

MODULE_AUTHOR(TFW_AUTHOR);
MODULE_DESCRIPTION("Tempesta round-robin scheduler");
MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL");

/*
 * The scheduler keeps all servers in a double-linked list.
 * When .get_srv() is invoked the first server in the list is returned and the
 * list is rotated so the next call returns the next server in the list.
 * The head 'srv_list' always points to the next server returned by the scheduler.
 */
LIST_HEAD(srv_list);
DEFINE_SPINLOCK(srv_list_spinlock);

/*
 * The srv_list consists of the TfwSchedRrSrvEntry elements.
 * They are allocated dynamically when a server is added or removed.
 */
typedef struct tfw_sched_rr_srv_entry_t {
	TfwServer *srv;
	struct list_head list;
} TfwSchedRrSrvEntry;

/**
 * Find an entry in the 'srv_list' corresponding to the given server.
 *
 * Note: the function must be called with srv_list_spinlock locked.
 */
static TfwSchedRrSrvEntry *
find_srv_entry(TfwServer *srv) {
	TfwSchedRrSrvEntry *srv_entry;

	list_for_each_entry(srv_entry, &srv_list, list) {
		if (srv == srv_entry->srv)
			return srv_entry;
	}

	return NULL;
}

/**
 * The implementation of get_srv() for the round-robin scheduler.
 *
 * @param msg  A message for which the server should be chosen.
 *             The round-robin scheduler doesn't use it to pick a server, so
 *             the argument is simply ignored.
 *
 * On each call the function returns the next server in the scheduling list
 * (which is filled from the tfw_sched_rr_add_srv() function).
 */
TfwServer *
tfw_sched_rr_get_srv(TfwMsg *msg)
{
	TfwSchedRrSrvEntry *entry;
	TfwServer *srv;

	spin_lock(&srv_list_spinlock);

	entry = list_first_entry_or_null(&srv_list, TfwSchedRrSrvEntry, list);
	list_rotate_left(&srv_list);

	spin_unlock(&srv_list_spinlock);

	srv = (entry ? entry->srv : NULL);
	return srv;
}

/**
 * The implementation of add_srv() method for the round-robin scheduler.
 *
 * @param srv  A server to be added for scheduling.
 *             Must not be NULL.
 *
 * The server is added to the head of the scheduling list, so the
 * tfw_sched_rr_get_srv() will return it upon the next call.
 *
 * Return: Zero on success, or an error code:
 *         ENOMEM if there is no memory available,
 *         EEXIST if the given is already present.
 */
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

/**
 * Delete the given server from the scheduling list.
 *
 * @param srv  A server to be removed from the scheduler.
 *             Must not be null.
 *
 * Return: Zero on success or ENOENT if no such server is found in the list.
 */
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

	return (entry_is_deleted ? 0 : -ENOENT);
}

static int
print_state_to_str(char *buf, size_t size)
{
	int printed, total_printed = 0;

	TfwSchedRrSrvEntry *srv_entry, *tmp_entry;
	list_for_each_entry_safe(srv_entry, tmp_entry, &srv_list, list) {
		printed = snprintf(buf, size, "%p\n", srv_entry->srv);
		if (printed <= 0)
			break;
		BUG_ON(printed > size);
		buf += printed;
		size -= printed;
		total_printed += printed;
	}

	return total_printed;
}


static TfwScheduler tfw_sched_rr_mod = {
	.name = "round-robin",
	.get_srv = tfw_sched_rr_get_srv,
	.add_srv = tfw_sched_rr_add_srv,
	.del_srv = tfw_sched_rr_del_srv
};

int tfw_sched_rr_init(void)
{

	static TfwDebugfsHandlers h = {
		.read = print_state_to_str,
		.write = NULL
	};
	tfw_debugfs_set_handlers("/sched_rr/state", &h);

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

	tfw_sched_unregister(&tfw_sched_rr_mod);
}
module_exit(tfw_sched_rr_exit);