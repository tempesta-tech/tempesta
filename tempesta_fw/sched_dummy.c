#include "sched.h"
#include "log.h"


/* The only single server is supported by the dummy scheduler. */
static TfwServer *dummy_srv = NULL;


TfwServer *
tfw_sched_dummy_get_srv(TfwMsg *msg)
{
	return dummy_srv;
}

int
tfw_sched_dummy_add_srv(TfwServer *srv)
{
	if (srv && dummy_srv)
		TFW_WARN("Can't add multiple servers to the dummy scheduler,"
			 "so only the most recently added server is used\n");

	dummy_srv = srv;

	return 0;
}

int
tfw_sched_dummy_del_srv(TfwServer *srv)
{
	if (srv != dummy_srv) {
		TFW_WARN("Can't remove the server from the dummy scheduler\n");
		return -ENOENT;
	} else {
		dummy_srv = NULL;
		return 0;
	}
}


TfwScheduler tfw_sched_dummy_mod = {
	.name = "dummy",
	.get_srv = tfw_sched_dummy_get_srv,
	.add_srv = tfw_sched_dummy_add_srv,
	.del_srv = tfw_sched_dummy_del_srv
};

int tfw_sched_dummy_init(void)
{

	return tfw_sched_register(&tfw_sched_dummy_mod);
}

void tfw_sched_dummy_exit(void)
{
	dummy_srv = NULL;

	tfw_sched_unregister(&tfw_sched_dummy_mod);
}
