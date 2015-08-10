#ifndef __TFW_SCHED_HELPER_H__
#define __TFW_SCHED_HELPER_H__

#include "server.h"

typedef struct {
	TfwConnection		conn;
	struct timer_list	retry_timer;
	unsigned long		timeout;
	unsigned int		attempts;
} TfwSrvConnection;

TfwSrvGroup *test_create_sg(const char *name, const char *sched_name);
void test_sg_release_all(void);

TfwServer *test_create_srv(const char *in_addr, TfwSrvGroup *sg);

TfwSrvConnection *test_create_conn(TfwPeer *peer);
void test_conn_release_all(TfwSrvGroup *sg);

#endif /* __TFW_SCHED_HELPER_H__ */
