/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2019 Tempesta Technologies, Inc.
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
#include <linux/types.h>
#include <asm/fpu/api.h>
/* prevent exporting symbols */
#include <linux/module.h>
#undef EXPORT_SYMBOL
#define EXPORT_SYMBOL(...)

#ifdef __read_mostly
#undef __read_mostly
#define __read_mostly
#endif

#ifdef __init
#undef __init
#define __init
#endif

/*
 * TODO #74: the test is complete mess - it includes half of Tempesta source
 * code and I gave up to fix multiple definition conflicts for debug mode.
 */
#undef DEBUG

#include "str.c"
#include "http_msg.c"
#include "msg.c"
#include "http_sess.c"
#include "http_sess_conf.c"

#include "filter.c"
#include "sock.c"
#include "server.c"
#include "sock_srv.c"
#include "client.c"
#include "http_limits.c"
#include "http_stream.c"
#include "http_frame.c"
#include "tls.c"

/* rename original tfw_cli_conn_send(), a custom version will be used here */
#define tfw_cli_conn_send	divert_tfw_cli_conn_send
#include "sock_clnt.c"
#undef tfw_cli_conn_send

/* rename original tfw_http_resp_build_error(), a custom version will be used here */
#define tfw_http_resp_build_error	divert_tfw_http_resp_build_error
/*
 * TODO make working redefinition; current redefinition does not work as
 * the definition and the call of the function are in the same file.
 */
#include "http.c"
#undef tfw_http_resp_build_error

#include "hash.c"
#include "addr.c"
#include "ss_skb.c"
#include "sched.c"
#include "gfsm.c"
#include "cache.c"
/*
 * Use the header file here to declare functions from http_parser.c included
 * by test_http_parser.c. We can not include the C file to avoid linker
 * conflicts on the module assembling.
 */
#include "http_parser.h"
#include "work_queue.c"
#include "procfs.c"

/* rename original tfw_connection_send(), a custom version will be used here */
#define tfw_connection_send	divert_tfw_connection_send
#include "connection.c"
#undef tfw_connection_send

#include "vhost.h"
#include "test.h"
#include "helpers.h"
#include "tfw_str_helper.h"

#define TOK_NAME	"__test_name"
#define MAX_MISSES	"3"

/* custom version for testing purposes */
int
tfw_connection_send(TfwConn *conn, TfwMsg *msg)
{
	return 0;
}

/* Custom version for testing purposes. */
int tfw_cli_conn_send(TfwCliConn *cli_conn, TfwMsg *msg)
{
	return tfw_connection_send((TfwConn *)cli_conn, msg);
}

/* Custom version for testing purposes. */
void
tfw_http_resp_build_error(TfwHttpReq *req)
{
	(void)req;
}

int
test_helper_sticky_start(unsigned int misses)
{
	redir_mark_enabled = true;
	return 0;
}

void
test_helper_sticky_stop(void)
{
	redir_mark_enabled = false;
}


TEST_SUITE(http_sticky)
{

}
