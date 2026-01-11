/**
 *		Tempesta FW
 *
 * This file contains utils that help to test certain Tempesta FW modules.
 * They implement things like stubbing, mocking, generating data for testing.
 *
 * Actually things contained in this file are wrong a bit.
 * Good code tends to have most of the logic in pure stateless loosely-coupled
 * well-isolated functions that may be tested without faking any state.
 * But this is not reachable most of the time, especially when performance is
 * a goal and you have to build the architecture keeping it in mind.
 * So over time, we expect to see a decent amount of helpers here.
 *
 * These things are specific to Tempesta FW, so they are located here,
 * and generic testing functions/macros are located in test.c/test.h
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2026 Tempesta Technologies, Inc.
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
#include "helpers.h"
#include "http_msg.h"
#include "pool.c"
#include "apm.h"
#include "filter.h"
#include "http_sess_conf.h"
#include "cache.h"
#include "http_tbl.h"
#include "access_log.h"
#include "tf_conf.h"
#include "tf_filter.h"

static TfwConn conn_req, conn_resp;

unsigned int tfw_cli_max_concurrent_streams;

#ifdef DBG_ENABLE_2556_DEBUG

void
print_conns(void)
{
}

#endif /* DBG_ENABLE_2556_DEBUG */

TfwHttpReq *
test_req_alloc(size_t data_len)
{
	int ret;
	TfwMsgIter it;
	TfwHttpMsg *hmreq;

	/* Actually there were more code here, mostly it was copy-paste from
	 * tfw_http_msg_alloc(). It is removed because we need to test how it
	 * initializes the message and we would not like to test the copy-paste.
	 */
	hmreq = __tfw_http_msg_alloc(Conn_HttpClnt, true);
	BUG_ON(!hmreq);

	ret = tfw_http_msg_setup(hmreq, &it, data_len);
	BUG_ON(ret);

	memset(&conn_req, 0, sizeof(TfwConn));
	tfw_connection_init(&conn_req);
	conn_req.proto.type = Conn_HttpClnt;
	hmreq->conn = &conn_req;
	hmreq->stream = &conn_req.stream;
	tfw_http_init_parser_req((TfwHttpReq *)hmreq);

	return (TfwHttpReq *)hmreq;
}

void
test_req_free(TfwHttpReq *req)
{
	/* In tests we are stricter: we don't allow to free a NULL pointer
	 * to be sure exactly what we are freeing and to catch bugs early. */
	BUG_ON(!req);

	tfw_http_msg_free((TfwHttpMsg *)req);
}

TfwHttpResp *
test_resp_alloc(size_t data_len)
{
	TfwMsgIter it;
	int ret;
	TfwHttpResp *hmresp = test_resp_alloc_no_data();

	ret = tfw_http_msg_setup((TfwHttpMsg *)hmresp, &it, data_len);
	BUG_ON(ret);

	return (TfwHttpResp *)hmresp;
}

TfwHttpResp *
test_resp_alloc_no_data()
{
	TfwHttpMsg *hmresp;

	hmresp = __tfw_http_msg_alloc(Conn_HttpSrv, true);
	BUG_ON(!hmresp);

	memset(&conn_resp, 0, sizeof(TfwConn));
	tfw_connection_init(&conn_resp);
	conn_resp.proto.type = Conn_HttpSrv;
	hmresp->conn = &conn_resp;
	hmresp->stream = &conn_resp.stream;
	tfw_http_init_parser_resp((TfwHttpResp *)hmresp);

	return (TfwHttpResp *)hmresp;
}

void
test_resp_free(TfwHttpResp *resp)
{
	BUG_ON(!resp);
	tfw_http_msg_free((TfwHttpMsg *)resp);
}

/*
 * Testing mocks to start/stop minimum functionality, necessary for the parser
 * environment.
 */
struct {} *tfw_perfstat;

void
tfw_apm_hm_srv_rcount_update(TfwStr *uri_path, void *apmref)
{
}

bool
tfw_apm_hm_srv_alive(TfwHttpResp *resp, TfwServer *srv)
{
	return true;
}

bool
tfw_apm_hm_srv_limit(int status, void *apmref)
{
	return false;
}

void
tfw_apm_update(void *apmref, unsigned long jtstamp, unsigned long jrtt)
{
}

void
tfw_apm_update_global(unsigned long jtstamp, unsigned long jrtime)
{
}

bool
ss_active(void)
{
	return true;
}

int
ss_send(struct sock *sk, struct sk_buff **skb_head, int flags)
{
	return 0;
}

int
ss_close(struct sock *sk, int flags)
{
	return 0;
}

bool
ss_synchronize(void)
{
	return true;
}

void
ss_stop(void)
{
}

void ss_skb_tcp_entail(struct sock *sk, struct sk_buff *skb, unsigned int mark,
		       unsigned char tls_type)
{
}

int ss_skb_tcp_entail_list(struct sock *sk, struct sk_buff **skb)
{
	return 0;
}

void
tfw_client_put(TfwClient *cli)
{
}

TfwClient *
tfw_client_obtain(TfwAddr addr, TfwAddr *xff_addr, TfwStr *user_agent,
		  void (*init)(void *))
{
	return NULL;
}

int
tfw_cli_conn_send(TfwCliConn *cli_conn, TfwMsg *msg)
{
	return 0;
}

void
tfw_cli_abort_all(void)
{
}

void
tfw_gfsm_state_init(TfwGState *st, void *obj, int st0)
{
}

int
tfw_gfsm_register_hook(int fsm_id, int prio, int state,
		       unsigned short hndl_fsm_id, int st0)
{
	return 0;
}

void
tfw_gfsm_unregister_fsm(int fsm_id)
{
}

void
tfw_gfsm_unregister_hook(int fsm_id, int prio, int state)
{
}

int
tfw_gfsm_move(TfwGState *st, unsigned short state, TfwFsmData *data)
{
	return 0;
}

int
tfw_gfsm_register_fsm(int fsm_id, tfw_gfsm_handler_t handler)
{
	return 0;
}

void
tfw_filter_block_ip(const TfwClient *cli, long duration)
{
}

TfwCfgSpec tfw_http_sess_specs[0];

int
tfw_http_sess_cfgop_finish(TfwVhost *vhost, TfwCfgSpec *cs)
{
	return 0;
}

int
tfw_http_sess_cfgop_begin(TfwVhost *vhost, TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return 0;
}

void
tfw_http_sess_cfgop_cleanup(TfwCfgSpec *cs)
{
}

void
tfw_http_sess_cookie_clean(TfwVhost *vhost)
{
}

int
tfw_http_sess_cfg_finish(TfwVhost *vhost)
{
	return 0;
}

void
tfw_http_sess_cfgstart(void)
{
}

void
tfw_http_sess_cfgend(void)
{
}

int
tfw_cache_process(TfwHttpMsg *msg, tfw_http_cache_cb_t action)
{
	return 0;
}

TfwHttpResp *
tfw_cache_build_resp_stale(TfwHttpReq *req)
{
	return NULL;
}

void
tfw_cache_put_entry(int node, void *ce)
{
}

void
tfw_tls_cfg_configured(bool global)
{
}

void
tfw_tls_set_allow_any_sni(bool match)
{
}

void
tfw_connection_init(TfwConn *conn)
{
	memset(conn, 0, sizeof(*conn));
	INIT_LIST_HEAD(&conn->list);
}

int
tfw_connection_close(TfwConn *conn, bool sync)
{
	return 0;
}

void
tfw_connection_abort(TfwConn *conn)
{
}

void
tfw_connection_hooks_register(TfwConnHooks *hooks, int type)
{
}

void
tfw_connection_hooks_unregister(int type)
{
}

TfwHdrMods*
tfw_vhost_get_hdr_mods(TfwLocation *loc, TfwVhost *vhost, int mod_type)
{
	return NULL;
}

TfwVhost *
tfw_vhost_lookup_default(void)
{
	return NULL;
}

int
tfw_http_tbl_action(TfwMsg *msg, TfwHttpActionResult *action)
{
	return 0;
}

int
tfw_http_tbl_method(const char *arg, tfw_http_meth_t *method)
{
	return 0;
}

TfwGlobal *
tfw_vhost_get_global(void)
{
	return NULL;
}

void
tfw_vhost_destroy(TfwVhost *vhost)
{
}

TfwSrvConn *
tfw_vhost_get_srv_conn(TfwMsg *msg)
{
	return NULL;
}

TfwLocation *
tfw_location_match(TfwVhost *vhost, TfwStr *arg)
{
	return NULL;
}

TfwNipDef *
tfw_nipdef_match(TfwLocation *loc, unsigned char method, TfwStr *arg)
{
	return NULL;
}

void
tfw_sg_wait_release(void)
{
}

void
tfw_server_destroy(TfwServer *srv)
{
}

void
do_access_log(TfwHttpResp *resp)
{
}

void
do_access_log_req(TfwHttpReq *req, int status, unsigned long content_length)
{
}

bool
frang_req_is_whitelisted(TfwHttpReq *req)
{
	return true;
}

int
frang_http_hdr_limit(TfwHttpReq *req, unsigned int new_hdr_len)
{
	return T_OK;
}

int
frang_sticky_cookie_handler(TfwHttpReq *req)
{
	return T_OK;
}

bool
ttls_hs_done(TlsCtx *tls)
{
	return true;
}

bool
ttls_xfrm_need_encrypt(TlsCtx *tls)
{
	return true;
}

TfwCacheUseStale *
tfw_vhost_get_cache_use_stale(TfwLocation *loc, TfwVhost *vhost)
{
	return NULL;
}

void
http_tf_cfgop_cleanup(TfwCfgSpec *cs)
{

}

int
tf_cfgop_begin(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return 0;
}

u64
http_get_tf_storage_size(void)
{
	return 0;
}

bool
tfh_init_filter(size_t max_storage_size)
{
	return true;
}

void
tfh_close_filter(void)
{

}

int
http_tf_cfgop_finish(TfwCfgSpec *cs)
{
	return 0;
}

u64
http_get_tf_recs_limit(HttpTfh fingerprint)
{
	return UINT_MAX;
}

u32
tfh_get_records_rate(HttpTfh fingerprint)
{
	return 0;
}

TfwCfgSpec tf_hash_specs[0];

unsigned int cache_default_ttl = 60;
