/**
 *		Tempesta FW
 *
 * Copyright (C) 2019-2025 Tempesta Technologies, Inc.
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

#include <crypto/hash.h>

#include "http_sess_conf.h"
#include "http_sess.h"
#include "vhost.h"
#include "lib/random.h"
#include "lib/fault_injection_alloc.h"

/* Currently parsed vhost. */
static TfwVhost *cur_vhost;

#define STICKY_NAME_DEFAULT	"__tfw"

/*
 * JavaScript challenge requires a browser to execute a code from the response
 * body, so 30x redirects don't work for us since browsers ignore the body
 * and perfrom redirects automatically. We still send location header, which
 * is ignored by the browser in case of 50x error code, but the logic is simpler
 * for us to allow a configurations with 30x redirects and unify the code for
 * the JavaScript and Cookie challenges.
 */
static const unsigned int tfw_cfg_jsch_code_dflt = 503;
#define TFW_CFG_JS_PATH "/etc/tempesta/js_challenge.html"

struct {
	TfwStickyCookie		sticky;
	unsigned long		vhost_flags;
	int			cookie_set:1,
				learn_set:1,
				st_sessions_set:1,
				lifetime_set:1;
	char			secret[1024];
} defaults_override;

static void
__tfw_http_sess_cookie_clean(TfwStickyCookie *sticky)
{
	TfwStr *c;

	if (sticky->shash)
		crypto_free_shash(sticky->shash);

	if (!sticky->js_challenge ||
	    !refcount_dec_and_test(&sticky->js_challenge->users))
	{
		return;
	}

	c = TFW_STR_CHUNK(&sticky->js_challenge->body, 0);
	if (c && c->data) {
		free_pages((unsigned long)c->data,
			   get_order(sticky->js_challenge->body.len));
		kfree(sticky->js_challenge->body.chunks);
	}
	kfree(sticky->js_challenge);
}

void
tfw_http_sess_cookie_clean(TfwVhost *vhost)
{
	return __tfw_http_sess_cookie_clean(vhost->cookie);
}

static int
__tfw_http_sess_cfgop_begin(TfwStickyCookie *sticky)
{
	sticky->name.data = sticky->name_eq.data = sticky->sticky_name;
	sticky->options.data = sticky->options_str;

	return 0;
}

static void
tfw_http_sess_cfg_defaults_reset(void)
{
	__tfw_http_sess_cookie_clean(&defaults_override.sticky);
	memset(&defaults_override, 0, sizeof(defaults_override));
}

int
tfw_http_sess_cfgop_begin(TfwVhost *vhost, TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	TfwStickyCookie *sticky;
	int r;

	/*
	 * 'sticky' directive at top level to override defaults. May appear
	 * multiple times.
	 */
	if (!vhost) {
		tfw_http_sess_cfg_defaults_reset();
		sticky = &defaults_override.sticky;
	}
	else {
		sticky = vhost->cookie;
	}

	if ((r = __tfw_http_sess_cfgop_begin(sticky)))
		return r;
	cur_vhost = vhost;

	return 0;
}

/**
 * Inherit default values from the @defaults_override. Applied only to
 * directives that can't be set up via default values from tfw_http_sess_specs.
 */
static int
tfw_cfgop_sticky_inherit(TfwVhost *vhost)
{
	TfwStickyCookie *st;
	TfwStickyCookie *def_st = &defaults_override.sticky;

	if (!vhost)
		return 0;
	st = vhost->cookie;

	/*
	 * 'cookie' was explicitly set, no need to inherit anything.
	 * 'js_challenge' directive can be inherited only if the 'cookie'
	 * is inherited. If the 'cookie' is explicitly defined in the current
	 * 'sticky' section, ignore 'js_challenge' defined at top-level.
	 */
	if (!TFW_STR_EMPTY(&st->name)
	    || !(defaults_override.cookie_set || defaults_override.learn_set))
	{
		return 0;
	}

	memcpy(st->sticky_name, def_st->sticky_name, def_st->name_eq.len);
	st->name.len = def_st->name_eq.len - 1;
	st->name_eq.len = def_st->name_eq.len;
	st->name.data = st->name_eq.data = st->sticky_name;

	memcpy(st->options_str, def_st->options_str, def_st->options.len);
	st->options.len = def_st->options.len;
	st->options.data = st->options_str;

	st->max_misses = def_st->max_misses;
	st->learn = def_st->learn;
	st->enforce = def_st->enforce;
	st->expires = def_st->expires;

	if (!st->js_challenge && def_st->js_challenge) {
		st->js_challenge = def_st->js_challenge;
		refcount_inc(&st->js_challenge->users);
		st->redirect_code = st->js_challenge->st_code;
		/*
		 * Already was checked at tfw_http_sess_cfgop_finish() for
		 * top-level sticky directive.
		 */
		WARN_ON_ONCE(!st->enforce);
	}
	else {
		st->redirect_code = TFW_REDIR_STATUS_CODE_DFLT;
	}

	return 0;
}

static int
tfw_cfgop_cookie_set_option(TfwStickyCookie *sticky, const char *name,
			    const char *val)
{
	size_t name_len = strlen(name);
	size_t val_len = val ? strlen(val) + 1 : 0;

	if (sticky->options.len + 2 + name_len + val_len > STICKY_OPT_MAXLEN) {
		T_ERR_NL("http_sess: too long cookie options length.\n");
		return -EINVAL;
	}

	sticky->options_str[sticky->options.len + 0] = ';';
	sticky->options_str[sticky->options.len + 1] = ' ';
	memcpy(&sticky->options_str[sticky->options.len + 2], name, name_len);
	if (val_len) {
		sticky->options_str[sticky->options.len + 2 + name_len] = '=';
		memcpy(&sticky->options_str[sticky->options.len + 3 + name_len],
		       val, val_len);
	}
	sticky->options.len += name_len + val_len + 2;

	return 0;
}

/**
 * Finish processing 'sticky' section.
 */
int
tfw_http_sess_cfgop_finish(TfwVhost *vhost, TfwCfgSpec *cs)
{
	TfwStickyCookie *sticky = vhost ? vhost->cookie
					: &defaults_override.sticky;
	int r;

	cur_vhost = NULL;

	if (sticky->js_challenge) {
		if (TFW_STR_EMPTY(&sticky->name)) {
			T_ERR_NL("http_sess: JavaScript challenge requires "
				 "sticky cookies enabled and explicitly defined "
				 "in the same section\n");
			return -EINVAL;
		}
		if (sticky->learn) {
			T_ERR_NL("http_sess: JavaScript challenge incompatible "
				 "with learned cookies\n");
			return -EINVAL;
		}
		T_LOG_NL("http_sess: JavaScript challenge requires enforced "
			 "sticky cookie mode\n");
		sticky->enforce = true;
		sticky->redirect_code = sticky->js_challenge->st_code;
	} else {
		sticky->redirect_code = TFW_REDIR_STATUS_CODE_DFLT;
	}

	if (sticky->options_str[0] != '\0') {
		if (TFW_STR_EMPTY(&sticky->name)) {
			T_ERR_NL("http_sess: cookie options requires "
				 "sticky cookies enabled and explicitly defined "
				 "in the same section\n");
			return -EINVAL;
		}
	} else if (!TFW_STR_EMPTY(&sticky->name)) {
		if ((r = tfw_cfgop_cookie_set_option(sticky, "Path", "/")))
			return r;
	}

	/* Inherit sticky options defined at top level. */
	if ((r = tfw_cfgop_sticky_inherit(vhost))) {
		T_ERR_NL("http_sess: Can't inherit top-level '%s' directive "
			 "configuration to vhost '%.*s'\n",
			 cs->name, PR_TFW_STR(&vhost->name));
		return r;
	}

	return 0;
}

void
tfw_http_sess_cfgop_cleanup(TfwCfgSpec *cs)
{
	/*
	 * Clean up function is required for configuration handling, but the
	 * clean up actually happens in vhost destructor. Nothing to do here.
	 */
	return;
}

static int
__tfw_cfgop_cookie_set_name(TfwStickyCookie *sticky, const char *name)
{
	size_t len;

	len = strlen(name);
	if (len == 0 || len > STICKY_NAME_MAXLEN) {
		T_WARN_NL("http_sess: invalid cookie name length: %zu (1..%d)\n",
			  len, STICKY_NAME_MAXLEN);
		return -EINVAL;
	}
	memcpy(sticky->sticky_name, name, len);
	sticky->sticky_name[len] = '=';
	sticky->name.data = sticky->sticky_name;
	sticky->name.len = len;
	sticky->name_eq.data = sticky->sticky_name;
	sticky->name_eq.len = len + 1;

	return 0;
}

static int
tfw_cfgop_cookie_set(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	size_t i;
	int r;
	const char *key, *val, *name_val = STICKY_NAME_DEFAULT;
	TfwStickyCookie *sticky;
	bool was_max_misses = false, was_name = false;

	if (!cur_vhost) {
		sticky = &defaults_override.sticky;
		defaults_override.cookie_set = 1;
	}
	else {
		sticky = cur_vhost->cookie;
	}

	if (!TFW_STR_EMPTY(&sticky->name)) {
		T_ERR_NL("http_sess: 'cookie' and 'learn' directives "
			 "can't be used at the same time\n");
		return -EINVAL;
	}

	TFW_CFG_ENTRY_FOR_EACH_ATTR(ce, i, key, val) {
		if (!strcasecmp(key, "name")) {
			TFW_CFG_CHECK_VAL_DUP(key, was_name, {
				return -EINVAL;
			})
			name_val = val;
		} else if (!strcasecmp(key, "max_misses")) {
			TFW_CFG_CHECK_VAL_DUP(key, was_max_misses, {
				return -EINVAL;
			})
			if (tfw_cfg_parse_uint(val, &sticky->max_misses))
			{
				T_ERR_NL("%s: invalid value for 'max_misses'"
					 " attribute: '%s'\n", cs->name, val);
				return -EINVAL;
			}
		} else {
			T_ERR_NL("%s: unsupported attribute: '%s=%s'.\n",
				 cs->name, key, val);
			return -EINVAL;
		}
	}

	if ((r = __tfw_cfgop_cookie_set_name(sticky, name_val)))
		return r;

	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, val) {
		if (!strcasecmp(val, "enforce")) {
			sticky->enforce = 1;
			if (!was_max_misses)
				sticky->max_misses = 1;
		} else {
			T_ERR_NL("%s: unsupported argument: '%s'\n",
				 cs->name, val);
			return -EINVAL;
		}
	}

	if (sticky->max_misses && !sticky->enforce) {
		T_ERR_NL("%s: 'max_misses' can be enabled only in 'enforce' "
			 "mode\n", cs->name);
		return -EINVAL;
	}

	return 0;
}

static int
tfw_cfgop_cookie_options_set(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	size_t i;
	int r;
	const char *key, *val;
	TfwStickyCookie *sticky = NULL;
	bool was_path = false, was_max_age = false, was_expires = false;

	if (!cur_vhost) {
		sticky = &defaults_override.sticky;
	}
	else {
		sticky = cur_vhost->cookie;
	}

	TFW_CFG_ENTRY_FOR_EACH_ATTR(ce, i, key, val) {
		if (!strcasecmp(key, "Path")) {
			TFW_CFG_CHECK_VAL_DUP(key, was_path, {
				return -EINVAL;
			})
		} else if (!strcasecmp(key, "Max-Age")) {
			TFW_CFG_CHECK_VAL_DUP(key, was_max_age, {
				return -EINVAL;
			})
		} else if (!strcasecmp(key, "Expires")) {
			TFW_CFG_CHECK_VAL_DUP(key, was_expires, {
				return -EINVAL;
			})
		}
		if ((r = tfw_cfgop_cookie_set_option(sticky, key, val)))
			return r;
	}

	if (!was_path) {
		if ((r = tfw_cfgop_cookie_set_option(sticky, "Path", "/")))
			return r;
	}
	if (was_max_age || was_expires)
		sticky->expires = true;

	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, key) {
		if ((r = tfw_cfgop_cookie_set_option(sticky, key, NULL)))
			return r;
	}

	return 0;
}

static int
tfw_cfgop_cookie_learn(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	size_t i;
	int r;
	const char *key, *val, *name_val = NULL;
	bool was_name_val = false;
	TfwStickyCookie *sticky;

	if (!cur_vhost) {
		sticky = &defaults_override.sticky;
		defaults_override.learn_set = 1;
	}
	else {
		sticky = cur_vhost->cookie;
	}

	if (!TFW_STR_EMPTY(&sticky->name)) {
		T_ERR_NL("http_sess: 'cookie' and 'learn' directives "
			 "can't be used at the same time\n");
		return -EINVAL;
	}

	if (ce->val_n) {
		T_ERR_NL("%s: no arguments allowed\n", cs->name);
		return -EINVAL;
	}
	TFW_CFG_ENTRY_FOR_EACH_ATTR(ce, i, key, val) {
		if (!strcasecmp(key, "name")) {
			TFW_CFG_CHECK_VAL_DUP(key, was_name_val, {
				return -EINVAL;
			})
			name_val = val;
		} else {
			T_ERR_NL("%s: unsupported attribute: '%s=%s'.\n",
				 cs->name, key, val);
			return -EINVAL;
		}
	}
	if (!name_val) {
		T_ERR_NL("http_sess: attribute 'name' for directive '%s' is "
			 "mandatory\n", cs->name);
		return -EINVAL;
	}

	if ((r = __tfw_cfgop_cookie_set_name(sticky, name_val)))
		return r;
	sticky->learn = 1;
	/*
	 * Unlike native TempestaFW cookies, the 'learn' directive has only one
	 * purpose: LB stickiness. It doesn't challenge the client, session
	 * failovering algorithm is also meaningless for the 'learn' mode.
	 * So enable the only usable stickiness mode.
	 * */
	__set_bit(TFW_VHOST_B_STICKY_SESS, (cur_vhost
					    ? &cur_vhost->flags
					    : &defaults_override.vhost_flags));

	return 0;
}

static void
tfw_cfgop_sticky_sess_inherit(unsigned long *flags)
{
	unsigned long nrs[] = {TFW_VHOST_B_STICKY_SESS,
			       TFW_VHOST_B_STICKY_SESS_FAILOVER};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(nrs); i++) {
		if (test_bit(nrs[i], &defaults_override.vhost_flags))
			__set_bit(nrs[i], flags);
		else
			__clear_bit(nrs[i], flags);
	}
}

static inline int
tfw_cfgop_sticky_sess_set(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	unsigned long *flags;

	TFW_CFG_CHECK_NO_ATTRS(cs, ce);
	TFW_CFG_CHECK_VAL_N(<=, 1, cs, ce);

	if (cur_vhost) {
		flags =  &cur_vhost->flags;
	} else {
		flags = &defaults_override.vhost_flags;
		defaults_override.st_sessions_set = 1;
	}

	if (!tfw_cfg_is_dflt_value(ce)) {
		if (!ce->val_n) {
			__set_bit(TFW_VHOST_B_STICKY_SESS, flags);
		} else if (!strcasecmp(ce->vals[0], "allow_failover")) {
			__set_bit(TFW_VHOST_B_STICKY_SESS, flags);
			__set_bit(TFW_VHOST_B_STICKY_SESS_FAILOVER, flags);
		} else {
			T_ERR_NL("Unsupported argument: %s\n", ce->vals[0]);
			return  -EINVAL;
		}

		return 0;
	}

	if (!cur_vhost || !defaults_override.st_sessions_set) {
		__clear_bit(TFW_VHOST_B_STICKY_SESS, flags);
		__clear_bit(TFW_VHOST_B_STICKY_SESS_FAILOVER, flags);
	} else {
		tfw_cfgop_sticky_sess_inherit(flags);
	}

	return 0;
}

static int
tfw_cfgop_sess_lifetime(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;
	int int_val = 0;
	TfwStickyCookie *sticky = cur_vhost ? cur_vhost->cookie
					    : &defaults_override.sticky;

	if (tfw_cfg_is_dflt_value(ce)) {
		if (!cur_vhost)
			return 0;
		if (defaults_override.lifetime_set) {
			sticky->sess_lifetime =
					defaults_override.sticky.sess_lifetime;
			return 0;
		}

	}

	cs->dest = &int_val;
	r = tfw_cfg_set_int(cs, ce);
	cs->dest = NULL;
	if (r)
		return r;
	/*
	 * "sess_lifetime 0;" means unlimited session lifetime,
	 * set tfw_cfg_sticky.sess_lifetime to maximum value.
	*/
	sticky->sess_lifetime = int_val ? : UINT_MAX;

	if (!cur_vhost)
		defaults_override.lifetime_set = 1;

	return 0;
}

static int
tfw_cfgop_sticky_secret_set(TfwStickyCookie *sticky, const char *secret_str,
			    unsigned int len)
{
	char secret[SHA1_DIGEST_SIZE];
	const char *secret_buf;
	int r;

	sticky->shash = crypto_alloc_shash("hmac(sha1)", 0, 0);
	if (IS_ERR(sticky->shash)) {
		T_ERR_NL("http_sess: shash allocation failed\n");
		r = (int)PTR_ERR(sticky->shash);
		sticky->shash = NULL;
		return r;
	}

	if (!len) {
		tfw_get_random_bytes(secret, sizeof(secret));
		len = sizeof(secret);
		secret_buf = secret;
	}
	else {
		secret_buf = secret_str;
	}

	r = crypto_shash_setkey(sticky->shash, secret_buf, len);
	if (r)
		T_ERR_NL("http_sess: can't set shash secret key");
	memset(secret, 0, sizeof(secret));

	return r;
}

/**
 * Configure sticky secret. If default value is given, then inherit secret
 * string from the @defaults_override.
 */
static int
tfw_cfgop_sticky_secret(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	unsigned int len = (unsigned int)strlen(ce->vals[0]);
	TfwStickyCookie *sticky;
	const char *secret = ce->vals[0];

	if (tfw_cfg_check_single_val(ce))
		return -EINVAL;

	if (!cur_vhost) {
		if (tfw_cfg_is_dflt_value(ce))
			return 0;
		sticky = &defaults_override.sticky;

		if (len >= sizeof(defaults_override.secret))
			T_WARN_NL("http_sess: too long secret string, can't"
				  "override default random value\n");
		else
			strcpy(defaults_override.secret, ce->vals[0]);
	}
	else {
		if (tfw_cfg_is_dflt_value(ce)) {
			secret = defaults_override.secret;
			len = strlen(secret);
		}
		sticky = cur_vhost->cookie;
	}

	return tfw_cfgop_sticky_secret_set(sticky, secret, len);
}

static inline int
tfw_cfgop_jsch_parse(TfwCfgSpec *cs, const char *key, const char *val,
		     unsigned int *uint_val)
{
	int r;

	if ((r = tfw_cfg_parse_uint(val, uint_val))) {
		T_ERR_NL("%s: can't parse key '%s'\n", cs->name, key);
		return r;
	}

	return 0;
}

static int
tfw_cfgop_jsch_parse_resp_code(TfwCfgSpec *cs, TfwCfgJsCh *js_ch,
			       const char *val)
{
	int r, int_val;
	size_t len;

	if ((r = tfw_cfg_parse_int(val, &int_val))) {
		T_ERR_NL("%s: can't parse key 'resp_code'\n", cs->name);
		return r;
	}
	if (!tfw_http_resp_status_line(int_val, &len)) {
		T_ERR_NL("%d is disallowed js challenge resp status code",
			 int_val);
		return -EINVAL;
	}
	js_ch->st_code = int_val;

	return 0;
}

static int
tfw_cfgop_jsch_set_body(TfwCfgSpec *cs, TfwCfgJsCh *js_ch, const char *script)
{
	char *body_data;
	size_t sz;
	char *rbegin, *rend, *p;
	int r;

	body_data = tfw_http_msg_body_dup(script, &sz);
	if (!body_data)
		return -ENOMEM;
	if ((p = strstr(body_data, "TFW_DONT_CHANGE_NAME"))) {
		if (!(rbegin = strchr(p, '"') + 1))
			goto err;
		if (!(rend = strchr(rbegin, '"')))
			goto err;
	} else {
		r = -EINVAL;
		goto err;
	}
	js_ch->body.chunks = tfw_kzalloc(sizeof(TfwStr) * 2, GFP_KERNEL);
	if (!js_ch->body.chunks) {
		r = -ENOMEM;
		goto err;
	}

	js_ch->body.chunks[0] = (TfwStr) { .data = body_data,
	                                   .len = rbegin - body_data};
	js_ch->body.chunks[1] = (TfwStr) { .data = rend,
	                                   .len = body_data + sz - rend };
	js_ch->body.len = js_ch->body.chunks[0].len + js_ch->body.chunks[1].len;
	js_ch->body.nchunks = 2;

	return 0;

err:
	T_ERR_NL("%s: can't find TFW_DONT_CHANGE_NAME in JS challenge script\n",
	         cs->name);
	free_pages((unsigned long)body_data, get_order(sz));
	return r;
}

static int
tfw_cfgop_js_challenge(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	unsigned int uint_val;
	int i, r;
	const char *key, *val;
	TfwCfgJsCh *js_ch;
	bool was_delay_min = false, was_delay_range=false, was_resp_code=false;

	js_ch = tfw_kzalloc(sizeof(TfwCfgJsCh), GFP_KERNEL);
	if (!js_ch) {
		T_ERR_NL("%s: can't allocate memory for JS challenge\n", cs->name);
		return -ENOMEM;
	}

	if (ce->val_n > 1) {
		T_ERR_NL("invalid number of values; 1 possible, got: %zu\n",
			 ce->val_n);
		r = -EINVAL;
		goto err;
	}
	TFW_CFG_ENTRY_FOR_EACH_ATTR(ce, i, key, val) {
		if (!strcasecmp(key, "delay_min")) {
			TFW_CFG_CHECK_VAL_DUP(key, was_delay_min, {
				r= -EINVAL;
				goto err;
			})
			if ((r = tfw_cfgop_jsch_parse(cs, key, val, &uint_val)))
				goto err;
			js_ch->delay_min = msecs_to_jiffies(uint_val);
		} else if (!strcasecmp(key, "delay_range")) {
			TFW_CFG_CHECK_VAL_DUP(key, was_delay_range, {
				r= -EINVAL;
				goto err;
			})
			if ((r = tfw_cfgop_jsch_parse(cs, key, val, &uint_val)))
				goto err;
			js_ch->delay_range = uint_val;
		} else if (!strcasecmp(key, "resp_code")) {
			TFW_CFG_CHECK_VAL_DUP(key, was_resp_code, {
				r= -EINVAL;
				goto err;
			})
			if ((r = tfw_cfgop_jsch_parse_resp_code(cs, js_ch, val)))
				goto err;
		} else {
			T_ERR_NL("%s: unsupported attribute: '%s=%s'.\n",
				 cs->name, key, val);
			r = -EINVAL;
			goto err;
		}
	}
	if (!js_ch->delay_min) {
		T_ERR_NL("%s: required argument 'delay_min' not set.\n",
			 cs->name);
		r = -EINVAL;
		goto err;
	}
	if (!js_ch->delay_range) {
		T_ERR_NL("%s: required argument 'delay_range' not set.\n",
			 cs->name);
		r = -EINVAL;
		goto err;
	}
	if (!js_ch->st_code)
		js_ch->st_code = tfw_cfg_jsch_code_dflt;

	r = tfw_cfgop_jsch_set_body(cs, js_ch,
				    ce->val_n ? ce->vals[0] : TFW_CFG_JS_PATH);
	if (r)
		goto err;

	refcount_set(&js_ch->users, 1);
	if (cur_vhost)
		cur_vhost->cookie->js_challenge = js_ch;
	else
		defaults_override.sticky.js_challenge = js_ch;

	return 0;
err:
	kfree(js_ch);

	return r;
}

/**
 * Initialize cookie options if the @vhost has no explicit 'sticky' section.
 */
int
tfw_http_sess_cfg_finish(TfwVhost *vhost)
{
	TfwStickyCookie *sticky = vhost->cookie;
	int r;

	if (WARN_ON_ONCE(!sticky))
		return -EINVAL;
	/* 'sticky' section was explicitly defined. */
	if (!TFW_STR_EMPTY(&sticky->name))
		goto set_expires;
	if (tfw_vhost_is_default(vhost)
	    && (r = __tfw_http_sess_cfgop_begin(sticky)))
	{
		return r;
	}
	/* Inherit sticky options defined at top level. */
	if ((r = tfw_cfgop_sticky_inherit(vhost)))
		return r;

	/*
	 * tfw_cfgop_sticky_inherit() only setups directives without
	 * default values in  tfw_http_sess_specs, init others.
	 */
	if (defaults_override.st_sessions_set)
		tfw_cfgop_sticky_sess_inherit(&vhost->flags);
	if (!TFW_STR_EMPTY(&sticky->name)) {
		r = tfw_cfgop_sticky_secret_set(sticky,
						defaults_override.secret,
						strlen(defaults_override.secret));
		if (r)
			return r;
	}
	sticky->sess_lifetime = defaults_override.lifetime_set
			? defaults_override.sticky.sess_lifetime
			: UINT_MAX;

set_expires:
	/*
	 * If expires flag is not set, this means that no Max-Age and
	 * no Expires options are present for this cookie. We set
	 * Max-Age according session lifetime to prevent usage expired
	 * cookies by client.
	 */
	if (!sticky->expires) {
		char max_age[STICKY_OPT_MAXLEN];
		if ((r = snprintf(max_age, sizeof(max_age), "%u",
		    sticky->sess_lifetime)) < 0)
			return r;
		if ((r = tfw_cfgop_cookie_set_option(sticky, "Max-Age", max_age)))
			return r;
	}

	return 0;
}

/**
 * Setup default settings storage before use: if last configuration has failed,
 * defaults may contain values from the previous configuration attempt.
 */
void
tfw_http_sess_cfgstart()
{
	tfw_http_sess_cfg_defaults_reset();
}

/**
 * Overridden default values has some parts that are dynamically allocated.
 * Need to free them after configuration processing and before shutdown,
 * since cfgend() hook is not called for failed configurations.
 */
void
tfw_http_sess_cfgend()
{
	tfw_http_sess_cfg_defaults_reset();
}

TfwCfgSpec tfw_http_sess_specs[] = {
	{
		.name = "cookie",
		.handler = tfw_cfgop_cookie_set,
		.allow_none = true,
		.allow_reconfig = true,
	},
	{
		.name = "cookie_options",
		.handler = tfw_cfgop_cookie_options_set,
		.allow_none = true,
		.allow_reconfig = true,
	},
	{
		.name = "learn",
		.handler = tfw_cfgop_cookie_learn,
		.allow_none = true,
		.allow_reconfig = true,
	},
	{
		.name = "sticky_sessions",
		.deflt = "off",
		.handler = tfw_cfgop_sticky_sess_set,
		.allow_none = true,
		.allow_reconfig = true,
	},
	{
		.name = "secret",
		.deflt = "\"\"",
		.handler = tfw_cfgop_sticky_secret,
		.allow_none = true,
		.allow_reconfig = true,
	},
	{
		/* Value is parsed as int, set max to INT_MAX*/
		.name = "sess_lifetime",
		.deflt = "0",
		.handler = tfw_cfgop_sess_lifetime,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, INT_MAX },
		},
		.allow_none = true,
		.allow_reconfig = true,
	},
	{
		.name = "js_challenge",
		.handler = tfw_cfgop_js_challenge,
		.allow_none = true,
		.allow_reconfig = true,
	},
	{ 0 }
};
