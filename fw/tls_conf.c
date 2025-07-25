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
#include "tls_conf.h"
#include "tls.h"
#include "vhost.h"

#define TFW_TLS_CFG_F_EMPY	0U
#define TFW_TLS_CFG_F_CERT	1U
#define TFW_TLS_CFG_F_CKEY	2U

#define TLS_CONF_CERT_NUM	8

typedef struct {
	TlsX509Crt	crt;
	TlsPkCtx	key;
	unsigned int	conf_stage;
} TlsCertConf;

typedef struct {
	TlsCertConf	certs[TLS_CONF_CERT_NUM];
	unsigned int	certs_num;
	unsigned int	init_done:1;
} TlsConfEntry;

size_t tfw_tls_vhost_priv_data_sz(void)
{
	return sizeof(TlsConfEntry);
}

static int
tfw_tls_peer_tls_init(TfwVhost *vhost)
{
	TlsConfEntry *conf = vhost->tls_cfg.priv;
	int r;

	if (conf->init_done)
		return 0;

	if ((r = ttls_config_peer_defaults(&vhost->tls_cfg, TTLS_IS_SERVER)))
		return r;
	conf->init_done = 1;

	return 0;
}

static inline TlsCertConf *
tfw_tls_get_cert_conf(TfwVhost *vhost, unsigned int directive)
{
	TlsConfEntry *conf = vhost->tls_cfg.priv;
	TlsCertConf *curr_cert_conf;

	if (conf->certs_num >= TLS_CONF_CERT_NUM) {
		T_WARN_NL("Too many certificates defined!\n");
		return NULL;
	}

	curr_cert_conf = &conf->certs[conf->certs_num];
	switch (directive) {
	case TFW_TLS_CFG_F_CERT:
		if (curr_cert_conf->conf_stage & TFW_TLS_CFG_F_CERT) {
			T_WARN_NL("'tls_certificate_key' directive was"
				  " expected, but 'tls_certificate' was"
				  " found first.\n");
			curr_cert_conf = NULL;
		}
		break;

	case TFW_TLS_CFG_F_CKEY:
		if (!(curr_cert_conf->conf_stage & TFW_TLS_CFG_F_CERT)) {
			T_WARN_NL("'tls_certificate_key' directive was found"
				  " before 'tls_certificate' has encountered."
				  "\n");
			curr_cert_conf = NULL;
			break;
		}
		if (curr_cert_conf->conf_stage & TFW_TLS_CFG_F_CKEY) {
			T_WARN_NL("'tls_certificate_key' directive was found"
				  " twice for the same 'tls_certificate'"
				  " directive.\n");
			curr_cert_conf = NULL;
			break;
		}
		break;

	default:
		BUG();
	}
	if (curr_cert_conf)
		curr_cert_conf->conf_stage |= directive;

	return curr_cert_conf;
}

/**
 * Validate the vhost name @hname against all SANs from the certificate and
 * add the SANs for fast matching against SNI in run-time.
 *
 * @a_vhost is a pointer to the TfwVhost.
 */
static int
tfw_tls_add_cn(const ttls_x509_buf *sname, void *a_vhost)
{
	int r = -EINVAL;
	TfwVhost *vhost = a_vhost;
	const char *hname = vhost->name.data;
	int hlen = vhost->name.len;
	/* cn-pointed data isn't modified, so just a type compatibility. */
	BasicStr cn = {.data = (char *)sname->p, .len = sname->len};

	/*
	 * Try wildcard match by RFC 2818 3.1:
	 *
	 *   Names may contain the wildcard character * which is considered to
	 *   match any single domain name component or component fragment.
	 *   E.g., *.a.com matches foo.a.com but not bar.foo.a.com. f*.com
	 *   matches foo.com but not bar.com.
	 *
	 * A vhost a.org may use certificate with SAN like
	 *
	 *   a.org *.a.org www.beta.a.org www.wiki.a.org
	 *
	 * all the SNIs must be matched with the vhost. Moreover, there could be
	 * configured 2 vhosts, e.g. wiki.a.org and www.a.org with the
	 * certificate. In this case there is SAN/CN name collision and we
	 * suppose that any such collision happens on the same certificate only.
	 */
	if (sname->len >= 3 && sname->p[0] == '*' && sname->p[1] == '.') {
		char *p = strchr(hname, '.');

		/* Return 0 if the wildcard CN matches the host name. */
		if (p && sname->len - 1 == hname + hlen - p
		    && !strncasecmp(sname->p + 1, p, sname->len - 1))
			r = 0;

		/*
		 * Add the chopped (w/o leading '*') wildcard to
		 * the SNI mapping.
		 */
		cn.data = (char *)sname->p + 1;
		cn.len = sname->len - 1;
	}

	/*
	 * Add the full SAN/CN entry or chopped wildcard (e.g. ".a.org" for
	 * "*.a.org") for SNI resolving into the vhost name.
	 */
	tfw_vhost_add_sni_map(&cn, vhost);

	return r;
}

/**
 * Handle 'tls_certificate <path>' config entry.
 */
int
tfw_tls_set_cert(TfwVhost *vhost, TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;
	unsigned char *crt_data;
	size_t crt_size;
	TlsCertConf *conf;
	uint32_t flags;

	BUG_ON(!vhost->tls_cfg.priv);
	if ((r = tfw_tls_peer_tls_init(vhost)))
		return r;
	if (!(conf = tfw_tls_get_cert_conf(vhost, TFW_TLS_CFG_F_CERT)))
		return -EINVAL;

	if (tfw_cfg_check_single_val(ce))
		return -EINVAL;

	crt_data = tfw_cfg_read_file(ce->vals[0], &crt_size);
	if (!crt_data) {
		T_ERR_NL("%s: Can't read certificate file '%s'\n",
			 ce->name, ce->vals[0]);
		return -EINVAL;
	}

	ttls_x509_crt_init(&conf->crt);
	r = ttls_x509_crt_parse(&conf->crt, crt_data, crt_size);
	if (r) {
		T_ERR_NL("%s: Invalid certificate specified, err=%x\n",
			 cs->name, -r);
		goto err;
	}

	/* Do simple check, because we don't have private key at this moment. */
	if ((flags = ttls_x509_check_cert_validity(&conf->crt))) {
		if (flags & TTLS_X509_BADCERT_EXPIRED)
			T_WARN("The certificate '%s' has expired! Please renew\n"
			       "the certificate to maintain functionality.",
			       ce->vals[0]);

		if (flags & TTLS_X509_BADCERT_FUTURE)
			T_WARN("The certificate %s is not yet valid. Please\n"
			       "ensure the correct certificate is in use.",
			       ce->vals[0]);
	}

	if (ttls_x509_process_san(&conf->crt, tfw_tls_add_cn, vhost)) {
		/* None of the SANs match the vhost. */
		T_WARN("Vhost %s doesn't have certificate with matching SAN/CN.\n"
		       "    Maybe that's fine, but it's worth checking the\n"
		       "    config - if there is no relations between the\n"
		       "    names, then host name confusion attack is possible.\n",
		       vhost->name.data);
	}

err:
	kfree(crt_data);

	return r;
}

static int
tfw_tls_cert_cfg_finish_cert(TfwVhost *vhost)
{
	TlsConfEntry *conf_entry = vhost->tls_cfg.priv;
	TlsCertConf *conf = &conf_entry->certs[conf_entry->certs_num];
	int r;

	r = ttls_conf_own_cert(&vhost->tls_cfg, &conf->crt, &conf->key,
			       conf->crt.next, NULL);
	if (r) {
		T_ERR_NL("TLS: can't set own certificate (%x)\n", r);
		return -EINVAL;
	}
	conf_entry->certs_num++;

	return 0;
}

/**
 * Handle 'tls_certificate_key <path>' config entry.
 *
 * TODO #67: At the moment `tls_certificate_key` always follow
 * `tls_certificate`, so at this place we have both the pair of the certificate
 * and private key initialized and can generate necessary MPI profiles.
 * The limitation on the directives order may be inconvenient for a user, so
 * this should be redesigned. Meantime, probably with the new API this won't be
 * an issue at all, TBD.
 */
int
tfw_tls_set_cert_key(TfwVhost *vhost, TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;
	void *key_data;
	size_t key_size;
	TlsCertConf *conf;

	BUG_ON(!vhost->tls_cfg.priv);
	if (tfw_cfg_check_single_val(ce))
		return -EINVAL;
	if (!(conf = tfw_tls_get_cert_conf(vhost, TFW_TLS_CFG_F_CKEY)))
		return -EINVAL;

	ttls_pk_init(&conf->key);

	key_data = tfw_cfg_read_file(ce->vals[0], &key_size);
	if (!key_data) {
		T_ERR_NL("%s: Can't read certificate file '%s'\n",
			 ce->name, ce->vals[0]);
		return -EINVAL;
	}

	r = ttls_pk_parse_key(&conf->key, key_data, key_size);
	/* The key is copied, so free the paged data. */
	kfree(key_data);
	if (r) {
		T_ERR_NL("%s: Invalid private key specified (%x)\n",
			 cs->name, -r);
		return -EINVAL;
	}

	return tfw_tls_cert_cfg_finish_cert(vhost);
}

int
tfw_tls_cert_cfg_finish(TfwVhost *vhost)
{
	TlsConfEntry *conf = vhost->tls_cfg.priv;
	TlsCertConf *curr_cert_conf;

	BUG_ON(!vhost->tls_cfg.priv);
	if (conf->certs_num)
		tfw_tls_cfg_configured(tfw_vhost_is_default_reconfig(vhost));
	if (conf->certs_num >= TLS_CONF_CERT_NUM)
		return 0;
	curr_cert_conf = &conf->certs[conf->certs_num];
	if (curr_cert_conf->conf_stage) {
		T_ERR_NL("TLS: certificate configuration is not done, "
			 "directive 'tls_certificate_key' is missing.\n");
		return -EINVAL;
	}

	return 0;
}

static void
tfw_tls_cleanup_tls_cert(TlsCertConf *conf)
{
	if (!(conf->conf_stage & TFW_TLS_CFG_F_CERT))
		return;
	ttls_x509_crt_free(&conf->crt);
}

static void
tfw_tls_cleanup_tls_ckey(TlsCertConf *conf)
{
	if (!(conf->conf_stage & TFW_TLS_CFG_F_CKEY))
		return;
	ttls_pk_free(&conf->key);
}

void
tfw_tls_cert_clean(TfwVhost *vhost)
{
	TlsConfEntry *conf = vhost->tls_cfg.priv;
	int i;

	ttls_key_cert_free(vhost->tls_cfg.key_cert);
	for (i = 0; i < TLS_CONF_CERT_NUM; i++) {
		TlsCertConf *cconf = &conf->certs[i];

		tfw_tls_cleanup_tls_cert(cconf);
		tfw_tls_cleanup_tls_ckey(cconf);
	}
	ttls_config_peer_free(&vhost->tls_cfg);
}

int
tfw_tls_set_tickets(TfwVhost *vhost, TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	bool enabled = true;
	const char *secret = NULL;
	size_t secret_len = 0;
	unsigned long lifetime = 0;
	TfwCfgEntry ce_tmp;
	const char *key, *val;
	int i, r;
	bool was_secret = false, was_lifetime=false;

	if ((r = tfw_tls_peer_tls_init(vhost)))
		return r;

	if (ce->have_children) {
		T_ERR_NL("%s: nested settings not allowed!\n", cs->name);
		return -EINVAL;
	}
	/*
	 * Tickets are by default enabled, unless user has switched them off,
	 * parse enable/disable value first and ignore all attributes.
	 */
	ce_tmp = *ce;
	ce_tmp.attr_n = 0;
	cs->dest = &enabled;
	if (tfw_cfg_set_bool(cs, &ce_tmp)) {
		T_ERR_NL("%s: can't parse positional values!\n", cs->name);
		cs->dest = NULL;
		return -EINVAL;
	}
	cs->dest = NULL;
	if (enabled) {
		TFW_CFG_ENTRY_FOR_EACH_ATTR(ce, i, key, val) {
			if (!strcasecmp(key, "secret")) {
				TFW_CFG_CHECK_VAL_DUP(key, was_secret, {
					return -EINVAL;
				})
				secret = val;
				secret_len = strlen(val);
			} else if (!strcasecmp(key, "lifetime")) {
				TFW_CFG_CHECK_VAL_DUP(key, was_lifetime, {
					return -EINVAL;
				})
				if ((r = tfw_cfg_parse_long(val, &lifetime))) {
					T_ERR_NL("%s: can't parse '%s' argument!"
						 "\n", cs->name, key);
					return r;
				}
				if (lifetime > 5 * TTLS_DEFAULT_TICKET_LIFETIME)
					T_WARN_NL("%s: setting too long ticket"
						  "lifetime can be insecure, "
						  "recommended value is %d\n",
						  cs->name,
						  TTLS_DEFAULT_TICKET_LIFETIME);
			} else {
				T_ERR_NL("%s: unsupported argument: '%s=%s'.\n",
					 cs->name, key, val);
				return -EINVAL;
			}
		}
	}

	return ttls_conf_tickets(&vhost->tls_cfg, enabled, lifetime, secret,
				 secret_len, vhost->name.data, vhost->name.len);
}
