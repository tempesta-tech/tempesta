/**
 *		Tempesta FW
 *
 * Copyright (C) 2019-2020 Tempesta Technologies, Inc.
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
	unsigned long	crt_pg_addr;
	unsigned int	crt_pg_order;
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
 * Handle 'tls_certificate <path>' config entry.
 */
int
tfw_tls_set_cert(TfwVhost *vhost, TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;
	unsigned char *crt_data;
	size_t crt_size;
	TlsCertConf *conf;

	BUG_ON(!vhost->tls_cfg.priv);
	if ((r = tfw_tls_peer_tls_init(vhost)))
		return r;
	if (!(conf = tfw_tls_get_cert_conf(vhost, TFW_TLS_CFG_F_CERT)))
		return -EINVAL;

	if (tfw_cfg_check_single_val(ce))
		return -EINVAL;

	ttls_x509_crt_init(&conf->crt);
	/* Preserve 3 bytes for the certificate length. */
	crt_data = tfw_cfg_read_file(ce->vals[0], &crt_size, TTLS_CERT_LEN_LEN);
	if (!crt_data) {
		T_ERR_NL("%s: Can't read certificate file '%s'\n",
			 ce->name, ce->vals[0]);
		return -EINVAL;
	}

	r = ttls_x509_crt_parse(&conf->crt, crt_data + TTLS_CERT_LEN_LEN,
				crt_size);
	if (r) {
		T_ERR_NL("%s: Invalid certificate specified (%x)\n",
			 cs->name, -r);
		free_pages((unsigned long)crt_data, get_order(crt_size));
		return -EINVAL;
	}
	ttls_x509_write_cert_len(&conf->crt, crt_data);

	conf->crt_pg_addr = (unsigned long)crt_data;
	conf->crt_pg_order = get_order(crt_size);

	return 0;
}

int
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

	key_data = tfw_cfg_read_file(ce->vals[0], &key_size, 0);
	if (!key_data) {
		T_ERR_NL("%s: Can't read certificate file '%s'\n",
			 ce->name, ce->vals[0]);
		return -EINVAL;
	}

	r = ttls_pk_parse_key(&conf->key, key_data, key_size);
	/* The key is copied, so free the paged data. */
	free_pages((unsigned long)key_data, get_order(key_size));
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
			 "directive 'tls_certificate_key' is missing. \n");
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
	free_pages(conf->crt_pg_addr, conf->crt_pg_order);
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
				secret = val;
				secret_len = strlen(val);
			} else if (!strcasecmp(key, "lifetime")) {
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
