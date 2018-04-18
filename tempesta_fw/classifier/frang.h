/**
 *		Tempesta FW
 *
 * Copyright (C) 2016-2018 Tempesta Technologies, Inc.
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
#ifndef __TFW_FRANG_H__
#define __TFW_FRANG_H__

/**
 * Response code block setting
 *
 * @codes	- Response code bitmap;
 * @limit	- Quantity of allowed responses in a time frame;
 * @tf		- Time frame in seconds;
 */
typedef struct {
	DECLARE_BITMAP(codes, 512);
	unsigned short	limit;
	unsigned short	tf;
} FrangHttpRespCodeBlock;

typedef struct {
	char   *str;
	size_t len;	/* The pre-computed strlen(@str). */
} FrangCtVal;

typedef struct frang_cfg_t FrangCfg;

struct frang_cfg_t {
	/* Limits (zero means unlimited). */
	unsigned int		req_rate;
	unsigned int		req_burst;
	unsigned int		conn_rate;
	unsigned int		conn_burst;
	unsigned int		conn_max;

	/*
	 * Limits on time it takes to receive
	 * a full header or a body chunk.
	 */
	unsigned long		clnt_hdr_timeout;
	unsigned long		clnt_body_timeout;

	/* Limits for HTTP request contents: uri, headers, body, etc. */
	unsigned int		http_uri_len;
	unsigned int		http_field_len;
	unsigned int		http_body_len;
	unsigned int		http_hchunk_cnt;
	unsigned int		http_bchunk_cnt;
	unsigned int		http_hdr_cnt;
	bool			http_ct_required;
	bool			http_host_required;

	bool			ip_block;

	/* The bitmask of allowed HTTP Method values. */
	unsigned long		http_methods_mask;
	/* The list of allowed Content-Type values. */
	FrangCtVal		*http_ct_vals;
	FrangHttpRespCodeBlock	*http_resp_code_block;
};

#endif /* __TFW_FRANG_H__ */
