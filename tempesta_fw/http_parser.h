/**
 *		Tempesta FW
 *
 * Copyright (C) 2018 Tempesta Technologies, Inc.
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
#ifndef __TFW_HTTP_PARSER_H__
#define __TFW_HTTP_PARSER_H__

void tfw_http_init_parser_req(TfwHttpReq *req);
void tfw_http_init_parser_resp(TfwHttpResp *resp);
int tfw_http_parse_req(void *req_data, unsigned char *data, size_t len);
int tfw_http_parse_resp(void *resp_data, unsigned char *data, size_t len);
bool tfw_http_parse_terminate(TfwHttpMsg *hm);

#endif /* __TFW_HTTP_PARSER_H__ */
