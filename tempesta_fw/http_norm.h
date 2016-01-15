/**
 *		Tempesta FW
 *
 * Definitions of HTTP Normalization logic.
 *
 * Normalization logic is expensive, but is still performance critical. So it
 * should be built-in to the HTTP parser while still be plugable. Also it's
 * good to be able to easy change the logic and perform normalization depending
 * on back-end server personalities.
 *
 * So we directly redefine common HTTP FSM label in http_norm_hooks.h that
 * they jump here, where we have additional normalization logic.
 * This makes normalization logic very fast, but still flexible.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#ifndef __TFW_HTTP_NORM_H__
#define __TFW_HTTP_NORM_H__

/* Switch on/off whole normalization logic. */
#ifdef TFW_HTTP_NORMALIZATION

/*
 * Do URI normalization according to RFC 3986
 * (see example from RFC 2616 3.2.3.
 */
#ifdef TFW_HTTP_NORM_URI

TFW_HTTP_STATE(Req_UriNorm) {
	/* empty for now */
}

#endif /* TFW_HTTP_NORM_URI */

/* Do POST body/arguments normalization. */
#ifdef TFW_HTTP_NORM_POST

TFW_HTTP_STATE(Req_PostNorm) {
	/* empty for now */
}

#endif /* TFW_HTTP_NORM_POST */

/* Do response body normalization. */
#ifdef TFW_HTTP_NORM_RESP

TFW_HTTP_STATE(Resp_BodyNorm) {
	/* empty for now */
}

#endif /* TFW_HTTP_NORM_RESP */

#endif /* TFW_HTTP_NORMALIZATION */

#endif /* __TFW_HTTP_NORM_H__ */
