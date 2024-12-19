/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2022 Tempesta Technologies, Inc.
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
#ifndef __TFW_H1_DEFS__
#define __TFW_H1_DEFS__

/* http1 tests parts count */
#define H1_CT_BODYLESS_TCNT	4
#define H1_CT_LINE_PARSER_TCNT	4
#define H1_DATE_PARSE_TCNT	5
#define H1_FWD_TCNT		4

#define H1_SUITE_PART_CNT	4

/* http2 tests parts count */
#define H2_CT_BODYLESS_TCNT	3
#define H2_FWD_TCNT		4
#define H2_ACCEPT_TCNT		4
#define H2_HOST_TCNT		4
#define H2_CC_TCNT		5
#define H2_DATE_FMT_TCNT	2

#define H2_SUITE_PART_CNT	9

#endif
