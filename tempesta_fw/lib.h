/**
 *		Tempesta FW
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
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
#ifndef __TFW_LIB_H__
#define __TFW_LIB_H__

#include "str.h"

#ifdef DEBUG
#define DEBUG_IS_DEFINED 1
#else
#define DEBUG_IS_DEFINED 0
#endif

#define IF_DEBUG if (DEBUG_IS_DEFINED)

#ifndef packedenum
#define packedenum  enum __attribute__((packed))
#endif

#ifndef STRINGIFY
#define _STRINGIFY(x) #x
#define STRINGIFY(x) _STRINGIFY(x)
#endif

int tfw_str_tokens_count(const char *str);
int tfw_inet_pton(char **p, void *addr);
int tfw_inet_ntop(const void *addr, char *buf);
bool tfw_addr_eq(const void *addr1, const void *addr2);

#endif /* __TFW_LIB_H__ */
