/**
 *		Tempesta FW
 *
 * Copyright (C) 2016-2018 Tempesta Technologies, Inc.
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
#ifndef __TTLS_H__
#define __TTLS_H__

#ifndef CHAR_BIT
#define CHAR_BIT 8 /* Normally in <limits.h> */
#endif

#include "config.h"

#include <linux/slab.h>
#include <linux/random.h>
#include <linux/string.h>

extern void *calloc(size_t n, size_t size);
extern void free(void *ptr);

#if defined(MBEDTLS_SELF_TEST) && defined(MBEDTLS_PKCS1_V15)
extern int rand(void);
#endif /* MBEDTLS_SELF_TEST && MBEDTLS_PKCS1_V15 */

/*
 * Include all the needed headers here.
 */

#include "aes.h"
#include "rsa.h"
#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "ssl.h"
#include "certs.h"
#include "debug.h"
#include "error.h"

#endif /* __TTLS_H__ */
