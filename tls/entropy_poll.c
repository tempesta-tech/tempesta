/*
 *  Platform-specific and custom entropy polling functions
 *
 *  Copyright (C) 2006-2016, ARM Limited, All Rights Reserved
 *  Copyright (C) 2015-2018 Tempesta Technologies, Inc.
 *  SPDX-License-Identifier: GPL-2.0
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
#include <linux/jiffies.h>
#include <linux/random.h>
#include <linux/timex.h>

#include "config.h"

#if defined(TTLS_ENTROPY_C)

#include "entropy.h"
#include "entropy_poll.h"
#if defined(TTLS_HAVEGE_C)
#include "havege.h"
#endif

int ttls_hardclock_poll(void *data,
			unsigned char *output, size_t len, size_t *olen)
{
	unsigned long timer = get_cycles();
	((void) data);
	*olen = 0;

	if (len < sizeof(unsigned long))
		return 0;

	memcpy(output, &timer, sizeof(unsigned long));
	*olen = sizeof(unsigned long);

	return 0;
}

#if defined(TTLS_HAVEGE_C)
int ttls_havege_poll(void *data,
				 unsigned char *output, size_t len, size_t *olen)
{
	ttls_havege_state *hs = (ttls_havege_state *) data;
	*olen = 0;

	if (ttls_havege_random(hs, output, len) != 0)
		return(TTLS_ERR_ENTROPY_SOURCE_FAILED);

	*olen = len;

	return 0;
}
#endif /* TTLS_HAVEGE_C */

/**
 * Tempesta requires at least Haswell processor having RDRAND instruction,
 * so call CPU for the entropy.
 */
int
ttls_hardware_poll(void *data, unsigned char *output, size_t len,
			  size_t *olen)
{
	get_random_bytes_arch(output, len);
	*olen = len;
	return 0;
}

#endif /* TTLS_ENTROPY_C */
