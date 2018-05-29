/**
 * \file havege.h
 *
 * \brief HAVEGE: HArdware Volatile Entropy Gathering and Expansion
 */
/*
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
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
#ifndef TTLS_HAVEGE_H
#define TTLS_HAVEGE_H

#include <stddef.h>

#define TTLS_HAVEGE_COLLECT_SIZE 1024

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief		  HAVEGE state structure
 */
typedef struct
{
	int PT1, PT2, offset[2];
	int pool[TTLS_HAVEGE_COLLECT_SIZE];
	int WALK[8192];
}
ttls_havege_state;

/**
 * \brief		  HAVEGE initialization
 *
 * \param hs	   HAVEGE state to be initialized
 */
void ttls_havege_init(ttls_havege_state *hs);

/**
 * \brief		  Clear HAVEGE state
 *
 * \param hs	   HAVEGE state to be cleared
 */
void ttls_havege_free(ttls_havege_state *hs);

/**
 * \brief		  HAVEGE rand function
 *
 * \param p_rng	A HAVEGE state
 * \param output   Buffer to fill
 * \param len	  Length of buffer
 *
 * \return		 0
 */
int ttls_havege_random(void *p_rng, unsigned char *output, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* havege.h */
