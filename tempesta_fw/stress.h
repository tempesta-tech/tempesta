/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2018 Tempesta Technologies, Inc.
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
#ifndef __TFW_STRESS__
#define __TFW_STRESS__

#include <linux/list.h>

#include "tempesta_fw.h"

typedef enum {
	TfwStress_Sys	= 1,
	TfwStress_Srv	= 2,
} TfwStressType;

/* Stress module handler. */
typedef struct {
	struct list_head st_list; /* list of stress handlers */

	TfwStressType	type;

	/* TODO it seems we can catch the stress events (the both callbacks
	 * below) just on receiving a response (for account_srv) and receiving
	 * a request (for account_sys).
	 */

	/*
	 * Account and handle back-end server overload.
	 * @return true if there is overload and false otherwise.
	 */
	bool		(*account_srv)(void);
	/*
	 * Account and handle local system overload.
	 * @return true if there is overload and false otherwise.
	 */
	bool		(*account_sys)(void);

} TfwStress;

void tfw_stress_account_srv(void);
void tfw_stress_account_sys(void);

int tfw_stress_register(TfwStress *mod);
void tfw_stress_unregister(TfwStress *mod);

#endif /* __TFW_STRESS__ */
