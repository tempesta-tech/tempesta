/**
 *		Tempesta FW
 *
 * TODO Stress/overload module for the local system (issue #488).
 *
 * Copyright (C) 2012-2013 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015 Tempesta Technologies, Inc.
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
#include <linux/module.h>

#include "../tempesta_fw.h"

MODULE_AUTHOR(TFW_AUTHOR);
MODULE_DESCRIPTION("Tempesta system stress accounting");
MODULE_VERSION("0.1.0");
MODULE_LICENSE("GPL");


static int __init
th_stress_sys_init(void)
{
	return 0;
}

static void __exit
th_stress_sys_exit(void)
{
}

module_init(th_stress_sys_init);
module_exit(th_stress_sys_exit);
