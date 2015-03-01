/**
 *		Tempesta FW
 *
 * Tempesta load balancing module interface.
 *
 * Copyright (C) 2015 Tempesta Technologies.
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

#include "lb_mod.h"
#include "log.h"

static const TfwLbMod *tfw_lb_mod;

/* Send the @msg with choosing an appropriate backend server. */
int
tfw_lb_send_msg(TfwMsg *msg)
{
	BUG_ON(!msg);
	BUG_ON(!tfw_lb_mod);

	return tfw_lb_mod->send_msg(msg);
}

int
tfw_lb_mod_register(const TfwLbMod *mod)
{
	BUG_ON(!mod);
	BUG_ON(!mod->name || !mod->send_msg);

	TFW_DBG("registering load balancer: %s\n", mod->name);

	if (tfw_lb_mod) {
		TFW_ERR("can't register the load balancer: '%s', already "
			"registered: '%s'\n", mod->name, tfw_lb_mod->name);
		return -EEXIST;
	}

	tfw_lb_mod = mod;
	return 0;
}
EXPORT_SYMBOL(tfw_lb_mod_register);

void
tfw_lb_mod_unregister(void)
{
	BUG_ON(!tfw_lb_mod);

	TFW_LOG("un-registering load balancer: %s\n", tfw_lb_mod->name);
	tfw_lb_mod = NULL;
}
EXPORT_SYMBOL(tfw_lb_mod_unregister);
