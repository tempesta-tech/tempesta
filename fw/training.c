/**
 *		Tempesta FW
 *
 * Copyright (C) 2026 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#include "training.h"
#include "client.h"
#include "http_limits.h"
#include "tempesta_fw.h"

int tfw_training_mod_period = 0;
static int tfw_training_mod_z_score_mem = 0;
static int tfw_training_mod_z_score_cpu = 0;
static int tfw_training_mod_z_score_conn_num = 0;
TfwTrainingMode tfw_training_mod_state = TFW_TRAINING_MODE_DISABLED; 

static struct timer_list training_timer;

static unsigned int num_clients = 0;
static unsigned long long total_client_mem = 0;
static unsigned long average_client_mem = 0;
static unsigned long long sum_of_squared_mem = 0;
static unsigned long standart_deviation_mem = 0;
static unsigned long long total_client_conn_num = 0;
static unsigned long average_client_conn_num = 0;
static unsigned long long sum_of_squared_conn_num = 0;
static unsigned long standart_deviation_conn_num = 0;

static inline int
__calculate_total_for_clients(void *data)
{
	TfwClient *cli = (TfwClient *)data;

	num_clients++;
	total_client_mem += tfw_client_mem(cli);
	total_client_conn_num += frang_client_conn_curr(cli);

	return 0;
}

static inline int
__calculate_sum_of_squared_difference_fro_clients(void *data)
{
	TfwClient *cli = (TfwClient *)data;

	sum_of_squared_mem += (tfw_client_mem(cli) - average_client_mem) *
		(tfw_client_mem(cli) - average_client_mem);
	sum_of_squared_conn_num +=
		(frang_client_conn_curr(cli) - average_client_conn_num) *
		(frang_client_conn_curr(cli) - average_client_conn_num);

	return 0;
}

static inline void
__prepare_z_score(void)
{
	total_client_mem = 0;
	num_clients = 0;
	average_client_mem = 0;
	sum_of_squared_mem = 0;
	standart_deviation_mem = 0;
	total_client_conn_num = 0;
	average_client_conn_num = 0;
	sum_of_squared_conn_num = 0;
	standart_deviation_conn_num = 0;

	tfw_client_for_each(__calculate_total_for_clients);
	if (!num_clients)
		return;
	average_client_mem = total_client_mem / num_clients;
	average_client_conn_num = total_client_conn_num / num_clients;
	tfw_client_for_each(__calculate_sum_of_squared_difference_fro_clients);
	standart_deviation_mem = (int_sqrt(sum_of_squared_mem / num_clients));
	standart_deviation_conn_num =
		(int_sqrt(sum_of_squared_conn_num / num_clients));
}

static void
tfw_training_timer_cb(struct timer_list *t)
{
	__prepare_z_score();
	tfw_training_mod_state = TFW_TRAINING_DEFENCE_MODE_ENABLED;
}

void
tfw_training_start(void)
{
	unsigned long trainging_perid_in_jiffies =
		msecs_to_jiffies(1000 * tfw_training_mod_period);

	tfw_training_mod_state = TFW_TRAINING_MODE_ENABLED;
	mod_timer(&training_timer, jiffies + trainging_perid_in_jiffies);
}

void
tfw_training_stop(TfwTrainingMode mode)
{
	if (del_timer_sync(&training_timer)) {
		__prepare_z_score();
		tfw_training_mod_state = mode;
	}
}

static int
tfw_training_mode_start(void)
{
	timer_setup(&training_timer, tfw_training_timer_cb, 0);
	return 0;
}

static void
tfw_training_mode_stop(void)
{
	tfw_training_stop(TFW_TRAINING_MODE_DISABLED);
	tfw_training_mod_state = TFW_TRAINING_MODE_DISABLED;
}

static TfwCfgSpec tfw_training_mode_specs[] = {
	{
		.name = "training_period",
		.deflt = "75",
		.handler = tfw_cfg_set_int,
		.dest = &tfw_training_mod_period,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, UINT_MAX },
		},
	},
	{
		.name = "training_z_score_mem",
		.deflt = "0",
		.handler = tfw_cfg_set_int,
		.dest = &tfw_training_mod_z_score_mem,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, UINT_MAX },
		}
	},
	{
		.name = "training_z_score_cpu",
		.deflt = "0",
		.handler = tfw_cfg_set_int,
		.dest = &tfw_training_mod_z_score_cpu,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, UINT_MAX },
		}
	},
	{
		.name = "training_z_score_connection_num",
		.deflt = "0",
		.handler = tfw_cfg_set_int,
		.dest = &tfw_training_mod_z_score_conn_num,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, UINT_MAX },
		}
	},
	{ 0 }
};

TfwMod tfw_training_mod = {
	.name 	= "training",
	.start	= tfw_training_mode_start,
	.stop	= tfw_training_mode_stop,
	.specs	= tfw_training_mode_specs,
};

int __init
tfw_training_mode_init(void)
{
	tfw_mod_register(&tfw_training_mod);

	return 0;
}

void
tfw_training_mode_exit(void)
{
	tfw_mod_unregister(&tfw_training_mod);
}
