/**
 *		Tempesta FW
 *
 * Copyright (C) 2024-2025 Tempesta Technologies, Inc.
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
#pragma once

#include <stddef.h>
#include <stdint.h>

#define TFW_PLUGIN_VERSION 1

#ifdef __cplusplus
extern "C" {
#endif

void plugin_log_debug(const char* msg);
void plugin_log_info(const char* msg);
void plugin_log_warn(const char* msg);
void plugin_log_error(const char* msg);

typedef struct {
	const char*	host;		// null-terminated
	uint16_t	port;

	const char*	db_name;	// null-terminated
	const char*	table_name;	// null-terminated

	const char*	user;      	// null-terminated
	const char*	password;  	// null-terminated

	size_t		max_events;
} PluginConfigApi;

typedef void* ProcessorInstance;

typedef struct {
	/**
	* Checks whether a stop of plugin loading has been requested.
	* Returns 0 = continue loading, 1 = stop requested.
	* Note: the flag is one-way — once set to 1 (stop requested),
	* it cannot be reset back to 0.
	*/
	int (*stop_requested)();

	/**
	* Signals that plugin loading should stop.
	* This is a one-way operation: once the flag is set to stop,
	* it will remain set and cannot be cleared.
	*/
	void (*request_stop)();
} StopFlag;

typedef struct {
	int		version;
	const char	*name;

	int	(*init)(StopFlag* stop_flag);
	void	(*done)(void);

	ProcessorInstance	(*create_processor)(const PluginConfigApi *config,
						    unsigned cpu_id);
	void 			(*destroy_processor)(ProcessorInstance);

	int			(*has_stopped)(ProcessorInstance);
	void			(*request_stop)(ProcessorInstance);

	int			(*consume)(ProcessorInstance, size_t *cnt);
	int			(*send)(ProcessorInstance, bool);
} TfwLoggerPluginApi;

typedef TfwLoggerPluginApi* (*TfwLoggerPluginGetApiFunc)(void);

TfwLoggerPluginApi *get_plugin_api();

#ifdef __cplusplus
}
#endif
