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

// TODO: add to plugin API
//tus::Error<bool> consume() = 0;
//bool make_background_work() noexcept = 0;


struct ClickHouseConfig;
typedef struct ClickHouseConfig ClickHouseConfig;

typedef struct TfwLoggerConfig TfwLoggerConfig;
typedef struct {
	int 		version;
	const char 	*name;
	int   (*init)(const ClickHouseConfig *config, void *stop_flag);
	void  (*done)(void);
	void* (*create_processor)(unsigned processor_id);
	void  (*destroy_processor)(void *processor);
} TfwLoggerPluginApi;

typedef TfwLoggerPluginApi* (*TfwLoggerPluginGetApiFunc)(void);

TfwLoggerPluginApi *get_plugin_api();

#ifdef __cplusplus
}
#endif
