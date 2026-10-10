/**
 *		Tempesta FW
 *
 * Copyright (C) 2026 Tempesta Technologies, Inc.
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
#include <spdlog/spdlog.h>

#include "../../libtus/error.hh"

#include "web_attack_log_clickhouse.hh"

namespace {
constexpr std::string_view TableCreationQueryTemplate =
	"CREATE TABLE IF NOT EXISTS {} "
	"(timestamp DateTime64(3, 'UTC'),"
	" client_address IPv6,"
	" client_port UInt16,"
	" local_port UInt16,"
	" event_type UInt16,"
	" event_body String,"
	" ip_block UInt8,"
	" dropped_events UInt64"
	") ENGINE = MergeTree() ORDER BY timestamp";

static const ClickHouseDecorator::TfwField TfwFields[] = {
	[0]								= {"timestamp", ch::Type::DateTime64},
	[TfwWebAttackLogTypeTraits<TFW_WA_LOG_ADDR>::index]		= {"client_address", ch::Type::IPv6},
	[TfwWebAttackLogTypeTraits<TFW_WA_LOG_CLIENT_PORT>::index]	= {"client_port", ch::Type::UInt16},
	[TfwWebAttackLogTypeTraits<TFW_WA_LOG_LOCAL_PORT>::index]	= {"local_port", ch::Type::UInt16},
	[TfwWebAttackLogTypeTraits<TFW_WA_LOG_EVENT_TYPE>::index]	= {"event_type", ch::Type::UInt16},
	[TfwWebAttackLogTypeTraits<TFW_WA_LOG_EVENT_BODY>::index]	= {"event_body", ch::Type::String},
	[TfwWebAttackLogTypeTraits<TFW_WA_LOG_IP_BLOCK>::index]		= {"ip_block", ch::Type::UInt8},
	[TfwWebAttackLogTypeTraits<TFW_WA_LOG_DROPPED>::index]		= {"dropped_events", ch::Type::UInt64}
};

//timestamp is calculated separately
static_assert(std::size(TfwFields) == TFW_WA_LOG_MAX + 1, "tfw_fields size mismatch");
} // anonymous namespace

WebAttackLogClickhouseDecorator::WebAttackLogClickhouseDecorator(
	std::shared_ptr<IClickhouse> client, std::string_view table_name,
	size_t max_events)
		: ClickHouseDecorator(client, TableCreationQueryTemplate,
				      table_name, TfwFields, max_events)
{
}

void
WebAttackLogClickhouseDecorator::append_timestamp(uint64_t timestamp)
{
	append<ch::ColumnDateTime64, 0>(timestamp);
}
