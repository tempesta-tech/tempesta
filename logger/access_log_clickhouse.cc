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
#include <spdlog/spdlog.h>

#include "../libtus/error.hh"

#include "access_log_clickhouse.hh"

namespace {
constexpr std::string_view TableCreationQueryTemplate =
	"CREATE TABLE IF NOT EXISTS {} "
	"(timestamp DateTime64(3, 'UTC'),"
	" address IPv6,"
	" method UInt8,"
	" version UInt8,"
	" status UInt16,"
	" response_content_length UInt64,"
	" response_time UInt32,"
	" vhost String,"
	" uri String,"
	" referer String,"
	" user_agent String,"
	" tft UInt64,"
	" tfh UInt64,"
	" dropped_events UInt64"
	") ENGINE = MergeTree() ORDER BY timestamp";

static const ClickHouseDecorator::TfwField TfwFields[] = {
	[0]							= {"timestamp", ch::Type::DateTime64},
	[TfwBinLogTypeTraits<TFW_MMAP_LOG_ADDR>::index]		= {"address", ch::Type::IPv6},
	[TfwBinLogTypeTraits<TFW_MMAP_LOG_METHOD>::index]	= {"method", ch::Type::UInt8},
	[TfwBinLogTypeTraits<TFW_MMAP_LOG_VERSION>::index]	= {"version", ch::Type::UInt8},
	[TfwBinLogTypeTraits<TFW_MMAP_LOG_STATUS>::index]	= {"status", ch::Type::UInt16},
	[TfwBinLogTypeTraits<TFW_MMAP_LOG_RESP_CONT_LEN>::index]= {"response_content_length", ch::Type::UInt32},
	[TfwBinLogTypeTraits<TFW_MMAP_LOG_RESP_TIME>::index]	= {"response_time", ch::Type::UInt32},
	[TfwBinLogTypeTraits<TFW_MMAP_LOG_VHOST>::index]	= {"vhost", ch::Type::String},
	[TfwBinLogTypeTraits<TFW_MMAP_LOG_URI>::index]		= {"uri", ch::Type::String},
	[TfwBinLogTypeTraits<TFW_MMAP_LOG_REFERER>::index]	= {"referer", ch::Type::String},
	[TfwBinLogTypeTraits<TFW_MMAP_LOG_USER_AGENT>::index]	= {"user_agent", ch::Type::String},
	[TfwBinLogTypeTraits<TFW_MMAP_LOG_TFT>::index]		= {"tft", ch::Type::UInt64},
	[TfwBinLogTypeTraits<TFW_MMAP_LOG_TFH>::index]		= {"tfh", ch::Type::UInt64},
	[TfwBinLogTypeTraits<TFW_MMAP_LOG_DROPPED>::index]	= {"dropped_events", ch::Type::UInt64}
};

//timestamp is calculated separately
static_assert(std::size(TfwFields) == TFW_MMAP_LOG_MAX + 1, "tfw_fields size mismatch");
} // anonymous namespace

AccessLogClickhouseDecorator::AccessLogClickhouseDecorator(
	std::unique_ptr<TfwClickhouse> client, std::string_view table_name,
	size_t max_events)
		: ClickHouseDecorator(std::move(client), TableCreationQueryTemplate,
				      table_name, TfwFields, max_events)
{
}

void
AccessLogClickhouseDecorator::append_timestamp(uint64_t timestamp)
{
	block_[0]->As<ch::ColumnDateTime64>()->Append(timestamp);
}
