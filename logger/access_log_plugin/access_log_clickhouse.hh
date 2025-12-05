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

#include <netinet/in.h>
#include <string_view>
#include <span>

#include "../../fw/access_log.h"
#include "../clickhouse/clickhouse_decorator.hh"

template<TfwBinLogFields FieldType>
struct TfwBinLogTypeCommonTraits
{
	static constexpr size_t index = static_cast<size_t>(FieldType) + 1;
};

template<TfwBinLogFields FieldType>
struct TfwBinLogTypeTraits;

template<>
struct TfwBinLogTypeTraits<TFW_MMAP_LOG_ADDR>
	: TfwBinLogTypeCommonTraits<TFW_MMAP_LOG_ADDR>
{
	using ColType = ch::ColumnIPv6;
	using ValType = struct in6_addr;
};

template<>
struct TfwBinLogTypeTraits<TFW_MMAP_LOG_METHOD>
	: TfwBinLogTypeCommonTraits<TFW_MMAP_LOG_METHOD>
{
	using ColType = ch::ColumnUInt8;
	using ValType = uint8_t;
};

template<>
struct TfwBinLogTypeTraits<TFW_MMAP_LOG_VERSION>
	: TfwBinLogTypeCommonTraits<TFW_MMAP_LOG_VERSION>
{
	using ColType = ch::ColumnUInt8;
	using ValType = uint8_t;
};

template<>
struct TfwBinLogTypeTraits<TFW_MMAP_LOG_STATUS>
	: TfwBinLogTypeCommonTraits<TFW_MMAP_LOG_STATUS>
{
	using ColType = ch::ColumnUInt16;
	using ValType = uint16_t;
};

template<>
struct TfwBinLogTypeTraits<TFW_MMAP_LOG_RESP_CONT_LEN>
	: TfwBinLogTypeCommonTraits<TFW_MMAP_LOG_RESP_CONT_LEN>
{
	using ColType = ch::ColumnUInt32;
	using ValType = uint32_t;
};

template<>
struct TfwBinLogTypeTraits<TFW_MMAP_LOG_RESP_TIME>
	: TfwBinLogTypeCommonTraits<TFW_MMAP_LOG_RESP_TIME>
{
	using ColType = ch::ColumnUInt32;
	using ValType = uint32_t;
};

template<>
struct TfwBinLogTypeTraits<TFW_MMAP_LOG_VHOST>
	: TfwBinLogTypeCommonTraits<TFW_MMAP_LOG_VHOST>
{
	using ColType = ch::ColumnString;
	using ValType = std::string_view;
};

template<>
struct TfwBinLogTypeTraits<TFW_MMAP_LOG_URI>
	: TfwBinLogTypeCommonTraits<TFW_MMAP_LOG_URI>
{
	using ColType = ch::ColumnString;
	using ValType = std::string_view;
};

template<>
struct TfwBinLogTypeTraits<TFW_MMAP_LOG_REFERER>
	: TfwBinLogTypeCommonTraits<TFW_MMAP_LOG_REFERER>
{
	using ColType = ch::ColumnString;
	using ValType = std::string_view;
};

template<>
struct TfwBinLogTypeTraits<TFW_MMAP_LOG_USER_AGENT>
	: TfwBinLogTypeCommonTraits<TFW_MMAP_LOG_USER_AGENT>
{
	using ColType = ch::ColumnString;
	using ValType = std::string_view;
};

template<>
struct TfwBinLogTypeTraits<TFW_MMAP_LOG_TFT>
	: TfwBinLogTypeCommonTraits<TFW_MMAP_LOG_TFT>
{
	using ColType = ch::ColumnUInt64;
	using ValType = uint64_t;
};

template<>
struct TfwBinLogTypeTraits<TFW_MMAP_LOG_TFH>
	: TfwBinLogTypeCommonTraits<TFW_MMAP_LOG_TFH>
{
	using ColType = ch::ColumnUInt64;
	using ValType = uint64_t;
};

template<>
struct TfwBinLogTypeTraits<TFW_MMAP_LOG_DROPPED>
	: TfwBinLogTypeCommonTraits<TFW_MMAP_LOG_DROPPED>
{
	using ColType = ch::ColumnUInt64;
	using ValType = uint64_t;
};

/**
 * ClickHouse decorator specialized for access-log events.
 *
 * Provides type-safe append operations for various binlog fields defined
 * in TfwBinLogFields. Each field maps to the corresponding ClickHouse column
 * type using TfwBinLogTypeTraits.
 *
 * This decorator delegates table creation and block management to the
 * base ClickHouseDecorator class. It provides a convenient API for
 * appending timestamps and binlog field values without exposing
 * low-level block or table creation details.
 */
class AccessLogClickhouseDecorator final: public ClickHouseDecorator
{
public:
	AccessLogClickhouseDecorator(std::unique_ptr<IClickhouse> client,
		std::string_view table_name, size_t max_events);

public:
	/**
	 * Appends a timestamp value to the current block.
	 */
	void
	append_timestamp(uint64_t timestamp);

	/**
	 * Appends a value of the specified binlog field type.
	 *
	 * The field type is resolved at compile-time using TfwBinLogTypeTraits,
	 * ensuring type-safe insertion into the correct ClickHouse column.
	 */
	template <TfwBinLogFields FieldType>
	void
	append(const typename TfwBinLogTypeTraits<FieldType>::ValType& value);
};

template <TfwBinLogFields FieldType>
void
AccessLogClickhouseDecorator::append(
	const typename TfwBinLogTypeTraits<FieldType>::ValType& value)
{
	using Traits   = TfwBinLogTypeTraits<FieldType>;
	using ColType  = typename Traits::ColType;

	block_[Traits::index]->template As<ColType>()->Append(value);
}
