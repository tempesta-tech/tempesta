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

#include "parser.hh"

#include <array>
#include <cassert>
#include <cstring>
#include <string>
#include <type_traits>

#include <spdlog/spdlog.h>

#include "../fw/access_log.h"

#include <netinet/in.h>

namespace {

enum class ParseResult {
	Success,
	NotEnoughData,
	FieldMissed,
};

template <auto Member, TfwBinLogFields Field, bool MemberIsOptional = false>
[[nodiscard]] ParseResult
parse_member(const TfwBinLogEvent &event, Parser::Bytes &data, AccessLog &dst)
{
	using T = std::remove_reference_t<decltype(dst.*Member)>;

	if (!TFW_MMAP_LOG_FIELD_IS_SET(&event, Field))
		return MemberIsOptional ? ParseResult::Success
					: ParseResult::FieldMissed;

	if constexpr (std::is_same_v<T, std::string>) {
		if (data.size() < sizeof(uint16_t))
			return ParseResult::NotEnoughData;
		uint16_t length = 0;
		std::memcpy(&length, data.data(), sizeof(uint16_t));
		data = data.subspan(sizeof(length));

		if (data.size() < length)
			return ParseResult::NotEnoughData;
		const auto *ptr = reinterpret_cast<const char *>(data.data());
		(dst.*Member).assign(ptr, length);
		data = data.subspan(length);
	}
	else {
		static_assert(std::is_trivially_copyable_v<T>);
		if (data.size() < sizeof(T))
			return ParseResult::NotEnoughData;
		std::memcpy(&(dst.*Member), data.data(), sizeof(T));
		data = data.subspan(sizeof(T));
	}
	return ParseResult::Success;
}

} // namespace

std::optional<AccessLog>
Parser::parse_next_event()
{
	if (data_.empty())
		return std::nullopt;

	if (data_.size() < sizeof(TfwBinLogEvent)) {
		spdlog::error("Not enough data to parse event, some events can "
			      "be lost or incorrectly parsed");
		return std::nullopt;
	}

	TfwBinLogEvent event;
	std::memcpy(&event, data_.data(), sizeof(event));

	data_ = data_.subspan(sizeof(TfwBinLogEvent));

	switch (event.type) {
	case TFW_MMAP_LOG_TYPE_ACCESS:
		return parse_access_log_event(event);
	default:
		spdlog::error("Unknown event type: {}. Some events can be "
			      "lost or incorrectly parsed",
			      static_cast<int>(event.type));
		return std::nullopt;
	}
}

[[nodiscard]] std::optional<AccessLog>
Parser::parse_access_log_event(const TfwBinLogEvent &event)
{
	AccessLog access_log;
	access_log.timestamp = std::chrono::milliseconds(event.timestamp);

	static constexpr std::array kSteps = {
	&parse_member<&AccessLog::address, TFW_MMAP_LOG_ADDR>,
	&parse_member<&AccessLog::method, TFW_MMAP_LOG_METHOD>,
	&parse_member<&AccessLog::version, TFW_MMAP_LOG_VERSION>,
	&parse_member<&AccessLog::status, TFW_MMAP_LOG_STATUS>,
	&parse_member<&AccessLog::response_content_length,
		      TFW_MMAP_LOG_RESP_CONT_LEN>,
	&parse_member<&AccessLog::response_time, TFW_MMAP_LOG_RESP_TIME>,
	&parse_member<&AccessLog::vhost, TFW_MMAP_LOG_VHOST>,
	&parse_member<&AccessLog::uri, TFW_MMAP_LOG_URI>,
	&parse_member<&AccessLog::referer, TFW_MMAP_LOG_REFERER>,
	&parse_member<&AccessLog::user_agent, TFW_MMAP_LOG_USER_AGENT>,
	&parse_member<&AccessLog::ja5t, TFW_MMAP_LOG_JA5T, true>,
	&parse_member<&AccessLog::ja5h, TFW_MMAP_LOG_JA5H>,
	&parse_member<&AccessLog::dropped_events, TFW_MMAP_LOG_DROPPED, true>,
	};

	for (auto step : kSteps) {
		switch (step(event, data_, access_log)) {
		case ParseResult::Success:
			break;
		case ParseResult::FieldMissed:
			spdlog::error("Field missed in access log event, some "
				      "events can be lost or incorrectly "
				      "parsed");
			return std::nullopt;
		case ParseResult::NotEnoughData:
			spdlog::error("Not enough data to parse access log "
				      "event, some events can be lost or "
				      "incorrectly parsed");
			return std::nullopt;
		default:
			assert(false);
			return std::nullopt;
		}
	}
	return access_log;
}
