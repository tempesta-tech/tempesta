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

#include <chrono>
#include <string>

#include <fmt/format.h>
#include <arpa/inet.h>
#include <netinet/in.h>

struct AccessLog {
	std::chrono::milliseconds timestamp;
	in6_addr address;
	uint8_t method;
	uint8_t version;
	uint16_t status;
	uint32_t response_content_length;
	uint32_t response_time;
	std::string vhost;
	std::string uri;
	std::string referer;
	std::string user_agent;
	uint64_t ja5t;
	uint64_t ja5h;
	uint64_t dropped_events;
};

template <> struct fmt::formatter<in6_addr> {
	constexpr auto
	parse(fmt::format_parse_context &ctx) const
	{
		return ctx.begin();
	}

	template <typename FormatContext>
	auto
	format(const in6_addr &addr, FormatContext &ctx) const
	{
		char buf[INET6_ADDRSTRLEN] = {};
		const char *s = inet_ntop(AF_INET6, &addr, buf, sizeof(buf));
		if (!s)
			return fmt::format_to(ctx.out(), "<invalid>");
		return fmt::format_to(ctx.out(), "{}", s);
	}
};

template <> struct fmt::formatter<AccessLog> {
	constexpr auto
	parse(fmt::format_parse_context &ctx) const
	{
		return ctx.begin();
	}

	template <typename FormatContext>
	auto
	format(const AccessLog &log, FormatContext &ctx) const
	{
		constexpr auto msg_template = "{{timestamp: {}ms,"
					      " address: {},"
					      " method: {},"
					      " version: {},"
					      " status: {},"
					      " response_content_length: {},"
					      " response_time: {}ms,"
					      " vhost: {},"
					      " uri: {},"
					      " referer: {},"
					      " user_agent: {},"
					      " ja5t: {},"
					      " ja5h: {},"
					      " dropped_events: {}}}";
		return fmt::format_to(ctx.out(),
				      msg_template,
				      log.timestamp.count(),
				      log.address,
				      log.method,
				      log.version,
				      log.status,
				      log.response_content_length,
				      log.response_time,
				      log.vhost,
				      log.uri,
				      log.referer,
				      log.user_agent,
				      log.ja5t,
				      log.ja5h,
				      log.dropped_events);
	}
};