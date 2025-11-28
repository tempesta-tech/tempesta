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

#include <optional>
#include <string>

#include <boost/property_tree/ptree_fwd.hpp>

#include <fmt/format.h>

struct PluginConfig {
	std::string			host{"localhost"};
	uint16_t			port{9000};
	std::string			db_name{"default"};
	std::string			table_name{"access_log"};
	std::optional<std::string>	user;
	std::optional<std::string>	password;
	// Events before forcing commit
	size_t				max_events{1000};

	void parse_from_ptree(const boost::property_tree::ptree &tree);

	void validate() const;
};

template <> struct fmt::formatter<PluginConfig> {
	constexpr decltype(auto)
	parse(fmt::format_parse_context &ctx)
	{
		return ctx.begin();
	}

	template <typename FormatContext>
	constexpr decltype(auto)
	format(const PluginConfig &config, FormatContext &ctx)
	{
		constexpr auto msg_template = "{{host: '{}',"
					      " port: {},"
					      " database: '{}',"
					      " table: '{}',"
					      " user: '{}',"
					      " max_events: {}}}";
		return fmt::format_to(ctx.out(),
				      msg_template,
				      config.host,
				      config.port,
				      config.db_name,
				      config.table_name,
				      config.user.value_or("<none>"),
				      config.max_events);
	}
};
