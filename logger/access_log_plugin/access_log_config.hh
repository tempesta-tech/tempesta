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
#pragma once

#include <optional>
#include <string>

#include <boost/property_tree/ptree_fwd.hpp>

#include <fmt/format.h>

struct AccessLogConfig {
	std::string			host{"localhost"};
	uint16_t			port{9000};
	std::string			db_name{"default"};
	std::string			access_log_table_name{"access_log"};
	std::string			dos_log_table_name{"security_dos_log"};
	std::string			web_attack_log_table_name{"security_web_attack_log"};
	std::optional<std::string>	user;
	std::optional<std::string>	password;
	// Events before forcing commit
	size_t				max_events{1000};
	std::string			json_str;

	void parse_json(std::string json);

private:
	void parse_from_ptree(const boost::property_tree::ptree &tree);
	void validate() const;
};

template <> struct fmt::formatter<AccessLogConfig> {
	constexpr decltype(auto)
	parse(fmt::format_parse_context &ctx)
	{
		return ctx.begin();
	}

	template <typename FormatContext>
	constexpr decltype(auto)
	format(const AccessLogConfig &config, FormatContext &ctx)
	{
		constexpr auto msg_template = "{{host: '{}',"
					      " port: {},"
					      " database: '{}',"
					      " access_log_table_name: '{}',"
					      " dos_log_table_name: '{}',"
					      " web_attack_log_table_name: '{}',"
					      " user: '{}',"
					      " max_events: {}}}";
		return fmt::format_to(ctx.out(),
				      msg_template,
				      config.host,
				      config.port,
				      config.access_log_table_name,
				      config.dos_log_table_name,
				      config.web_attack_log_table_name,
				      config.user.value_or("<none>"),
				      config.max_events);
	}
};
