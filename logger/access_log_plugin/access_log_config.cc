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

#include "access_log_config.hh"
#include "../config_utils.hh"

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

void
AccessLogConfig::parse_json(std::string json)
{
	namespace pt = boost::property_tree;

	pt::ptree tree;
	std::istringstream json_stream{json};

	pt::read_json(json_stream, tree);
	parse_from_ptree(tree);
	validate();
}

void
AccessLogConfig::validate() const
{
	if (host.empty())
		throw std::runtime_error("ClickHouse host cannot be empty");

	if (port == 0)
		throw std::runtime_error("Invalid ClickHouse port");

	if (db_name.empty())
		throw std::runtime_error(
		"ClickHouse database name cannot be empty");

	if (access_log_table_name.empty())
		throw std::runtime_error(
		"access log table name cannot be empty");

	if (dos_log_table_name.empty())
		throw std::runtime_error("dos log table name cannot be empty");

	if (web_attack_log_table_name.empty())
		throw std::runtime_error(
		"web attack log table name cannot be empty");

	if (max_events == 0)
		throw std::runtime_error("max_events must be greater than 0");

	cfg_utils::validate_table_name(access_log_table_name);
	cfg_utils::validate_table_name(dos_log_table_name);
	cfg_utils::validate_table_name(web_attack_log_table_name);
}

void
AccessLogConfig::parse_from_ptree(const boost::property_tree::ptree &tree)
{
	host = tree.get<std::string>("host", host);
	port = tree.get<uint16_t>("port", port);
	db_name = tree.get<std::string>("db_name", db_name);
	access_log_table_name = tree.get<std::string>("access_log_table_name",
						      access_log_table_name);
	dos_log_table_name =
		tree.get<std::string>("security_dos_log_table_name",
				      dos_log_table_name);
	web_attack_log_table_name =
		tree.get<std::string>("security_web_attack_log_table_name",
				      web_attack_log_table_name);
	max_events = tree.get<size_t>("max_events", max_events);

	if (const auto val = tree.get_optional<std::string>("user"))
		user = *val;

	if (const auto val = tree.get_optional<std::string>("password"))
		password = *val;
}
