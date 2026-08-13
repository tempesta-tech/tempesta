/**
 *		Tempesta FW
 *
 * Copyright (C) 2024-2026 Tempesta Technologies, Inc.
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
#include "plugin_config.hh"

#include <regex>
#include <stdexcept>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include "config_utils.hh"

void
PluginConfig::validate() const
{
	if (host.empty())
		throw std::runtime_error("ClickHouse host cannot be empty");

	if (port == 0)
		throw std::runtime_error("Invalid ClickHouse port");

	if (db_name.empty())
		throw std::runtime_error(
		"ClickHouse database name cannot be empty");

	if (table_name.empty())
		throw std::runtime_error(
		"ClickHouse table name cannot be empty");

	if (max_events == 0)
		throw std::runtime_error("max_events must be greater than 0");

	cfg_utils::validate_table_name(table_name);
}

void
PluginConfig::parse_from_ptree(const boost::property_tree::ptree &tree)
{
	host = tree.get<std::string>("host", host);
	port = tree.get<uint16_t>("port", port);
	db_name = tree.get<std::string>("db_name", db_name);
	table_name = tree.get<std::string>("table_name", table_name);
	max_events = tree.get<size_t>("max_events", max_events);

	if (const auto val = tree.get_optional<std::string>("user"))
		user = *val;

	if (const auto val = tree.get_optional<std::string>("password"))
		password = *val;

	std::ostringstream out;

	boost::property_tree::write_json(out, tree, false);

	json_str = out.str();
}
