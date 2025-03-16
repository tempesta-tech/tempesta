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

#include "tfw_logger_config.hh"
#include "error.hh"

#include <boost/property_tree/json_parser.hpp>
#include <boost/program_options.hpp>
#include <thread>
#include <iostream>
#include <sstream>

namespace pt = boost::property_tree;
namespace po = boost::program_options;

std::optional<TfwLoggerConfig>
TfwLoggerConfig::load_from_file(const fs::path &path)
{
	if (!fs::exists(path))
	{
		std::cerr << "Config file not found: " << path << std::endl;
		return std::nullopt;
	}

	TfwLoggerConfig config;

	try
	{
		pt::ptree tree;
		pt::read_json(path.string(), tree);
		config.parse_from_ptree(tree);
	}
	catch (const pt::json_parser_error &e)
	{
		std::cerr << "Error parsing config file: " << e.what() << std::endl;
		return std::nullopt;
	}
	catch (const pt::ptree_error &e)
	{
		std::cerr << "Error in config structure: " << e.what() << std::endl;
		return std::nullopt;
	}
	catch (const std::exception &e)
	{
		std::cerr << "Error loading config: " << e.what() << std::endl;
		return std::nullopt;
	}

	return std::move(config);
}

TfwLoggerConfig
TfwLoggerConfig::from_cli_args(int argc, char *argv[])
{
	TfwLoggerConfig config;
	po::options_description desc("Tempesta Logger options");

	std::string mode_str;
	std::string ch_host;

	desc.add_options()("help,h", "Show help message")("mode,m", po::value<std::string>(&mode_str)->default_value("daemon"),
	"Operating mode (daemon or handle)")("log-path,l", po::value<fs::path>(&config.log_path_),
	"Path to the log file")("pid-file,p", po::value<fs::path>(&config.pid_file_),
	"Path to the PID file")("buffer-size,b", po::value<size_t>(&config.buffer_size_),
	"Buffer size in bytes")("cpu-count,c", po::value<size_t>(&config.cpu_count_),
	"Number of CPUs to use (0 = auto)")("clickhouse-host,H", po::value<std::string>(&config.clickhouse_.host)->required(),
	"ClickHouse server host")("clickhouse-port", po::value<uint16_t>(&config.clickhouse_.port),
	"ClickHouse server port")("clickhouse-user,u", po::value<std::string>(),
	"ClickHouse username")("clickhouse-password", po::value<std::string>(),
	"ClickHouse password")("clickhouse-max-events", po::value<size_t>(&config.clickhouse_.max_events),
	"Maximum events in a batch")("clickhouse-max-wait", po::value<int>(),
	"Maximum wait time for batch (ms)");

	po::variables_map vm;

	try
	{
		po::store(po::parse_command_line(argc, argv, desc), vm);

		if (vm.count("help"))
		{
			std::cout << desc << std::endl;
			exit(0);
		}

		po::notify(vm);

		// Process mode
		if (mode_str == "daemon")
		{
			config.mode_ = Mode::DAEMON;
		}
		else if (mode_str == "handle")
		{
			config.mode_ = Mode::HANDLE;
		}
		else
		{
			throw std::runtime_error("Invalid mode: " + mode_str);
		}

		// Process optional parameters
		if (vm.count("clickhouse-user"))
		{
			config.clickhouse_.user = vm["clickhouse-user"].as<std::string>();
		}

		if (vm.count("clickhouse-password"))
		{
			config.clickhouse_.password = vm["clickhouse-password"].as<std::string>();
		}

		if (vm.count("clickhouse-max-wait"))
		{
			int ms = vm["clickhouse-max-wait"].as<int>();
			config.clickhouse_.max_wait = std::chrono::milliseconds(ms);
		}
	}
	catch (const po::error &e)
	{
		std::cerr << "Error parsing command line: " << e.what() << std::endl;
		std::cerr << "Use --help for usage information" << std::endl;
		exit(1);
	}
	catch (const std::exception &e)
	{
		std::cerr << "Error: " << e.what() << std::endl;
		exit(1);
	}

	return config;
}

void TfwLoggerConfig::parse_from_ptree(const pt::ptree &tree)
{
	// Parse mode
	std::string mode_str = tree.get<std::string>("mode", "daemon");
	if (mode_str == "daemon")
	{
		mode_ = Mode::DAEMON;
	}
	else if (mode_str == "handle")
	{
		mode_ = Mode::HANDLE;
	}
	else
	{
		throw std::runtime_error("Invalid mode: " + mode_str);
	}

	// Parse paths
	log_path_ = tree.get<std::string>("log_path", log_path_.string());
	pid_file_ = tree.get<std::string>("pid_file", pid_file_.string());

	// Parse buffer and CPU settings
	buffer_size_ = tree.get<size_t>("buffer_size", buffer_size_);
	cpu_count_ = tree.get<size_t>("cpu_count", cpu_count_);

	// Parse ClickHouse config if present
	if (auto ch_node = tree.get_child_optional("clickhouse"))
	{
		clickhouse_.host = ch_node->get<std::string>("host");
		clickhouse_.port = ch_node->get<uint16_t>("port", clickhouse_.port);

		if (auto user = ch_node->get_optional<std::string>("user"))
		{
			clickhouse_.user = *user;
		}

		if (auto password = ch_node->get_optional<std::string>("password"))
		{
			clickhouse_.password = *password;
		}

		clickhouse_.max_events = ch_node->get<size_t>("max_events", clickhouse_.max_events);

		int max_wait_ms = ch_node->get<int>("max_wait_ms", clickhouse_.max_wait.count());
		clickhouse_.max_wait = std::chrono::milliseconds(max_wait_ms);
	}
}

bool TfwLoggerConfig::save_to_file(const fs::path &path) const
{
	try
	{
		pt::ptree tree;

		// Save mode
		tree.put("mode", mode_ == Mode::DAEMON ? "daemon" : "handle");

		// Save paths
		tree.put("log_path", log_path_.string());
		tree.put("pid_file", pid_file_.string());

		// Save buffer and CPU settings
		tree.put("buffer_size", buffer_size_);
		tree.put("cpu_count", cpu_count_);

		// Save ClickHouse config
		pt::ptree ch_node;
		ch_node.put("host", clickhouse_.host);
		ch_node.put("port", clickhouse_.port);

		if (clickhouse_.user)
		{
			ch_node.put("user", *clickhouse_.user);
		}

		if (clickhouse_.password)
		{
			ch_node.put("password", *clickhouse_.password);
		}

		ch_node.put("max_events", clickhouse_.max_events);
		ch_node.put("max_wait_ms", clickhouse_.max_wait.count());

		tree.put_child("clickhouse", ch_node);

		pt::write_json(path.string(), tree);
		return true;
	}
	catch (const std::exception &e)
	{
		std::cerr << "Error saving config: " << e.what() << std::endl;
		return false;
	}
}
