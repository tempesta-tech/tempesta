/**
 *		Tempesta DB Query Tool
 *
 * Copyright (C) 2015 Tempesta Technologies.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#include <iostream>
#include <string>

#include <boost/program_options.hpp>

#include <libtdb.h>

// String definitions.
#define ACT_INFO	"info"
#define ACT_CREATE	"create"
#define ACT_INSERT	"insert"
#define ACT_SELECT	"select"

namespace po  = boost::program_options;

static void
check_config(po::variables_map &vm)
{
	if (!vm.count("action")) {
		throw TdbExcept("please specify some action");
		return;
	}

	auto a = vm["action"].as<std::string>();
	auto t = vm["table"].as<std::string>();
	if (a == ACT_INFO && t != "*")
		throw TdbExcept("'show' command is only allowed for"
				" all tables");
	if (t == "*" && a != ACT_INFO)
		throw TdbExcept("please specify a table");

	auto m = vm["mmap"].as<size_t>();
	if (m % 2)
		throw TdbExcept("mmap size must be multiple of 2");
	if (m > UINT_MAX)
		throw TdbExcept("mmap size must be multiple of page size");
}

int
main(int argc, char *argv[])
{
	po::variables_map vm;
	po::options_description desc("\n\tTempesta DB CLI Query Tool\n"
				     "\nUsage:");
	desc.add_options()
		("debug,d", "Switch on debug mode")
		("help,h", "Show this message and exit")
		("mmap,m", po::value<size_t>()->default_value(TdbHndl::MMSZ),
		 "Size of mmap()'ed ring for communications w/ kernel in pages")

		("action,a", po::value<std::string>(),
		 "The action specification, one of the follwoing:\n"
		 "  " ACT_INFO "    - information about current"
		 		      " database state;\n"
		 "  " ACT_CREATE "  - create a new table;\n"
		 "  " ACT_INSERT "  - insert a record to a table;\n"
		 "  " ACT_SELECT "  - select from a table")
		("key,k", po::value<std::string>(), "The record key")
		("table,t", po::value<std::string>()->default_value("*"),
		 "The table to operate on or '*' for all tables");
	try {
		// Parse config options
		po::store(po::parse_command_line(argc, argv, desc), vm);
		po::notify(vm);
		if (vm.count("help")) {
			std::cout << desc << std::endl;
			return 0;
		}
		if (vm.count("debug"))
			debug = true;
		check_config(vm);
	}
	catch (std::exception &e) {
		std::cerr << "Configuration error:  " << e.what() << std::endl;
		return 1;
	}

	try {
		auto a = vm["action"].as<std::string>();
		TdbHndl th(vm["mmap"].as<size_t>());

		if (a == ACT_INFO) {
			// TODO tables list, database version, usage memory etc.
			th.get_info();
		}
		else if (a == ACT_CREATE) {
		}
		else if (a == ACT_INSERT) {
			// TODO generic insertion function for many key=value pairs
		}
		else if (a == ACT_SELECT) {
		}
		else
			throw TdbExcept(("bad action: " + a).c_str());
	}
	catch (TdbExcept &e) {
		std::cerr << "Error: " << e.what() << std::endl;
		return 2;
	}

	return 0;
}
