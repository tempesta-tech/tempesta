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

enum {
	ACT_INFO,
	ACT_CREATE,
	ACT_INSERT,
	ACT_SELECT,
};

namespace po  = boost::program_options;

struct Cfg {
	int		action;
	unsigned int	rec_sz;
	size_t		tbl_sz;
	size_t		mm_sz;
	std::string	db_path;
	std::string	table;

	Cfg &
	operator=(po::variables_map &&vm)
	{
		if (vm.count("path"))
			db_path	= std::move(vm["path"].as<std::string>());
		table	= std::move(vm["table"].as<std::string>());
		tbl_sz	= vm["tbl_size"].as<size_t>();
		rec_sz	= vm["rec_size"].as<size_t>();
		mm_sz	= vm["mmap"].as<size_t>();

		std::string a = std::move(vm["action"].as<std::string>());
		if (a == "info") {
			action = ACT_INFO;
		} else if (a == "create") {
			action = ACT_CREATE;
		} else if (a == "insert") {
			action = ACT_INSERT;
		} else if (a == "select") {
			action = ACT_SELECT;
		} else {
			throw TdbExcept("bad action: %s", a.c_str());
		}

		if (action == ACT_INFO && table != "*")
			throw TdbExcept("'info' command is only allowed for"
					" all tables");
		if (table == "*" && action != ACT_INFO)
			throw TdbExcept("please specify a table");
		if (action == ACT_CREATE && db_path.empty())
			throw TdbExcept("please specify database path");

		if (mm_sz % 2)
			throw TdbExcept("mmap size must be multiple of 2");
		if (mm_sz > UINT_MAX)
			throw TdbExcept("mmap size must be multiple to"
					" page size");
		return *this;
	}
};

int
main(int argc, char *argv[])
{
	Cfg cfg;
	po::options_description desc("\n\tTempesta DB CLI Query Tool\n"
				     "\nUsage:");
	desc.add_options()
		("debug,d", "Switch on debug mode")
		("help,h", "Show this message and exit")
		("mmap,m", po::value<size_t>()->default_value(TdbHndl::MMSZ),
		 "Size of mmap()'ed ring for communications w/ kernel in pages")

		("action,a", po::value<std::string>(),
		 "The action specification, one of the follwoing:\n"
		 "  info    - information about current"
		 		      " database state;\n"
		 "  create  - create a new table;\n"
		 "  insert  - insert a record to a table;\n"
		 "  select  - select from a table")
		("key,k", po::value<std::string>(), "The record key")
		("path,p", po::value<std::string>(), "Path to database files")
		("rec_size,r", po::value<size_t>()->default_value(0),
		 "Table record size. Specify this for fixed-size records"
		 " and leave zero for variable-size records like strings")
		("table,t", po::value<std::string>()->default_value("*"),
		 "The table to operate on or '*' for all tables")
		("tbl_size,s", po::value<size_t>()->default_value(64),
		 "Table size in pages");
	try {
		// Parse config options
		po::variables_map vm;
		po::store(po::parse_command_line(argc, argv, desc), vm);
		po::notify(vm);
		if (vm.count("help")) {
			std::cout << desc << std::endl;
			return 0;
		}
		if (vm.count("debug"))
			debug = true;

		cfg = std::move(vm);
	}
	catch (std::exception &e) {
		std::cerr << "Configuration error:  " << e.what() << std::endl;
		return 1;
	}

	try {
		TdbHndl th(cfg.mm_sz);

		switch (cfg.action) {
		case ACT_INFO:
			th.get_info([=](TdbMsg *m) {
				std::cout << m->recs[0].data << std::endl;
			});
			break;
		case ACT_CREATE:
			th.create_table(cfg.db_path, cfg.table, cfg.tbl_sz,
					cfg.rec_sz);
			std::cout << "table " << cfg.table << " created"
				  << std::endl;
			break;
		case ACT_INSERT:
			// TODO generic insertion function for many key=value pairs
			break;
		case ACT_SELECT:
			break;
		default:
			throw TdbExcept("bad action number %d", cfg.action);
		}
	}
	catch (TdbExcept &e) {
		std::cerr << "Error: " << e.what() << std::endl;
		return 2;
	}

	return 0;
}
