/**
 *		Tempesta Language
 *
 * Copyright (C) 2015 Tempesta Technologies, Inc.
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
#include <fstream>
#include <iostream>
#include <string>

#include <boost/program_options.hpp>

#include "ast.h"
#include "exception.h"
#include "scanner.h"
#include "compiler.h"

namespace po = boost::program_options;

bool debug = false;

int
main(int argc, char *argv[])
{
	po::variables_map vm;
	po::options_description desc("\n\tTempesta Language (TL)\n"
				     "\nUsage:");
	desc.add_options()
		("debug,d", "Switch on debug mode")
		("exec,e", po::value<std::string>(), "Script to compile")
		("file,f", po::value<std::string>(), "TL script file to load")
		("help,h", "Show this message and exit")
		("print,p", "Print compilation result and exit");
	try {
		// Parse config options.
		po::store(po::parse_command_line(argc, argv, desc), vm);
		po::notify(vm);
		if (vm.count("help")) {
			std::cout << desc << std::endl;
			return 0;
		}
		if (vm.count("debug"))
			debug = true;
	}
	catch (std::exception &e) {
		std::cerr << "Configuration error:  " << e.what() << std::endl;
		return 1;
	}

	try {
		std::string program;

		if (vm.count("file") && vm.count("exec"))
			throw TfwExcept("'file' conflicts with 'exec'");

		if (vm.count("file")) {
			std::string fname = vm["file"].as<std::string>();
			std::ifstream ifs(fname);
			if (!ifs)
				throw TfwExcept("cannot open %s",
						fname.c_str());
			program.assign(std::istreambuf_iterator<char>(ifs),
				       std::istreambuf_iterator<char>());
		}
		else if (vm.count("exec")) {
			program = std::move(vm["exec"].as<std::string>());
		}
		else {
			std::cout << "> ";
			std::getline(std::cin, program);
		}

		tl::Compiler compiler(debug);
		compiler.parse(program);

		if (vm.count("print")) {
			compiler.ast_print();
			return 0;
		}

		// TODO
	}
	catch (TfwExcept &e) {
		std::cerr << "Error: " << e.what() << std::endl;
		return 2;
	}

	return 0;
}
