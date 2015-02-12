#include <sys/ioctl.h>

#include <iostream>

#include <boost/program_options.hpp>

int
main(int argc, char *argv[])
{
	__po::variables_map vm;
	__po::options_description desc("Usage");
	desc.add_options()
		("help,h", "show this message and exit")
	;

	try {
		// Parse config options
		__po::store(__po::parse_command_line(argc, argv, desc), vm);
		__po::notify(vm);
		if (vm.count("help")) {
			std::cout << desc << std::endl;
			return 0;
		}

		// Check configuration
		// TODO
	}
	catch (std::exception& e) {
		std::cerr << "Configuration error:  " << e.what() << std::endl;
		return 1;
	}

	try {
		// TODO
	}
	} catch (...) {
		std::cerr << "Unknown exception!" << std::endl;
	}

	return 0;
}
