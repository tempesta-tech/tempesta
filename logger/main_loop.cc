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

#include "main_loop.hh"

#include <chrono>
#include <thread>
#include <vector>

#include <spdlog/spdlog.h>

namespace {

void
run_thread(Reader reader)
{
	constexpr std::chrono::milliseconds poll_interval(10);

	while (reader.run())
		std::this_thread::sleep_for(poll_interval);
}

} // namespace

void
run_main_loop(const ReaderFactory &reader_factory)
{
	/*
	 * Use sysconf() instead of std::thread::hardware_concurrency() because
	 * it respects process CPU affinity, cgroups, and container limits,
	 * is more reliable on NUMA systems and machines with 100+ CPUs while
	 * hardware_concurrency() is just a "hint".
	 */
	const size_t cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
	if (cpu_count <= 0) {
		spdlog::error("Cannot determine CPU count");
		return;
	}

	spdlog::info("Starting {} worker threads...", cpu_count);

	std::vector<std::thread> threads;
	for (size_t i = 0; i < cpu_count; ++i)
		if (auto reader = reader_factory(i))
			threads.emplace_back(run_thread, std::move(*reader));

	if (threads.size() == cpu_count)
		spdlog::info("All {} worker threads started", cpu_count);
	else
		spdlog::error("Only {} of {} worker threads started",
			      threads.size(), cpu_count);

	for (auto &t : threads)
		if (t.joinable())
			t.join();
}
