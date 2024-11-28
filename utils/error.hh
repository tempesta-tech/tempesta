/**
 *		Tempesta FW
 *
 * Copyright (C) 2024 Tempesta Technologies, Inc.
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

#include <array>
#include <cassert>
#include <cstdio>
#include <fmt/format.h>
#include <source_location>
#include <sstream>
#include <string>
#include <stdexcept>

#include <boost/system/system_error.hpp>
#include <boost/system/error_code.hpp>

class Exception : public std::runtime_error {
public:
	Exception(std::string s) noexcept
		: std::runtime_error(format_syserr(s))
	{}

protected:
	// Add system error code (errno).
	static std::string
	format_syserr(std::string msg) noexcept
	{
		namespace sys = boost::system;

		auto ec = sys::error_code(errno, sys::system_category());
		if (ec) {
			std::stringstream ss;
			ss << " (" << ec.message() << ", errno=" << ec.value() << ")";
			msg += ss.str();
		}

		return msg;
	}
};

template <typename... Args>
class Except : public Exception {
public:
	Except() =delete;
	Except(const Except &) =delete;
	Except &operator=(const Except &) =delete;
	~Except() override =default;

	Except(fmt::format_string<Args...> fmt, Args&&... args,
	       const std::source_location &loc = std::source_location::current()) noexcept
		: Exception(format_loc(fmt, std::forward<Args>(args)..., loc))
	{}

private:
	static std::string
	format_loc(fmt::format_string<Args...> fmt, Args&&... args,
		   const std::source_location &loc) noexcept
	{
		std::string s(fmt::format("{} (at {}:{} in {})",
					  fmt::format(fmt, std::forward<Args>(args)...),
					  loc.file_name(), loc.line(),
					  loc.function_name()));

		return format_syserr(s);
	}
};

template <typename... Args>
Except(fmt::format_string<Args...>, Args&&...) -> Except<Args...>;
