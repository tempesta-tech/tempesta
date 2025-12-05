/**
 *		Tempesta FW
 *
 * Error handling - rules of thumb:
 * 1. prefer std::expected and std::optional on the data plane to reduce
 *    overhead and improve reliability;
 * 2. it's OK to use exceptions on control path for easier error management.
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
#pragma once

#include <array>
#include <cassert>
#include <cstdio>
#include <expected>
#include <fmt/format.h>
#include <source_location>
#include <sstream>
#include <string>
#include <stdexcept>
#include <utility>

#include <boost/system/system_error.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/linux_error.hpp>

namespace tus {

/*
 * ------------------------------------------------------------------------
 *	std::expected API for the data path
 * ------------------------------------------------------------------------
 */
enum class Err : int {
	// Clickhouse error.
	DB_SRV_FATAL,
	DB_CLT_TRANSIENT,
};

class ErrorCategory : public std::error_category {
public:
	const char *
	name() const noexcept override
	{
		return "error";
	}

	std::string
	message(int e) const override
	{
		switch (static_cast<Err>(e)) {
		case Err::DB_SRV_FATAL:
			return "Database unrecoverable server error";
		case Err::DB_CLT_TRANSIENT:
			return "Database recoverable client error";
		default:
			return "Unknown error";
		}
	}
};

const std::error_category &tfw_error_category();

inline std::error_code
make_error_code_from_int(int e) noexcept
{
	return {e, tfw_error_category()};
}

inline std::error_code
make_error_code(Err e) noexcept
{
	return make_error_code_from_int(static_cast<int>(e));
}

[[nodiscard]] inline auto
error(Err e) noexcept
{
	return std::unexpected(std::error_code(std::to_underlying(e),
					       tfw_error_category()));
}

template <typename T>
using Error = std::expected<T, std::error_code>;

/*
 * ------------------------------------------------------------------------
 *	std::exception API for the control path
 * ------------------------------------------------------------------------
 */

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
			ss << " (" << ec.message()
			   << ", errno=" << ec.value() << ")";
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
	       const std::source_location &loc =
			std::source_location::current()) noexcept
		: Exception(format_loc(fmt, std::forward<Args>(args)..., loc))
	{}

private:
	static std::string
	format_loc(fmt::format_string<Args...> fmt, Args&&... args,
		   const std::source_location &loc) noexcept
	{
		std::string s(
			fmt::format(
				"{} (at {}:{} in {})",
				fmt::format(fmt, std::forward<Args>(args)...),
				loc.file_name(), loc.line(),
				loc.function_name()));

		return format_syserr(s);
	}
};

template <typename... Args>
Except(fmt::format_string<Args...>, Args&&...) -> Except<Args...>;

} // tus namespace

namespace std {
	template<>
	struct is_error_code_enum<tus::Err> : true_type
	{};
}
