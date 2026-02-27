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
 *	std::expected API for the data path:
 * 		return std::expected<result, Error<Enum, Category>>
 * ------------------------------------------------------------------------
 */
/**
 * ErrorCategoryBase defines a compile-time contract for error categories.
 */
template <typename Derived>
struct ErrorCategoryBase
 {
	/**
	 * We could use the CategoryId enum instead of uint16_t, but this would make
	 * Tempesta aware of Escudo modules. On the other hand, having a single enum
	 * for all categories is more reliable.
	 */
	static constexpr uint16_t id()
	{
		static_assert(requires { Derived::Id; },
			"Category must define: static constexpr uint16_t Id");
		return Derived::Id;
	}

	static constexpr std::string_view name()
	{
		static_assert(requires { Derived::Name; },
			"Category must define: static constexpr std::string_view Name");
		return Derived::Name;
	}
};

struct TfwCategory: ErrorCategoryBase<TfwCategory>
{
	static constexpr uint16_t Id = 0x1000;
	static constexpr std::string_view Name = "tfw";
};

/**
 * Each Error instance is tied to a specific error enum (Enum) and a category
 * (Category) defined via ErrorCategoryBase.
 * Categories provide stable identifiers and names, enforced at compile-time.
 * Each error has a combined integer code() composed of the category ID and the
 * enum value.
 */
template <typename Enum, typename Category>
class Error
{
public:
	constexpr Error(Enum e): enum_val_(static_cast<uint16_t>(e))
		, category_id_(Category::id()), category_name_(Category::name())
	{
		static_assert(std::is_same_v<std::underlying_type_t<Enum>, uint16_t>,
			      "Enum underlying type must be uint16_t");
		code_ = compose_code(category_id_, enum_val_);
	}

public:
	/* Code to return outside the module*/
	constexpr int
	code() const noexcept
	{
		return code_;
	}

	constexpr std::string_view
	category_name() const noexcept
	{
		return category_name_;
	}

	constexpr std::string_view
	message() const
	{
		return message(static_cast<Enum>(enum_val_));
	}

	/* Message with category ane error */
	friend std::ostream&
	operator<<(std::ostream& os, const Error& err)
	{
		return os << err.category_name_ << ": " << err.message()
			  << " (0x" << std::hex << err.code_ << std::dec << ")";
	}

private:
	static constexpr int
	compose_code(uint16_t category_id, uint16_t enum_val) noexcept
	{
		return (category_id << 16) | enum_val;
	}

private:
	int			code_;
	uint16_t		enum_val_;
	uint16_t		category_id_;
	std::string_view	category_name_;
};

inline std::string
code_to_hex(int code)
{
	bool is_neg = code < 0;
	int abs_code = is_neg ? -code : code;

	return fmt::format("{}0x{:08X}", is_neg ? "-" : "", abs_code);
}

/**
 * TODO: Design a mechanism to recover the category and enum from an error code,
 * so that a full trace of the error can be reconstructed within a module. Enable
 * throwing exceptions carrying the Error object, so that at the catch site the
 * relevant information—category, enum, code, and message—can be easily retrieved
 * for tracing, diagnostics, and returning the error code outside the module.
 */

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
