/**
 *		Tempesta FW
 *
 * ClickHouse UDF for printing binary data produced by tfw_logger in a
 * human-readable format.
 *
 * Copyright (C) 2026 Tempesta Technologies, Inc.
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

#include <array>
#include <cstring>
#include <iostream>
#include <span>
#include <string>
#include <vector>

#include "../../fw/event_log.h"

constexpr auto make_log_formats() {
	std::array<const char *, TFW_LOG_EVENT_MAX> arr{};

#define DEFINE_EVENT(name, bin_fmt, text_fmt)			\
	arr[TfwLogEventType::name] = text_fmt;
#define DEFINE_EVENT_NO_PARAMS(name, text_str)			\
	arr[TfwLogEventType::name] = text_str;
#include "../../fw/event_types.h"
#undef DEFINE_EVENT
#undef DEFINE_EVENT_NO_PARAMS
	return arr;
}

constexpr auto event_formats = make_log_formats();
/* The formatted message is twice the size of the binary message. */
constexpr size_t MAX_BUF_SIZE = TFW_EVENT_LOG_MAX_BIN_LEN * 2;

namespace {

template<typename T> bool
move_num_arg_to_buf(std::span<char> &args, std::span<char> &buf)
{
	if (sizeof(T) > args.size())
		return false;

	T arg;
	std::memcpy(&arg, args.data(), sizeof(arg));
	std::string arg_str = std::to_string(arg);

	if (arg_str.size() > buf.size())
		return false;

	std::memcpy(buf.data(), arg_str.data(), arg_str.size());
	buf = buf.subspan(arg_str.size());

	args = args.subspan(sizeof(T));

	return true;
}

std::span<char>
format_record(TfwLogEventType event_type, std::span<char> args,
	      std::array<char, MAX_BUF_SIZE> &buf)
{
	const char *fmt{nullptr};
	std::span<char> str{buf};
	unsigned char type{FORMAT_TYPE_NONE};
	int32_t precision{0};

	auto make_record = [&]()
	{
		return std::span(buf.data(), buf.size() - str.size());
	};

	if (event_type >= TFW_LOG_EVENT_MAX ||
	    event_type == TFW_LOG_EVENT_INVALID)
		return make_record();

	fmt = event_formats[event_type];

	while (*fmt) {
		if (!str.size())
			return make_record();

		int read = format_decode(fmt, &type, &precision);

		switch (type) {
		case FORMAT_TYPE_INVALID:
			return make_record();
		case FORMAT_TYPE_CHAR:
		{
			if (sizeof(char) > str.size() ||
			    sizeof(char) > args.size())
				return make_record();

			std::memcpy(str.data(), args.data(), sizeof(char));
			str = str.subspan(sizeof(char));
			args = args.subspan(sizeof(char));
			break;
		}
		case FORMAT_TYPE_STR:
		{
			if (sizeof(uint16_t) > args.size())
				return make_record();
			uint16_t str_len;
			std::memcpy(&str_len, args.data(), sizeof(str_len));
			if (str_len > str.size())
				return make_record();
			if (sizeof(uint16_t) + str_len > args.size())
				return make_record();

			std::memcpy(str.data(), args.data() + sizeof(uint16_t),
				    str_len);

			str = str.subspan(str_len);

			args = args.subspan(sizeof(uint16_t) + str_len);
			break;
		}
		case FORMAT_TYPE_UBYTE:
		{
			if (!move_num_arg_to_buf<uint8_t>(args, str))
				return make_record();
			break;
		}
		case FORMAT_TYPE_BYTE:
		{
			if (!move_num_arg_to_buf<int8_t>(args, str))
				return make_record();
			break;
		}
		case FORMAT_TYPE_USHORT:
		{
			if (!move_num_arg_to_buf<uint16_t>(args, str))
				return make_record();
			break;
		}
		case FORMAT_TYPE_SHORT:
		{
			if (!move_num_arg_to_buf<int16_t>(args, str))
				return make_record();
			break;
		}
		case FORMAT_TYPE_UINT:
		{
			if (!move_num_arg_to_buf<uint32_t>(args, str))
				return make_record();
			break;
		}
		case FORMAT_TYPE_INT:
		{
			if (!move_num_arg_to_buf<int32_t>(args, str))
				return make_record();
			break;
		}
		case FORMAT_TYPE_ULONG:
		{
			if (!move_num_arg_to_buf<uint64_t>(args, str))
				return make_record();
			break;
		}
		case FORMAT_TYPE_LONG:
		{
			if (!move_num_arg_to_buf<int64_t>(args, str))
				return make_record();
			break;
		}
		case FORMAT_TYPE_PRECISION:
			/*
			 * Simply parse precision specifier but don't apply it.
			 * Always interpret %.*s as *s, because we always have
			 * size of the string in binary representation
			 */
			break;
		default:
			auto len = std::min<std::size_t>(read, str.size());

			if (len) {
				std::memcpy(str.data(), fmt, len);
				str = str.subspan(len);
			}
		}

		fmt += read;
	}

	return make_record();
}

template<typename T>
requires std::is_trivially_copyable_v<T> bool
cin_read(T &value)
{
	return static_cast<bool>(
		std::cin.read(reinterpret_cast<char*>(&value), sizeof(T)));
}

// Read LEB128 encoded size from std::cin
bool
cin_read_var_size(uint64_t &value)
{
	value = 0;
	uint32_t shift = 0;
	unsigned char byte;

	do {
		if (!std::cin.read(reinterpret_cast<char *>(&byte), 1))
			return false;
		value |= uint64_t(byte & 0x7F) << shift;
		shift += 7;
	} while ((byte & 0x80) != 0 && shift < 64);

	return true;
}

bool
cin_read_binary_row(std::vector<char> &out)
{
	uint64_t size;

	if (!cin_read_var_size(size))
		return false;

	out.resize(size);

	return static_cast<bool>(std::cin.read(out.data(), size));
}

/**
 * Write LEB128 encoded size into std::cout
 * See reference https://en.wikipedia.org/wiki/LEB128#Encode_unsigned_integer
 */
void
cout_write_var_size(uint64_t value)
{
	do {
		unsigned char byte = value & 0x7f;
		value >>= 7;

		if (value != 0)
			byte |= 0x80;
		std::cout.write(reinterpret_cast<const char *>(&byte), 1);
	} while (value != 0);
}

void
cout_write_row(const std::span<const char> &s)
{
	cout_write_var_size(s.size());
	std::cout.write(s.data(), s.size());
}

} // anonymous namespace

int
main()
try
{
	uint16_t event_type;
	std::vector<char> event_body;
	std::array<char, MAX_BUF_SIZE> buffer;
	constexpr std::string_view broken_msg{"<broken record>"};

	while (cin_read(event_type)) {
		if (!cin_read_binary_row(event_body))
			throw std::runtime_error("Can't read event body");

		TfwLogEventType tfw_ev_type =
			static_cast<TfwLogEventType>(event_type);

		auto record = format_record(tfw_ev_type, event_body, buffer);
		if (!record.size())
			cout_write_row(broken_msg);
		else
			cout_write_row(record);
	}

    return 0;
}
catch (const std::exception& e)
{
    std::cerr << "Fatal error: " << e.what() << '\n';
    return 1;
}
catch (...)
{
    std::cerr << "Fatal error: unknown exception\n";
    return 1;
}
