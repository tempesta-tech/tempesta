/**
 *		Tempesta DB User-space Library
 *
 * Error/exceptions handling.
 *
 * Copyright (C) 2015-2018 Tempesta Technologies.
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
#ifndef __EXCEPTION_H__
#define __EXCEPTION_H__

#include <assert.h>
#include <errno.h>
#include <execinfo.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sstream>
#include <string>

extern bool debug;

class TdbExcept : public std::exception {
private:
	static const size_t maxmsg = 256;
	std::string str_;

public:
	TdbExcept(const char* fmt, ...) noexcept
	{
		va_list ap;
		char msg[maxmsg];
		va_start(ap, fmt);
		vsnprintf(msg, maxmsg, fmt, ap);
		va_end(ap);
		str_ = msg;

		// Add system error code (errno).
		if (errno) {
			std::stringstream ss;
			ss << " (" << strerror(errno)
				<< ", errno=" << errno << ")";
			str_ += ss.str();
		}

		// Add call trace symbols.
		if (debug)
			call_trace();
	}

	~TdbExcept() noexcept
	{}

	const char *
	what() const noexcept
	{
		return str_.c_str();
	}

private:
	void
	call_trace() noexcept
	{
		// Do not print more that BTRACE_CALLS_NUM calls in the trace.
		static const size_t BTRACE_CALLS_NUM	= 32;

		void *trace_addrs[BTRACE_CALLS_NUM];
		int n_addr = backtrace(trace_addrs,
				sizeof(trace_addrs) / sizeof(trace_addrs[0]));
		if (!n_addr)
			return;

		char **btrace = backtrace_symbols(trace_addrs, n_addr);
		if (!btrace)
			return;

		for (auto i = 0; i < n_addr; ++i)
			str_ += std::string("\n\t") + btrace[i];

		free(btrace);
	}
};

#endif // __EXCEPTION_H__
