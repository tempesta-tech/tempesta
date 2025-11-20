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

#pragma once

class IPluginProcessor
{
public:
	virtual ~IPluginProcessor() = default;

public:
	/**
	 * Returns 1 if the processor is active, 0 if inactive.
	 */
	virtual int is_active() noexcept = 0;

	/**
	 * Requests the processor to stop as soon as possible.
	 */
	virtual void request_stop() noexcept = 0;

	/**
	 * Processes available data. Returns 0 on success (writes consumed count
	 * to *cnt), or a non-zero TUS error code on failure.
	 */
	virtual int consume(int* cnt) noexcept = 0;

	/**
	 * Performs background maintenance work.
	 * Returns 0 on success, or a non-zero TUS error code on failure.
	 */
	virtual int make_background_work() noexcept = 0;

	virtual std::string_view name() const noexcept = 0;
};