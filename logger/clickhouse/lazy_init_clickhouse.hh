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
#include <memory>

#include "clickhouse_iface.hh"
#include "reconnect_policy.hh"

/**
 * LazyInitClickhouse initializes the ClickHouse client lazily and respects
 * the reconnection policy delays before retrying failed initializations
 */
class LazyInitClickhouse final: public IClickhouse
{
public:
	using Ptr = std::unique_ptr<IClickhouse>;

public:
	LazyInitClickhouse(std::function<Ptr()> factory)
		: factory_(std::move(factory))
	{}

	~LazyInitClickhouse() override
	{};

public:
	virtual bool ensure_connected() noexcept override
	{
		auto ptr = get();
		if (!ptr) [[unlikely]]
			return false;
		return (*ptr)->ensure_connected();
	}

	virtual bool execute(const std::string &query) noexcept override
	{
		auto ptr = get();
		if (!ptr) [[unlikely]]
			return false;
		return (*ptr)->execute(query);
	}

	virtual bool
	flush(const std::string &table_name, ch::Block &block) noexcept override
	{
		auto ptr = get();
		if (!ptr) [[unlikely]]
			return false;
		return (*ptr)->flush(table_name, block);
	}

private:
	/**
	 * Try to get initialized object.
	 * Returns nullptr if connection is unavailable.
	 */
	Ptr* get() noexcept
	{
		if (ptr_) [[likely]]
			return &ptr_;

		return try_initialize() ? &ptr_ : nullptr;
	}

	bool try_initialize() noexcept
	{
		if (!policy_.can_attempt())
			return false;

		try {
			ptr_ = factory_();
			policy_.on_success();
			return true;
		}
		catch (...)
		{
			ptr_.reset();
			policy_.on_failure();
			return false;
		}
	}

private:
	ReconnectPolicy		policy_;
	std::function<Ptr()>	factory_;
	Ptr			ptr_;
};
