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

#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>

#include "tfw_logger_config.hh"

namespace fs = std::filesystem;

class ConfigTest : public ::testing::Test
{
protected:
	void SetUp() override
	{
		temp_dir = fs::temp_directory_path() / "tfw_logger_test";
		fs::create_directories(temp_dir);
	}

	void TearDown() override
	{
		if (fs::exists(temp_dir))
		{
			fs::remove_all(temp_dir);
		}
	}

	fs::path temp_dir;

	void write_config(const fs::path &path, const std::string &content)
	{
		std::ofstream file(path);
		file << content;
	}
};

TEST_F(ConfigTest, DefaultValues)
{
	TfwLoggerConfig config;

	EXPECT_EQ(config.get_buffer_size(), 4 * 1024 * 1024);
	EXPECT_EQ(config.get_cpu_count(), 0);

	const auto &ch = config.get_clickhouse();
	EXPECT_EQ(ch.host, "localhost");
	EXPECT_EQ(ch.port, 9000);
	EXPECT_EQ(ch.max_events, 1000);
}

TEST_F(ConfigTest, LoadValidConfig)
{
	auto config_path = temp_dir / "valid.json";
	write_config(config_path, R"({
        "buffer_size": 8388608,
        "cpu_count": 4,
        "clickhouse": {
            "host": "test.host.com",
            "port": 9001,
            "user": "testuser",
            "max_events": 500
        }
    })");

	auto config = TfwLoggerConfig::load_from_file(config_path);
	ASSERT_TRUE(config.has_value());

	EXPECT_EQ(config->get_buffer_size(), 8388608);
	EXPECT_EQ(config->get_cpu_count(), 4);

	const auto &ch = config->get_clickhouse();
	EXPECT_EQ(ch.host, "test.host.com");
	EXPECT_EQ(ch.port, 9001);
	EXPECT_EQ(ch.user.value(), "testuser");
	EXPECT_EQ(ch.max_events, 500);
}

TEST_F(ConfigTest, InvalidJSON)
{
	auto config_path = temp_dir / "invalid.json";
	write_config(config_path, R"({
        "buffer_size": 1024,
        "invalid": 
    })");

	auto config = TfwLoggerConfig::load_from_file(config_path);
	EXPECT_FALSE(config.has_value());
}

TEST_F(ConfigTest, ValidationBufferTooSmall)
{
	auto config_path = temp_dir / "small_buffer.json";
	write_config(config_path, R"({
        "buffer_size": 1024
    })");

	auto config = TfwLoggerConfig::load_from_file(config_path);
	EXPECT_FALSE(config.has_value());
}

TEST_F(ConfigTest, CommandLineOverrides)
{
	TfwLoggerConfig config;

	config.override_buffer_size(16777216);
	config.override_cpu_count(8);
	config.override_clickhouse_host("override.host.com");
	config.override_clickhouse_port(9002);

	EXPECT_EQ(config.get_buffer_size(), 16777216);
	EXPECT_EQ(config.get_cpu_count(), 8);
	EXPECT_EQ(config.get_clickhouse().host, "override.host.com");
	EXPECT_EQ(config.get_clickhouse().port, 9002);
}

TEST_F(ConfigTest, SaveAndLoad)
{
	TfwLoggerConfig config;
	config.override_clickhouse_host("save.test.com");
	config.override_buffer_size(12345678);

	auto save_path = temp_dir / "saved.json";
	EXPECT_TRUE(config.save_to_file(save_path));

	auto loaded = TfwLoggerConfig::load_from_file(save_path);
	ASSERT_TRUE(loaded.has_value());

	EXPECT_EQ(loaded->get_clickhouse().host, "save.test.com");
	EXPECT_EQ(loaded->get_buffer_size(), 12345678);
}

TEST_F(ConfigTest, NonExistentFile)
{
	auto config = TfwLoggerConfig::load_from_file("/non/existent/file.json");
	EXPECT_FALSE(config.has_value());
}
