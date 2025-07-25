/**
 *		Tempesta FW
 *
 * Copyright (C) 2025 Tempesta Technologies, Inc.
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

#include <filesystem>
#include <fstream>

#include "../tfw_logger_config.hh"

#include <gtest/gtest.h>

namespace fs = std::filesystem;

class ConfigTest : public ::testing::Test
{
protected:
	void
	SetUp() override
	{
		temp_dir = fs::temp_directory_path() / "tfw_logger_test";
		fs::create_directories(temp_dir);
	}

	void
	TearDown() override
	{
		if (fs::exists(temp_dir)) {
			fs::remove_all(temp_dir);
		}
	}

	fs::path temp_dir;

	void
	write_config(const fs::path &path, const std::string &content)
	{
		std::ofstream file(path);
		file << content;
	}
};

TEST_F(ConfigTest, DefaultValues)
{
	TfwLoggerConfig config;

	// Test default values
	EXPECT_EQ(config.get_buffer_size(), 4 * 1024 * 1024); // 4MB
	EXPECT_TRUE(config.get_log_path().empty()); // no default set initially

	const auto &ch = config.get_clickhouse();
	EXPECT_EQ(ch.host, "localhost");
	EXPECT_EQ(ch.port, 9000);
	EXPECT_EQ(ch.table_name, "access_log");
	EXPECT_EQ(ch.max_events, 1000);
	EXPECT_EQ(ch.max_wait.count(), 100);
	EXPECT_FALSE(ch.user.has_value());
	EXPECT_FALSE(ch.password.has_value());
}

TEST_F(ConfigTest, LoadValidConfig)
{
	auto config_path = temp_dir / "valid.json";
	write_config(config_path, R"({
		"log_path": "/var/log/test.log",
		"buffer_size": 8388608,
		"clickhouse": {
			"host": "test.host.com",
			"port": 9001,
			"table_name": "test_logs",
			"user": "testuser",
			"password": "testpass",
			"max_events": 500,
			"max_wait_ms": 200
		}
	})");

	auto config = TfwLoggerConfig::load_from_file(config_path);
	ASSERT_TRUE(config.has_value());

	EXPECT_EQ(config->get_log_path(), "/var/log/test.log");
	EXPECT_EQ(config->get_buffer_size(), 8388608);

	const auto &ch = config->get_clickhouse();
	EXPECT_EQ(ch.host, "test.host.com");
	EXPECT_EQ(ch.port, 9001);
	EXPECT_EQ(ch.table_name, "test_logs");
	EXPECT_EQ(ch.user.value(), "testuser");
	EXPECT_EQ(ch.password.value(), "testpass");
	EXPECT_EQ(ch.max_events, 500);
	EXPECT_EQ(ch.max_wait.count(), 200);
}

TEST_F(ConfigTest, LoadConfigWithoutOptionalFields)
{
	auto config_path = temp_dir / "minimal.json";
	write_config(config_path, R"({
		"clickhouse": {
			"host": "minimal.host.com"
		}
	})");

	auto config = TfwLoggerConfig::load_from_file(config_path);
	ASSERT_TRUE(config.has_value());

	// Optional fields should use defaults
	EXPECT_TRUE(config->get_log_path().empty());
	EXPECT_EQ(config->get_buffer_size(), 4 * 1024 * 1024);

	const auto &ch = config->get_clickhouse();
	EXPECT_EQ(ch.host, "minimal.host.com");
	EXPECT_EQ(ch.port, 9000);		// default
	EXPECT_EQ(ch.table_name, "access_log"); // default
	EXPECT_FALSE(ch.user.has_value());
	EXPECT_FALSE(ch.password.has_value());
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
		"buffer_size": 1024,
		"clickhouse": {
			"host": "test.com"
		}
	})");

	auto config = TfwLoggerConfig::load_from_file(config_path);
	EXPECT_FALSE(config.has_value());
}

TEST_F(ConfigTest, ValidationEmptyHost)
{
	auto config_path = temp_dir / "empty_host.json";
	write_config(config_path, R"({
		"clickhouse": {
			"host": ""
		}
	})");

	auto config = TfwLoggerConfig::load_from_file(config_path);
	EXPECT_FALSE(config.has_value());
}

TEST_F(ConfigTest, ValidationInvalidPort)
{
	auto config_path = temp_dir / "invalid_port.json";
	write_config(config_path, R"({
		"clickhouse": {
			"host": "test.com",
			"port": 0
		}
	})");

	auto config = TfwLoggerConfig::load_from_file(config_path);
	EXPECT_FALSE(config.has_value());
}

TEST_F(ConfigTest, ValidationEmptyTableName)
{
	auto config_path = temp_dir / "empty_table.json";
	write_config(config_path, R"({
		"clickhouse": {
			"host": "test.com",
			"table_name": ""
		}
	})");

	auto config = TfwLoggerConfig::load_from_file(config_path);
	EXPECT_FALSE(config.has_value());
}

TEST_F(ConfigTest, ValidationZeroMaxEvents)
{
	auto config_path = temp_dir / "zero_events.json";
	write_config(config_path, R"({
		"clickhouse": {
			"host": "test.com",
			"max_events": 0
		}
	})");

	auto config = TfwLoggerConfig::load_from_file(config_path);
	EXPECT_FALSE(config.has_value());
}

TEST_F(ConfigTest, ValidationNegativeMaxWait)
{
	auto config_path = temp_dir / "negative_wait.json";
	write_config(config_path, R"({
		"clickhouse": {
			"host": "test.com",
			"max_wait_ms": -1
		}
	})");

	auto config = TfwLoggerConfig::load_from_file(config_path);
	EXPECT_FALSE(config.has_value());
}

TEST_F(ConfigTest, CommandLineOverrides)
{
	TfwLoggerConfig config;

	config.override_log_path(fs::path("/override/log.log"));
	config.override_buffer_size(16777216);
	config.override_clickhouse_host("override.host.com");
	config.override_clickhouse_port(9002);
	config.override_clickhouse_table("override_table");
	config.override_clickhouse_user("override_user");
	config.override_clickhouse_password("override_pass");
	config.override_clickhouse_max_events(2000);
	config.override_clickhouse_max_wait(500);

	EXPECT_EQ(config.get_log_path(), "/override/log.log");
	EXPECT_EQ(config.get_buffer_size(), 16777216);

	const auto &ch = config.get_clickhouse();
	EXPECT_EQ(ch.host, "override.host.com");
	EXPECT_EQ(ch.port, 9002);
	EXPECT_EQ(ch.table_name, "override_table");
	EXPECT_EQ(ch.user.value(), "override_user");
	EXPECT_EQ(ch.password.value(), "override_pass");
	EXPECT_EQ(ch.max_events, 2000);
	EXPECT_EQ(ch.max_wait.count(), 500);
}

TEST_F(ConfigTest, NonExistentFile)
{
	auto config =
	    TfwLoggerConfig::load_from_file("/non/existent/file.json");
	EXPECT_FALSE(config.has_value());
}

TEST_F(ConfigTest, FileWithoutClickHouseSection)
{
	auto config_path = temp_dir / "no_clickhouse.json";
	write_config(config_path, R"({
		"buffer_size": 8388608
	})");

	auto config = TfwLoggerConfig::load_from_file(config_path);
	ASSERT_TRUE(config.has_value());

	// Should use default ClickHouse config
	const auto &ch = config->get_clickhouse();
	EXPECT_EQ(ch.host, "localhost");
	EXPECT_EQ(ch.port, 9000);
	EXPECT_EQ(ch.table_name, "access_log");
}

// Table name validation tests
TEST_F(ConfigTest, TableNameValidation_ValidNames)
{
	std::vector<std::string> valid_names = {
		"access_log",
		"table123",
		"Table_123_test",
		"t",
		"_",
		"ACCESS_LOG",
		"test_table_name",
		std::string(128, 'a') // Max length
	};

	for (const auto& table_name : valid_names) {
		auto config_path = temp_dir / ("valid_" + 
			std::to_string(std::hash<std::string>{}(table_name)) + ".json");
		write_config(config_path, R"({
			"clickhouse": {
				"host": "test.com",
				"table_name": ")" + table_name + R"("
			}
		})");

		auto config = TfwLoggerConfig::load_from_file(config_path);
		EXPECT_TRUE(config.has_value()) << "Valid table name should be accepted: " 
						<< table_name;
		
		if (config.has_value()) {
			EXPECT_EQ(config->get_clickhouse().table_name, table_name);
		}
	}
}

TEST_F(ConfigTest, TableNameValidation_InvalidCharacters)
{
	std::vector<std::string> invalid_names = {
		"access-log",     // dash
		"access.log",     // dot
		"access log",     // space
		"access;log",     // semicolon
		"access'log",     // single quote
		"access\"log",    // double quote
		"access/log",     // slash
		"access\\log",    // backslash
		"access&log",     // ampersand
		"access*log",     // asterisk
		"access(log)",    // parentheses
		"access[log]",    // brackets
		"access{log}",    // braces
		"access%log",     // percent
		"access$log",     // dollar
		"access#log",     // hash
		"access@log",     // at
		"access!log",     // exclamation
		"access~log",     // tilde
		"access^log",     // caret
		"access|log",     // pipe
		"access<log",     // less than
		"access>log",     // greater than
		"access?log",     // question mark
		"access+log",     // plus
		"access=log",     // equals
		"access\nlog",    // newline
		"access\tlog",    // tab
		"access\rlog",    // carriage return
	};

	for (const auto& table_name : invalid_names) {
		auto config_path = temp_dir / ("invalid_" + 
			std::to_string(std::hash<std::string>{}(table_name)) + ".json");
		write_config(config_path, R"({
			"clickhouse": {
				"host": "test.com",
				"table_name": ")" + table_name + R"("
			}
		})");

		auto config = TfwLoggerConfig::load_from_file(config_path);
		EXPECT_FALSE(config.has_value()) << "Invalid table name should be rejected: " 
						 << table_name;
	}
}

TEST_F(ConfigTest, TableNameValidation_TooLong)
{
	auto config_path = temp_dir / "too_long.json";
	std::string long_name(129, 'a'); // 129 characters - too long
	write_config(config_path, R"({
		"clickhouse": {
			"host": "test.com",
			"table_name": ")" + long_name + R"("
		}
	})");

	auto config = TfwLoggerConfig::load_from_file(config_path);
	EXPECT_FALSE(config.has_value()) << "Table name longer than 128 characters "
					    "should be rejected";
}

TEST_F(ConfigTest, TableNameValidation_EmptyName)
{
	auto config_path = temp_dir / "empty_name.json";
	write_config(config_path, R"({
		"clickhouse": {
			"host": "test.com",
			"table_name": ""
		}
	})");

	auto config = TfwLoggerConfig::load_from_file(config_path);
	EXPECT_FALSE(config.has_value()) << "Empty table name should be rejected";
}

TEST_F(ConfigTest, TableNameValidation_DefaultNameValidation)
{
	// Test that default table name passes validation
	auto config_path = temp_dir / "default_table.json";
	write_config(config_path, R"({
		"clickhouse": {
			"host": "test.com"
		}
	})");

	auto config = TfwLoggerConfig::load_from_file(config_path);
	ASSERT_TRUE(config.has_value()) << "Default table name should be valid";
	EXPECT_EQ(config->get_clickhouse().table_name, "access_log");
}
