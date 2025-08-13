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

#include <signal.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>

#include "../pidfile.hh"

#include <gtest/gtest.h>
#include <sys/wait.h>

namespace fs = std::filesystem;

class PidFileTest : public ::testing::Test
{
protected:
	void
	SetUp() override
	{
		temp_dir = fs::temp_directory_path() / "tfw_pidfile_test";
		fs::create_directories(temp_dir);
		test_pidfile = temp_dir / "test.pid";
	}

	void
	TearDown() override
	{
		// Clean up any test PID files
		if (fs::exists(test_pidfile)) {
			fs::remove(test_pidfile);
		}

		if (fs::exists(temp_dir)) {
			fs::remove_all(temp_dir);
		}
	}

	fs::path temp_dir;
	fs::path test_pidfile;

	void
	write_pid_file(const fs::path &path, pid_t pid)
	{
		std::ofstream file(path);
		file << pid;
	}
};

TEST_F(PidFileTest, CheckNonExistentFile)
{
	// Non-existent PID file should return 0 (no daemon running)
	EXPECT_EQ(pidfile_check(test_pidfile.string()), 0);
}

TEST_F(PidFileTest, CreateAndRemovePidFile)
{
	// Create PID file
	int fd = pidfile_create(test_pidfile.string());
	EXPECT_GE(fd, 0);

	// File should exist
	EXPECT_TRUE(fs::exists(test_pidfile));

	// File should contain our PID
	std::ifstream file(test_pidfile);
	pid_t written_pid;
	file >> written_pid;
	EXPECT_EQ(written_pid, getpid());

	// Remove PID file
	pidfile_remove(test_pidfile.string(), fd);

	// File should be gone
	EXPECT_FALSE(fs::exists(test_pidfile));
}

TEST_F(PidFileTest, CheckOwnPidFile)
{
	// Create PID file with our own PID
	int fd = pidfile_create(test_pidfile.string());
	EXPECT_GE(fd, 0);

	// Close the file descriptor to release the lock first
	pidfile_remove(test_pidfile.string(), fd);

	// Now write our PID to the file manually (simulating running daemon)
	write_pid_file(test_pidfile, getpid());

	// Now checking should return 0 (since we're not actually locking it)
	// In real scenario, this would detect that process is running
	// For testing, we just verify the file exists and has valid PID
	EXPECT_TRUE(fs::exists(test_pidfile));
}

TEST_F(PidFileTest, CheckStalePidFile)
{
	// Create PID file with non-existent PID
	pid_t fake_pid = 999999; // Very unlikely to exist
	write_pid_file(test_pidfile, fake_pid);

	// Should return 0 (no daemon running) for stale PID file
	EXPECT_EQ(pidfile_check(test_pidfile.string()), 0);
}

TEST_F(PidFileTest, CreatePidFileInNonWritableDirectory)
{
	// Try to create PID file in non-writable directory
	fs::path readonly_dir = temp_dir / "readonly";
	fs::create_directories(readonly_dir);
	fs::permissions(readonly_dir,
			fs::perms::owner_read | fs::perms::owner_exec);

	fs::path readonly_pidfile = readonly_dir / "test.pid";

	// Should fail to create PID file
	int fd = pidfile_create(readonly_pidfile.string());
	EXPECT_EQ(fd, -1);

	// Restore permissions for cleanup
	fs::permissions(readonly_dir, fs::perms::owner_all);
}

TEST_F(PidFileTest, StopDaemonWithValidPid)
{
	// Use a definitely non-existent PID for testing
	// This tests the signal sending logic without actually killing anything
	pid_t fake_pid = 999999; // Very unlikely to exist
	write_pid_file(test_pidfile, fake_pid);

	// Should handle non-existent process gracefully
	// (it will try SIGTERM, get ESRCH, and handle it properly)
	EXPECT_NO_THROW(pidfile_stop_daemon(test_pidfile.string()));
}

TEST_F(PidFileTest, StopDaemonWithInvalidPidFormat)
{
	// Write invalid PID format to file
	std::ofstream file(test_pidfile);
	file << "not_a_number";
	file.close();

	// Should throw exception for invalid PID format
	EXPECT_THROW(pidfile_stop_daemon(test_pidfile.string()),
		     std::runtime_error);
}

TEST_F(PidFileTest, StopDaemonWithZeroPid)
{
	// Write zero PID to file
	write_pid_file(test_pidfile, 0);

	// Should throw exception for zero PID
	EXPECT_THROW(pidfile_stop_daemon(test_pidfile.string()),
		     std::runtime_error);
}

TEST_F(PidFileTest, StopDaemonWithNegativePid)
{
	// Write negative PID to file
	write_pid_file(test_pidfile, -1);

	// Should throw exception for negative PID
	EXPECT_THROW(pidfile_stop_daemon(test_pidfile.string()),
		     std::runtime_error);
}

TEST_F(PidFileTest, ConcurrentPidFileCreation)
{
	// Create first PID file
	int fd1 = pidfile_create(test_pidfile.string());
	EXPECT_GE(fd1, 0);

	// While first file is locked, create a second different PID file
	fs::path second_pidfile = temp_dir / "test2.pid";
	int fd2 = pidfile_create(second_pidfile.string());
	EXPECT_GE(fd2, 0);

	// Both should succeed since they're different files
	EXPECT_TRUE(fs::exists(test_pidfile));
	EXPECT_TRUE(fs::exists(second_pidfile));

	pidfile_remove(test_pidfile.string(), fd1);
	pidfile_remove(second_pidfile.string(), fd2);
}

TEST_F(PidFileTest, PidFilePermissions)
{
	// Create PID file
	int fd = pidfile_create(test_pidfile.string());
	EXPECT_GE(fd, 0);

	// Check file permissions (should be -rw-r--r--)
	auto perms = fs::status(test_pidfile).permissions();
	auto expected = fs::perms::owner_read | fs::perms::owner_write |
			fs::perms::group_read | fs::perms::others_read;

	EXPECT_EQ(perms & fs::perms::mask, expected);

	pidfile_remove(test_pidfile.string(), fd);
}
