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

#include "pidfile.hh"

#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <thread>

#include "error.hh"

constexpr std::chrono::milliseconds STOP_WAIT_INTERVAL{10};

int
tus::pidfile_check(const std::string &fname)
{
	struct flock fl;
	int fd = -1;

	fd = open(fname.c_str(), O_RDWR);
	if (fd == -1) {
		if (errno == ENOENT) {
			errno = 0;
			return 0;
		}
		return -1;
	}

	// Set locking parameters
	memset(&fl, 0, sizeof(fl));
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;
	fl.l_pid = getpid();

	if (fcntl(fd, F_SETLK, &fl) == -1) {
		close(fd);

		// File is locked by another process
		if (errno == EAGAIN || errno == EACCES) {
			errno = 0;
			throw tus::Except("Daemon is already running");
		}
		return -1;
	}

	// Unlock
	fl.l_type = F_UNLCK;
	if (fcntl(fd, F_SETLK, &fl) == -1) {
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

int
tus::pidfile_create(const std::string &fname)
{
	int fd = -1;
	struct flock fl;
	char pid_str[64] = {0};
	int pid_str_len;
	mode_t mask;

	// Get PID as string
	pid_str_len = snprintf(pid_str, sizeof(pid_str), "%ld",
			       static_cast<long>(getpid()));

	// Remove old PID file
	if (access(fname.c_str(), F_OK) != -1) {
		unlink(fname.c_str());
		errno = 0;
	}

	// Create new PID file with appropriate permissions
	mask = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH; // -rw-r--r--
	fd = open(fname.c_str(), O_RDWR | O_CREAT, mask);
	if (fd == -1) {
		std::cerr << "Cannot create pidfile: " << fname << std::endl;
		return -1;
	}

	// Write PID
	if (write(fd, &pid_str[0], pid_str_len) == -1) {
		std::cerr << "Cannot write pid into pidfile: " << fname
			  << std::endl;
		close(fd);
		return -1;
	}

	// Set locking parameters
	memset(&fl, 0, sizeof(fl));
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;
	fl.l_pid = getpid();

	// Lock file
	if (fcntl(fd, F_SETLK, &fl) == -1) {
		close(fd);
		std::cerr << "Cannot lock pidfile: " << fname << std::endl;
		return -1;
	}

	return fd;
}

void
tus::pidfile_remove(const std::string &fname, int fd)
{
	struct flock fl;

	// Set unlocking parameters
	memset(&fl, 0, sizeof(fl));
	fl.l_type = F_UNLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;

	// Release lock
	if (fcntl(fd, F_SETLK, &fl) == -1)
		std::cerr << "Cannot unlock pidfile: " << fname << std::endl;

	// Close file descriptor
	close(fd);

	// Remove PID file
	if (unlink(fname.c_str()) == -1)
		std::cerr << "Cannot remove pidfile: " << fname << std::endl;
}

void
tus::pidfile_stop_daemon(const std::string &fname)
{
	pid_t pid;
	std::ifstream pid_file(fname);

	if (!pid_file)
		throw tus::Except("No PID file found at '{}'. "
			     "Is the daemon running?", fname);

	pid_file >> pid;
	pid_file.close();

	if (pid <= 0)
		throw tus::Except("Invalid PID in PID file: {}", pid);

	// Send SIGTERM to daemon
	if (kill(pid, SIGTERM) < 0) {
		if (errno == ESRCH) {
			// Process not running - remove stale PID file
			unlink(fname.c_str());
			return;
		}
		throw tus::Except("Failed to stop daemon (PID {}): {}",
			     pid, strerror(errno));
	}

	// Wait for graceful shutdown
	constexpr int GRACEFUL_WAIT_ITERATIONS = 50; // 50 * 10ms = 500ms
	for (int i = 0; i < GRACEFUL_WAIT_ITERATIONS; ++i) {
		if (kill(pid, 0) == -1 && errno == ESRCH)
			return; // Process died gracefully

		std::this_thread::sleep_for(STOP_WAIT_INTERVAL);
	}

	// Graceful shutdown failed, try SIGKILL
	if (kill(pid, SIGKILL) < 0) {
		if (errno == ESRCH)
			return; // Process already stopped

		throw tus::Except("Failed to kill daemon (PID {}): {}",
			     pid, strerror(errno));
	}

	// Wait for force kill to take effect
	constexpr int FORCE_WAIT_ITERATIONS = 50; // 50 * 10ms = 500ms
	for (int i = 0; i < FORCE_WAIT_ITERATIONS; ++i) {
		if (kill(pid, 0) == -1 && errno == ESRCH)
			return; // Process force-killed

		std::this_thread::sleep_for(STOP_WAIT_INTERVAL);
	}

	// If we get here, something is seriously wrong
	throw tus::Except("Failed to stop daemon (PID {}) even with SIGKILL", pid);
}
