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

#pragma once

#include <string>

namespace tus {

/**
 * Check if daemon is already running by examining PID file.
 *
 * @param fname Path to PID file
 * @return 0 if no daemon is running, -1 on error
 * @throws Exception if daemon is already running
 */
int
pidfile_check(const std::string &fname);

/**
 * Create and lock PID file.
 *
 * @param fname Path to PID file
 * @return File descriptor of locked PID file, -1 on error
 */
int
pidfile_create(const std::string &fname);

/**
 * Remove PID file and release lock.
 *
 * @param fname Path to PID file
 * @param fd File descriptor of PID file
 */
void
pidfile_remove(const std::string &fname, int fd);

/**
 * Stop daemon by reading PID from file and sending SIGTERM.
 *
 * @param fname Path to PID file
 * @throws Exception if PID file not found or daemon stop failed
 */
void
pidfile_stop_daemon(const std::string &fname);

} // tus namespace
