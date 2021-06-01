/**
 * Multithreaded client for performance testing of Synchronous Socket API.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
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
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <iostream>
#include <thread>

static const size_t THR_N = 16;
static const size_t CONNECTIONS = 64; // connections per thread
static const size_t MESSAGES = 4096;
static int msg[MSG_SZ];
static unsigned short PORT = 5000;
static struct sockaddr_in saddr = {};

void
run_tcp_load()
{
	int sd[CONNECTIONS] = { 0 };

	for (size_t i = 0; i < CONNECTIONS; ++i) {
		sd[i] = socket(PF_INET, SOCK_STREAM, 0);
		if (sd[i] < 0) {
			sd[i] = 0;
			std::cerr << "can't create socket #" << i << std::endl;
		}

		// Send segments as soon as possible.
		const int o = 1;
		if (setsockopt(sd[i], IPPROTO_TCP, TCP_NODELAY, &o, sizeof(o)))
			std::cerr << "can't set TCP_NODELAY on socket #" << i
				<< std::endl;

		if (connect(sd[i], (struct sockaddr *)&saddr, sizeof(saddr))) {
			std::cerr << "can't connect on socket #" << i
				<< std::endl;
			close(sd[i]);
			sd[i] = 0;
		}
	}

	for (size_t i = 0; i < CONNECTIONS; ++i) {
		if (!sd[i])
			continue;
		for (size_t m = 0; m < MESSAGES; ++m)
			if (send(sd[i], msg, sizeof(msg), 0) != sizeof(msg)) {
				std::cerr << "can't send on socket #"
					<< i << std::endl;
				close(sd[i]);
				sd[i] = 0;
			}
	}

	for (size_t i = 0; i < CONNECTIONS; ++i)
		if (sd[i])
			close(sd[i]);
}

int
main(int argc, char *argv[])
{
	if (argc < 2) {
		std::cerr << "Please specify server address" << std::endl;
		return 1;
	}

	struct rlimit rlim;
	if (getrlimit(RLIMIT_NOFILE, &rlim)) {
		std::cerr << "getrlimit() failed" << std::endl;
	} else {
		if (rlim.rlim_cur < THR_N * CONNECTIONS
		    || rlim.rlim_max < THR_N * CONNECTIONS)
		{
			std::cerr << "please adjust limit of open files to "
				<< THR_N * CONNECTIONS << std::endl;
			return 2;
		}
	}

	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(PORT);
	if (inet_pton(AF_INET, argv[1], &saddr.sin_addr.s_addr) <= 0) {
		std::cerr << "Bad address: " << argv[1] << std::endl;
		return 3;
	}

	// Initialize message - the same for all transmission.
	for (size_t i = 0; i < MSG_SZ; ++i)
		msg[i] = i;

	std::thread thr[THR_N];
	for (size_t i = 0; i < THR_N; ++i)
		thr[i] = std::thread{ run_tcp_load };
	for (size_t i = 0; i < THR_N; ++i)
		thr[i].join();

	return 0;
}
