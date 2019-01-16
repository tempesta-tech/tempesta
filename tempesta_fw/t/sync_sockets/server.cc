/**
 * Multiplexing user-space server for performance testing of
 * Synchronous Socket API.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2018 Tempesta Technologies, Inc.
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
#include <assert.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <iostream>

static const size_t MAX_CONNECTIONS = 1000 * 1000;
static const int READ_SZ = MSG_SZ * sizeof(int);

/**
 * Counts number of requests per second and prints the best one.
 */
class RequestsStatistics {
public:
	RequestsStatistics()
		: last_ts_(time(NULL)),
		curr_(0),
		max_(0)
	{}

	void
	update(int events)
	{
		time_t t = time(NULL);
		if (last_ts_ == t) {
			curr_ += events;
		} else {
			// recharge
			if (curr_ > max_)
				max_ = curr_;
			curr_ = events;
			last_ts_ = t;
		}
	}

	void
	print()
	{
		std::cout << "Best rps: " << (std::max(max_, curr_) / READ_SZ)
			<< std::endl;
	}

private:
	time_t last_ts_;
	unsigned int curr_;
	unsigned int max_;
};

static unsigned short PORT = 5000;
static int msg[MSG_SZ];
static unsigned int g_counter = 0;
RequestsStatistics stat;

void
sig_handler(int sig_num)
{
	std::cout << "received signal " << sig_num << std::endl;
	exit(0);
}

void
set_sig_handlers()
{
	struct sigaction sa;

	sigemptyset (&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGHUP);
	sigaddset(&sa.sa_mask, SIGINT);
	sigaddset(&sa.sa_mask, SIGQUIT);
	sigaddset(&sa.sa_mask, SIGPIPE);
	sigaddset(&sa.sa_mask, SIGTERM);
	sigaddset(&sa.sa_mask, SIGUSR1);
	sigaddset(&sa.sa_mask, SIGUSR2);

	sa.sa_handler = sig_handler;
	sa.sa_flags = SA_RESTART;

	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);
}

void
print_statistics()
{
	stat.print();
}

int
sd_add_to_epoll(int efd, int sd)
{
	epoll_event ev = {};
	ev.events = EPOLLIN;
	ev.data.fd = sd;
	if (epoll_ctl(efd, EPOLL_CTL_ADD, sd, &ev) < 0) {
		std::cerr << "can't add socket " << sd << " to epoll"
			<< std::endl;
		return 1;
	}
	return 0;
}

void
set_nonblock(int sd, const char *desc)
{
	int flags = fcntl(sd, F_GETFL, 0);
	if (!(flags & O_NONBLOCK))
		if(fcntl(sd, F_SETFL, flags | O_NONBLOCK) < 0) {
			std::cerr << "can't make " << desc
				<< " socket nonblocking" << std::endl;
			exit(1);
		}
}

void
work_loop(int listen_sd, int wd)
{
	struct epoll_event ev[64];
	int n = epoll_wait(wd, ev, 64, -1);
	if (n < 1) {
		std::cerr << "epoll wait failed" << std::endl;
		exit(1);
	}

	for (int i = 0; i < n; ++i) {
		if (ev[i].data.fd == listen_sd) {
			// Process new connection.
			while (1) {
				int sd = accept(listen_sd, NULL, NULL);
				if (sd < 1) {
					if (errno == EAGAIN)
						break;
					std::cerr << "can't accept a socket"
						<< std::endl;
					exit(1);
				}

				set_nonblock(sd, "work");

				if (sd_add_to_epoll(wd, sd))
					exit(1);
		
				stat.update(READ_SZ);
			}
		}
		else {
			// Process data on established connections.
			assert(ev[i].events & EPOLLIN);

			int count = 0, r;
			do {
				r = recv(ev[i].data.fd, msg, READ_SZ, 0);
				if (!r) {
					epoll_ctl(wd, EPOLL_CTL_DEL,
					  ev[i].data.fd, NULL);
					close(ev[i].data.fd);
					count = READ_SZ;
				}
				else if (r < 0 && errno != EAGAIN) {
					std::cerr << "failed to read on"
						<< " socket " << ev[i].data.fd
						<< " (ret=" << r << ")"
						<< std::endl;
					exit(1);
				}

				// Just do some useless work.
				if (r > 0) {
					for (int j = 0; j < r / 4; ++j)
						g_counter += msg[j];
					count += r;
				}
			} while (r > 0);

			stat.update(count);
		}
	}
}

int
main(int argc, char *argv[])
{
	struct rlimit rlim;
	if (getrlimit(RLIMIT_NOFILE, &rlim)) {
		std::cerr << "getrlimit() failed" << std::endl;
	} else {
		if (rlim.rlim_cur < MAX_CONNECTIONS
		    || rlim.rlim_max < MAX_CONNECTIONS)
		{
			std::cerr << "please adjust limit of open files to "
				<< MAX_CONNECTIONS << std::endl;
			exit(1);
		}
	}

	set_sig_handlers();
	atexit(print_statistics);

	int listen_sd = socket(PF_INET, SOCK_STREAM, 0);
	if (listen_sd < 0) {
		std::cerr << "can't create listening socket" << std::endl;
		exit(1);
	}

	static const int on = 1;
	if (setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, (char *)&on,
		       sizeof(on)) < 0)
	{
		std::cerr << "can't set reuseaddr for listening socket"
			<< std::endl;
		exit(1);
	}

	struct sockaddr_in saddr = {};
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons(PORT);
	if (bind(listen_sd, (const sockaddr *)&saddr, sizeof(saddr))) {
		std::cerr << "can't bind listening socket " << std::endl;
		exit(1);
	}

	/*
	 * XXX set /proc/sys/net/core/somaxconn also to 1000.
	 * See listen(2).
	 */
	if (listen(listen_sd, 1000)) {
		std::cerr << "can't listen on socket" << std::endl;
		exit(1);
	}

	set_nonblock(listen_sd, "listen");

	int wd = epoll_create(1000);
	if (wd < 0) {
		std::cerr << "can't create epoll" << std::endl;
		exit(1);
	}

	if (sd_add_to_epoll(wd, listen_sd))
		exit(1);

	while (1)
		work_loop(listen_sd, wd);

	return 0;
}
