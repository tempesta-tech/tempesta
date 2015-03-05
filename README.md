## Tempesta FW (FrameWork and/or FireWall)


### What it is?

**Tempesta FW** is a hybrid solution which combines reverse proxy and firewall
at the same time. It accelerates Web applications and provide high performance
framework with access to all network layers for running complex network traffic
classification and blocking modules.

**Tempesta FW** is built on top of **Synchronous Sockets**,
a library for Linux kernel which provides better and more stable performance
characteristics in comparison with common Socket API and even kernel sockets.


### Prerequisites

Tempesta requires following Linux kernel configuration options to be switched
on:

* CONFIG\_SECURITY
* CONFIG\_SECURITY\_NETWORK
* CONFIG\_NETLINK\_MMAP

Tempesta DB user-space libarary requires netlink mmap defined in standard
headers, so preferably Linux distribution should have native 3.10 kernel.
Currently CentOS 7 is shipped with appropriate kernel.


### Build

To build the module you need to do following steps:

1. Patch Linux kernel 3.10.10 with linux-3.10.10.patch
2. Build and load the kernel
3. Just run make to build Synchronous Sockets, Tempesta DB and Tempesta FW
   modules

Add NORMALIZATION=1 as an argument to make to build Tempesta with HTTP
normalization logic.


### Run & Stop

        $ ./tempesta.sh start
        $ ./tempesta.sh stop

### Configuration

Tempesta is configured via plain-text configuration file.

The file location is determined by the `TFW_CFG_PATH` environment variable:

        $ TFW_CFG_PATH="/opt/tempesta.conf" ./tempesta.sh start

By default, the `tempesta_fw.conf` from this directory is used.

See `tempesta_fw.conf` for the list of available options and their descriptions.


### Schedulers

Scheduler is a module that decides how to distribute incoming HTTP requests over back-end servers.
Currently there are three modules implemented:

1. `rr` - the round-robin scheduler that distributes all requests equally across all servers
2. `hash` - for each request it calculates a hash value of Host and URI of the request and picks a server corresponding to the hash value. Therefore, all requests with the same URI and Host go to the same back-end server.
3. `http` - matches each HTTP request against a set of rules defined in the configuration. Allows to route requests to particular back-end servers according to the request's URI or Host or any other header value.

Schedulers are implemented as separate kernel modules. Such module is loaded by the `tmpesta.sh` startup script and cannot be switched after that. A module is selected by passing the `SCHED` environment variable to the `tempesta.sh` script, e.g.:

      $ SCHED=rr ./tempesta.sh 
      $ SCHED=hash ./tempesta.sh
      $ SCHED=http ./tempesta.sh

When none of the three is selected, the script loads a default scheduler called `dummy` that supports only one back-end server and sends all incoming requests to the server.

