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

Tempesta requires following Linux kernel configuration options to be switched on:

* CONFIG\_SECURITY
* CONFIG\_SECURITY\_NETWORK


### Build

To build the module you need to do following steps:

1. Patch Linux kernel 3.10.10 with linux-3.10.10.patch
2. Build and load the kernel
3. Just run make to build Synchronous Sockets, Tempesta DB and Tempesta FW
   modules

Add NORMALIZATION=1 as an argument to make to build Tempesta with HTTP
normalization logic.


### Run & Stop

        $ SYNC_SOCKET=<path to sync_socket> TDB=./tempesta_db ./tempesta.sh start
        $ ./tempesta.sh stop


### Configuration

Tempesta is configured via sysctl interface under `net.tempesta` directory.
Configuration variables are described below.

#### backend

Address and port of backend server, e.g. `172.16.0.4:8080`.

#### listen

Tempesta listening address, e.g. `0.0.0.0:80`.

#### cache

Boolean value to enable ("1") or disable ("0") Web content caching.
It can be useful to switch caching off to run Tempesta on the same host as
protected HTTP accelerator.
