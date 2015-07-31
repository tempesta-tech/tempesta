## Tempesta FW (FrameWork and/or FireWall)


### What it is?

**Tempesta FW** is a hybrid solution which combines reverse proxy and firewall
at the same time. It accelerates Web applications and provide high performance
framework with access to all network layers for running complex network traffic
classification and blocking modules.

**Tempesta FW** is built into Linux TCP/IP stack for better and more stable
performance characteristics in comparison with TCP servers on top of common
Socket API and even kernel sockets.


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

1. Patch Linux kernel 3.10.10 with linux-3.10.10.patch or just download
   [already patched kernel](https://github.com/krizhanovsky/linux-3.10.10-sync_sockets)
2. Build and load the kernel
3. Just run make to build Tempesta FW and Tempesta DB modules:

        $ cd tempesta && make

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
