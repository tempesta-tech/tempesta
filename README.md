## Tempesta FW (FrameWork and/or FireWall)


### What it is?

**Tempesta FW** is a hybrid solution that combines reverse proxy and firewall
at the same time. It accelerates Web applications and provide high performance
framework with access to all network layers for running complex network traffic
classification and blocking modules.

**Tempesta FW** is built into Linux TCP/IP stack for better and more stable
performance characteristics in comparison with TCP servers on top of common
Socket API or even kernel sockets.


### Prerequisites

Tempesta requires that the following Linux kernel configuration options are
switched on:

* CONFIG\_SECURITY
* CONFIG\_SECURITY\_NETWORK
* CONFIG\_NETLINK\_MMAP

Tempesta DB user-space library requires netlink mmap defined in standard
headers, so preferably Linux distribution should have native 3.10 kernel.
Currently CentOS 7 is shipped with an appropriate kernel.

Please, also read [Tempesta DB README](tempesta_db/README.md) for its
prerequisites.


### Build

To build the module you need to do the following steps:

1. Patch Linux kernel 3.10.10 with linux-3.10.10.patch or just download
   [an already patched kernel](https://github.com/krizhanovsky/linux-3.10.10-sync_sockets)
2. Build and load the kernel
3. Run make to build Tempesta FW and Tempesta DB modules:

        $ cd tempesta && make

Add NORMALIZATION=1 as an argument to make to build Tempesta with HTTP
normalization logic.


### Run & Stop

Use `tempesta.sh` script to run and stop Tempesta. The script provides help
information with `--help` switch. Usage example:

        $ ./tempesta.sh --start
        $ ./tempesta.sh --stop


### Configuration

Tempesta is configured via plain-text configuration file.

The file location is determined by the `TFW_CFG_PATH` environment variable:

        $ TFW_CFG_PATH="/opt/tempesta.conf" ./tempesta.sh --start

By default, the `tempesta_fw.conf` from this directory is used.

See `tempesta_fw.conf` for the list of available options and their descriptions.

#### Frang

**Frang** is a separate Tempesta module for HTTP DoS and DDoS attacks prevention.
Use `-f` command key to start Tempesta with Frang:

        $ ./tempesta.sh -f --start

Frang has a separate section in the configuration file, *"frang_limits"*.
The list of available options:

* **request_rate** - maximum number of requests per second from a client;

* **request_burst** - maximum number of requests per fraction of a second;

* **connection_rate** - maximum number of connections per client;

* **connection_burst** - maximum number of connections per fraction of a second;

* **concurrent_connections** - maximum number of concurrent connections per client;

* **client_header_timeout** - maximum time for receiving the whole HTTP message header of incoming request;

* **client_body_timeout** - maximum time between receiving parts of HTTP message body of incoming request;

* **http_uri_len** - maximum length of URI part in a request;

* **http_field_len** - maximum length of a single HTTP header field of incoming request;

* **http_body_len** - maximum length of HTTP message body of incoming request;

* **http_header_chunk_cnt** - limit number of chunks in all header for HTTP request;

* **http_body_chunk_cnt** - limit number of chunks for HTTP request body;

* **http_host_required** - require presence of `Host` header in a request;

* **http_ct_required** - require presence of `Content-Type` header in a request;

* **http_ct_vals** - the list of accepted values for `Content-Type` header;

* **http_methods** - the list of accepted HTTP methods;


