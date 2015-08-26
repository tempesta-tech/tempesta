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

Tempesta DB user-space library requires netlink mmap defined in standard
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

Use ```tempesta.sh``` script to run and stop Tempesta. The script provides help
info by ```--help``` switch. Usage example:

        $ ./tempesta.sh --start
        $ ./tempesta.sh --stop


### Configuration

Tempesta is configured via plain-text configuration file.

The file location is determined by the `TFW\_CFG\_PATH` environment variable:

        $ TFW_CFG_PATH="/opt/tempesta.conf" ./tempesta.sh start

By default, the `tempesta\_fw.conf` from this directory is used.

See ```tempesta\_fw.conf` for the list of available options and their descriptions.

#### Frang

**Frang** is a separate Tempesta module for HTTP DoS and DDoS attaks prevention.
Use ```-f``` command key to start Tempesta with Frang:

        $ ./tempesta.sh -f --start

Frang has secific section in configuration file, *"frang_limits"*.
The list of available options:

* **request_rate** - requests per second rate through a connection;

* **request_burst** - temporal burst of requests within 1 second;

* **connection_rate** - new connections rate for each client;

* **connection_burst** - temporal burst of new connections within 1 second;

* **concurrent_connections** - maximum number of concurrent connection for
			       each peer;

* **client_header_timeout** - timeout between HTTP headers of incomming request;

* **client_body_timeout** - timeout between chunks of HTTP request body;

* **http_uri_len** - maximum length of URI part in a request;

* **http_field_len** - maximum length of fields (headers) in a request;

* **http_body_len** - maximum length of a request body;

* **http_host_required** - require presense of ```Host``` header in a request;

* **http_ct_required** - require ```Content-Type``` header in a request;

* **http_methods** - sets the list of pemitted HTTP methods;

* **http_ct_vals** - allowed values for ```Content-Type``` header;

