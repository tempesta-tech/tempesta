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

        $ ./tempesta.sh start
        $ ./tempesta.sh stop

### Configuration

Tempesta is configured via plain-text configuration file.

The file location is determined by the `TFW_CFG_PATH` environment variable:

        $ TFW_CFG_PATH="/opt/tempesta.conf" ./tempesta.sh start

By default, the `tempesta_fw.conf` from this directory is used.

See `tempesta_fw.conf` for the list of available options and their descriptions.

####Frang
A part of the Tempesta which prevents some HTTP DoS and DDoS attaks is designed as s eparate module. 
It called "Frang". After a procedure of registration in the Tempesta as a kind of a "Classifier", the Tempestra starts to checks new connections and messages through the Frang. You can use -f key when starting the Tempesta to turn on Frang module.

The Frang has his section of options in configuration("frang_limits"). This options are:
* "request_rate" - rate of requests through a connection;

* "request_burst" - maximum rate of requests per fixed period of time(fraction of sec)"connection_rate" -number of new connection per second;

* "connection_burst" -number of new connection per fixed period of time (fraction of second);

* "concurrent_connections" - number of concurrent connection;
"client_header_timeout" timeout of incomming header of request;
* "client_body_timeout" timeout of incomming parts of a message;

* "http_uri_len" - max length of uri part in a request;

* "http_field_len" max length of fields in a request;

* "http_body_len" - max length of a request body;

* "http_host_required" - the field "Host" is not optional;

* "http_ct_required"- Content-Type is not optional;

* "http_methods" - a list of pemitted requests methods;

* "http_ct_vals" - the enabled values of Content-Type of a request;

