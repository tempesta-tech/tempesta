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

        $ SYNC_SOCKET=<path to sync_socket> TDB=./tempesta_db SCHED=<scheduler_name> ./tempesta.sh start
        $ ./tempesta.sh stop

### Configuration

Tempesta is configured via sysctl interface under `net.tempesta` directory.
Configuration variables are described below.

##### backend

Address and port of backend server, e.g. `172.16.0.4:8080`.

A space-separated list of back-end servers is supported. Both IPv4 and IPv6 addresses are allowed, e.g.:

      127.0.0.1:8080  127.0.0.1:8081  [::1]:8082  [::1]:8083


##### listen

Tempesta listening address, e.g. `0.0.0.0:80`.

##### cache

Boolean value to enable ("1") or disable ("0") Web content caching.
It can be useful to switch caching off to run Tempesta on the same host as
protected HTTP accelerator.

##### sched_http_rules

List of rules for the `http` scheduler (see below).
Example:

      # Send request to either :8081 or :8082 when URI is equal to /foo/bar.html
      uri = /foo/bar.html {
      	127.0.0.1:8080
      	127.0.0.1:8081
      }
      
      # Send to 127.0.0.3 if URI prefix is /foo
      uri ^ /foo {
      	127.0.0.3:8080
      }
      
      # Iterate over all raw (not parsed) headers and send the request to 127.0.0.4 if
      # any raw line in the headers section of the HTTP request starts with "X-Raw-Header: value"
      hdr_raw ^ "X-Raw-Header: value" {
      	127.0.0.4:8080
      }
      
      # Send the request to either 127.0.0.5 or 127.0.0.6 when "Connection" header value is "Keep-Alive"
      hdr_conn = Keep-Alive {
      	127.0.0.5:8080 127.0.0.6:8080
      }
      
      # If none of above matches, send the request to any of the servers listed below.
      uri ^ / {
      	127.0.0.1:8080
      	127.0.0.2:8080
      	127.0.0.3:8080
      }


In general, the rule format is: `REQUEST-FIELD  OPERATOR  VALUE  { SERVER+ }`.

The `REQUEST-FIELD` is one of:
* `uri` - relative URI of the HTTP request
* `host` - either host specified in URI or in `Host` header
* `hdr_conn` - `Connection` header value
* `hdr_host` - `Host` header value
* `hdr_raw` - any other header name + value (note: this is slow)

The `OPERATOR` is one of:
* `=` - equal
* `^` - prefix

The `VALUE` is a string optionally enclosed into quotes.

The rule format is a subject to change in the near future.

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

