![Tempesta FW](http://tempesta-tech.com/images/tempesta_technologies_logo_small.png)

# Tempesta FW


### What it is?

**Tempesta FW** is a hybrid solution that combines a reverse proxy and
a firewall at the same time. It accelerates Web applications and provides
high performance framework with access to all network layers for running
complex network traffic classification and blocking modules.

**Tempesta FW** is built into Linux TCP/IP stack for better and more stable
performance characteristics in comparison with TCP servers on top of common
Socket API or even kernel sockets.


### Prerequisites

#### Common

* **x86-64 Haswell** or later CPU. Tempesta FW requires **SSE 4.2**, **AVX2**
  and **2MB huge pages** enabled (check **sse4\_2**, **avx2** and **pse** flags
  in your /proc/cpuinfo);
* At least **2GB RAM**;
* **RSS** capable network adapter;
* Linux CentOS/RHEL 7 or Debian 8;
* Filesystem with `fallocate(2)` system call (e.g. **ext4**, **btrfs** or
  **xfs**);
* GNU Make 3.82 or higher;
* GCC and G++ compilers of versions 4.8 or higher;
* Boost library of version 1.53 or higher;


#### Kernel

Tempesta requires that the following Linux kernel configuration options are
switched on:

* CONFIG\_SECURITY
* CONFIG\_SECURITY\_NETWORK
* CONFIG\_SECURITY\_TEMPESTA
* CONFIG\_DEFAULT\_SECURITY\_TEMPESTA
* CONFIG\_DEFAULT\_SECURITY="tempesta"
* CONFIG\_NETLINK\_MMAP

We suggest that CONFIG\_PREEMPT\_NONE is used for better throughput. However,
please use CONFIG\_PREEMPT\_VOLUNTARY for debugging since this mode causes
additional stress to synchronization of several algorithms. Also note that
CONFIG\_PREEMPT is not supported at all.


### Build

To build the module you need to do the following steps:

* Download [the patched Linux kernel](https://github.com/tempesta-tech/linux-4.1.27-tfw)
* Build, install, and then boot the kernel. Classic build and install procedure
  is used. For that, go to the directory with the patched kernel sources, make
  sure you have a correct `.config` file, and then do the following (`<N>` is
  the number of CPU cores on the system):

        make -j<N>
        make -j<N> modules
        make -j<N> modules_install
        make install

* Optionally, add kernel parameter `tempesta_dbmem` to the kernel command line.
  The value is the order of 2MB memory blocks reserved on each NUMA node for
  Tempesta database. Huge pages are used if possible. The default value is 8
  which stands for 512Mb reserved on each NUMA node.

        tempesta_dbmem=1
  
* Run `make` to build Tempesta FW and Tempesta DB modules:

        $ cd tempesta && make


### Run & Stop

Use `tempesta.sh` script to run and stop Tempesta. The script provides help
information with `--help` switch. Usage example:

        $ ./scripts/tempesta.sh --start
        $ ./scripts/tempesta.sh --stop


### Configuration

Tempesta is configured via plain-text configuration file.

The file location is determined by the `TFW_CFG_PATH` environment variable:

        $ TFW_CFG_PATH="/opt/tempesta.conf" ./scripts/tempesta.sh --start

By default, the `tempesta_fw.conf` from this directory is used.

See `tempesta_fw.conf` for the list of available configuration directives,
options and their descriptions.


### Listening address

Tempesta listens to incoming connections on specified address and port.
The syntax is as follows:
```
listen <PORT> | <IPADDR>[:PORT] [proto=http|https];
```
`IPADDR` may be either IPv4 or IPv6 address. Host names are not allowed.
IPv6 address must be enclosed in square brackets (e.g. "[::0]" but not "::0").
If only `PORT` is specified, then address 0.0.0.0 (but not [::1]) is used.
If only `IPADDR` is specified, then default HTTP port 80 is used.

Tempesta opens one socket for each `listen` directive. Multiple `listen`
directives may be defined to listen on multiple addresses/ports.
If `listen` directive is not defined in the configuration file,
then by default Tempesta listens on IPv4 address 0.0.0.0 and port 80,
which is an equivalent to `listen 80` directive.

Below are examples of `listen` directive:
```
listen 80;
listen 443 proto=https;
listen [::0]:80;
listen 127.0.0.1:8001;
listen [::1]:8001;
```

It is allowed to specify the type of listening socket via the `proto`. At
the moment **HTTP** and **HTTPS** protos are supported. If no `proto`
option was given, then **HTTP** is supposed by the default.

### TLS/SSL support

Tempesta allows to use TLS-encrypted HTTP connections (HTTPS). It is
required that public certificate and private key have been configured as
follows:
```
ssl_certificate /path/to/tfw-root.crt;
ssl_certificate_key /path/to/tfw-root.key;
```

Also, `proto=https` option is needed for the `listen` directive.

#### Self-signed certificate genration

In case of using a self-signed certificate with Tempesta, it's
convenient to use OpenSSL to generate a key and a certificate. The
following shell command can be used:

~~~
openssl req -nodes -new -x509 -keyout tfw-root.key -out tfw-root.crt
~~~

You'll be prompted to fill out several X.509 certificate fields. The
values are the same for the subject and the issuer in a self-signed
certificate. Use any valid values as you like.

The file `tfw-root.key` contains the private key, and the file
`tfw-root.crt` contains the public X.509 certificate. Both are in PEM
format. These files are used in Tempesta configuration as follows:
```
ssl_certificate /path/to/tfw-root.crt;
ssl_certificate_key /path/to/tfw-root.key;
```

### Keep-alive timeout

Tempesta may use a single TCP connection to send and receive multiple HTTP
requests/responses. The syntax is as follows:
```
keepalive_timeout <TIMEOUT>;
```
`TIMEOUT` is a timeout in seconds during which a keep-alive client connection
will stay open in Tempesta. The zero value disables keep-alive client
connections. Default value is 75.

Below are examples of `keepalive_timeout` directive:
```
keepalive_timeout 75;
```

### Caching

Tempesta caches Web-content by default, i.e. works as reverse proxy.
Configuration directive `cache` manages the cache befavior:

* `0` - no caching at all, pure proxying mode;
* `1` - cache sharding when each NUMA node contains independent shard
	    of whole cache. This mode has the smallest memory requirements;
* `2` - (default) replicated mode when each NUMA node has whole replica
	    of the cache. It requires more RAM, but delivers the highest
	    performance.

`cache_db` specifies path to a cache database files.
The PATH must be absolute and the directory must exist. The database file
must end with `.tbd`. E.g. `cache_db /opt/tempesta/db/cache.tdb` is
the right Tmpesta DB path. However, this is the only path pattern rather than
real path. Tempesta creates per NUMA node database files, so if you have two
processor packages on modern hardware, then the following files will be
created (one for each processor package) for the example above:

        /opt/tempesta/db/cache0.tdb
        /opt/tempesta/db/cache1.tdb


`cache_size` defines size (in bytes, suffixes like 'MB' are not supported
yet) of each Tempesta DB file used as Web cache storage. The size must be
multiple of 2MB (Tempesta DB extent size). Default value is `268435456`
(256MB).

`cache_methods` specifies the list of cacheable request methods. Responses
to requests with these methods will be cached. If this directive is skipped,
then the default cacheable request method is `GET`. Note that not all of
HTTP request methods are cacheable by the HTTP standards. Besides, some
request methods may be cachable only when certain additional restrictions
are satisfied. Also, note that not all HTTP request methods may be supported
by Tempesta at this time. Below is an example of this directive:
```
cache_methods GET HEAD;
```

#### Caching Policy

Caching policy is controlled by rules that match the destination URL
agsinst the pattern specified in the rule and using the match operator
specified in the same rule. The full syntax is as follows:
```
<caching policy> <OP> <string> [<string>];
```

`<caching policy>` directive can be one of the following:
* **cache_fulfill** - Serve the request from cache. If the response is not
found in cache, then forward the request to a back end server, and store
the response in cache to serve future requests for the same resource. Update
the cached response when necessary.
* **cache_bypass** - Skip the cache. Simply forward the request to a server.
Do not store the response in cache.

`<string>` is the anticipated substring of URL. It is matched against
the URL in a request according to the match operator specified by `<OP>`.
Note that the string must be verbatim. Regular expressions are not
supported at this time.

The following `<OP>` keywords (match operators) are supported:
* **eq** - URL is fully equal to `<string>`.
* **prefix** - URL starts with `<string>`.
* **suffix** - URL ends with `<string>`.

Caching policy directives are processed strictly in the order they
are defined in the configuration file. Below are examples of caching
policy directives:
```
cache_fulfill suffix ".jpg" ".png";
cache_bypass suffix ".avi";
cache_bypass prefix "/static/dynamic_zone/";
cache_fulfill prefix "/static/";
```

Also, a special variant of wildcard matching is supported. It makes
all requests and responses either use or skip the cache. It should
be used with caution.
```
cache_fulfill * *;
cache_bypass * *;
```

#### Manual Cache Purging

Cached responses may be purged manually using the PURGE request method
and the URL of the cached response. A typical use case is that when some
content is changed on the upstream server, then a PURGE request followed
by a GET request will update an appropriate entry in the cache.

This functionality is controlled with the following directives:
* **cache_purge `[invalidate]`;** - Defines the purge mode
`invalidate` just makes the cache record invalid. The cached response may
still be returned to a client under certain conditions. This is the default
mode. Other modes will be added in future.
* **cache_purge_acl `<ip_address>`;** - Specifies the IP addresses of hosts
that are permitted to send PURGE requests. PURGE requests from all other
hosts will be denied. That makes this directive mandatory when `cache_purge`
directive is specified. Multilple addresses are separated with white spaces.

`<ip_address>` can be an IPv4 or IPv6 address. An IP address can be specified
in CIDR format where the address is followed by a slash character and the
prefix (or mask) with the number of significant bits in the addresss. Below
are examples of a valid IP address specification:
```
127.0.0.1
192.168.10.50/24
::ffff:c0a8:b0a
[::ffff:c0a8:a0a]
::ffff:c0a8:b0b/120
[::ffff:c0a8:b0b]/120
```

A PURGE request can be issued using any tool that is convenient. Below is
just one example:
```
curl -X PURGE http://192.168.10.10/
```

### Locations

Location is a way of grouping certain directives that are applied only
to that specific location. Location is defined by a string and a match
operator that are used to match the string against URL in requests.
The syntax is as follows:
```
location <OP> "<string>" {
	<directive>;
	...
	<directive>;
}
```

`<OP>` and `<string>` are specified the same way as defined in the
[Caching Policy](#Caching Policy) section.

Multiple locations may be defined. Location directives are processed
strictly in the order they are defined in the configuration file.

Only caching policy directives may currently be grouped by the location
directive. Caching policy directives defined outside of any specific
location are considered the default policy for all locations.

When locations are defined in the configuration, the URL of each request
is matched against strings specified in the location directives and using
the corresponding match operator. If a matching location is found, then
caching policy directives for that location are matched against the URL.

In case there's no matching location, or there's no matching caching
directive in the location, the default caching policy directives are
matched against the URL.

If a matching caching policy directive is not found, then the default
action is to skip the cache - do not serve requests from cache, and
do not store responses in cache.

Below is an example of location directive definition:
```
cache_bypass suffix ".php";
cache_fulfill suffix ".mp4";

location prefix "/static/" {
	cache_bypass prefix "/static/dynamic_zone/";
	cache_fulfill * *;
}
location prefix "/society/" {
	cache_bypass prefix "/society/breaking_news/";
	cache_fulfill suffix ".jpg" ".png";
	cache_fulfill suffix ".css";
}
```

### Server Load Balancing

#### Servers

A back end HTTP server is defined with `server` directive. The full syntax is
as follows:
```
server <IPADDR>[:<PORT>] [conns_n=<N>];
```
`IPADDR` can be either IPv4 or IPv6 address. Hostnames are not allowed.
IPv6 address must be enclosed in square brackets (e.g. "[::0]" but not "::0").
`PORT` defaults to 80 if not specified.
`conns_n=<N>` is the number of parallel connections to the server.
`N` defaults to 4 if not specified.

Multiple back end servers may be defined. For example:
```
server 10.1.0.1;
server [fc00::1]:80;
```

#### Server Groups

Back end servers can be grouped together into a single unit for the purpose of
load balancing. Servers within a group are considered interchangeable.
The load is distributed evenly among servers within a group.
If a server goes offline, other servers in a group take the load.
The full syntax is as follows:
```
srv_group <NAME> [sched=<SCHED_NAME>] {
	server <IPADDR>[:<PORT>] [conns_n=<N>];
	...
}
```
`NAME` is a unique identifier of the group that may be used to refer to it
later.
`SCHED_NAME` is the name of scheduler module that distributes load among
servers within the group. Default scheduler is used if `sched` parameter is
not specified.

Servers that are defined outside of any group implicitly form a special group
called `default`.

Below is an example of server group definition:
```
srv_group static_storage sched=hash {
	server 10.10.0.1:8080;
	server 10.10.0.2:8080;
	server [fc00::3]:8081 conns_n=1;
}
```

#### Schedulers

Scheduler is used to distribute load among known servers. The syntax is as
follows:
```
sched <SCHED_NAME>;
```
`SCHED_NAME` is the name of a scheduler available in Tempesta.

Currently there are two schedulers available:
* **round-robin** - Rotates all servers in a group in round-robin manner so
that requests are distributed uniformly across servers. This is the default
scheduler.
* **hash** - Chooses a server based on a URI/Host hash of a request.
Requests are distributed uniformly, and requests with the same URI/Host are
always sent to the same server.

If no scheduler is defined, then scheduler defaults to `round-robin`.

The defined scheduler affects all server definitions that are missing a
scheduler definition. If `srv_group` is missing a scheduler definition,
and there is a scheduler defined, then that scheduler is set for the group.

Multiple `sched` directives may be defined in the configuration file.
Each directive affects server groups that follow it.

#### HTTP Scheduler

HTTP scheduler plays a special role as it distributes HTTP requests among
groups of back end servers. Then requests are futher distributed among
individual back end servers within a chosen group.

HTTP scheduler is able to look inside of an HTTP request and examine its
contents such as URI and headers. The scheduler distributes HTTP requests
depending on values of those fields. The work of HTTP scheduler is controlled
by pattern-matching rules that map certain header field values to server
groups. The full syntax is as follows:
```
sched_http_rules {
	match <SRV_GROUP> <FIELD> <OP> <ARG>;
	...
}
```
`SRV_GROUP` is the reference to a previously defined server group.
`FIELD` is an HTTP request field, such as `uri`, `host`, etc.
`OP` is a string comparison operator, such as `eq`, `prefix`, etc.
`ARG` is an argument for the operator, such as `/foo/bar.html`, `example.com`,
etc.

A `match` entry is a single instruction for the load balancer that says:
take `FIELD` of an HTTP request, compare it with `ARG` using `OP`.
If they match, then send the request to the specified `SRV_GROUP`.
For every HTTP request, the load balancer executes all `match` instructions
sequentially until it finds a match. If no match is found, then the request
is dropped.

The following `FIELD` keywords are supported:
* **uri** Only a part of URI is looked at that contains the path and the query
string if any. (e.g. `/abs/path.html?query&key=val#fragment`).
* **host** The host part from URI in HTTP request line, or the value of `Host`
header. Host part in URI takes priority over the `Host` header value.
* **hdr_host** The value of `Host` header.
* **hdr_conn**  The value of `Connection` header.
* **hdr_raw** The contents of any other HTTP header field as specified by
`ARG`. `ARG` must include contents of an HTTP header starting with the header
field name. The `suffix` `OP` is not supported for this `FIELD`. Processing
of `hdr_raw` may be slow because it requires walking over all headers of an
HTTP request.

The following `OP` keywords are supported:
* **eq** `FIELD` is fully equal to the string specified in `ARG`.
* **prefix** `FIELD` starts with the string specified in `ARG`.
* **suffix** `FIELD` ends with the string specified in `ARG`.

Below are examples of pattern-matching rules that define the HTTP scheduler:
```
srv_group static { ... }
srv_group foo_app { ... }
srv_group bar_app { ... }

sched_http_rules {
	match static   uri       prefix  "/static";
	match static   uri       suffix  ".php";
	match static   host      prefix  "static.";
	match static   host      suffix  "tempesta-tech.com";
	match foo_app  host      eq      "foo.example.com";
	match bar_app  hdr_conn  eq      "keep-alive";
	match bar_app  hdr_host  prefix  "bar.";
	match bar_app  hdr_host  suffix  "natsys-lab.com";
	match bar_app  hdr_host  eq      "bar.natsys-lab.com";
	match bar_app  hdr_raw   prefix  "X-Custom-Bar-Hdr: ";
}
```
There's a special default match rule that matches any request. If defined,
the default rule must come last in the list of rules. All requests that didn't
match any rule are routed to the server group specified in the default rule.
If a default match rule is not defined, and there's the group `default` with
servers defined outside of any group, then the default rule is added
implicitly to route requests to the group `default`. The syntax is as follows:
```
match <SRV_GROUP> * * * ;
```

By default no rules are defined. If there's the group `default`,
then the default match rule is added to route HTTP requests to the group
`default`. Otherwise, requests don't match any rule, and therefore they're
dropped.


### Sticky Cookie

**Sticky cookie** is a special HTTP cookie that is generated by Tempesta.
It allows for unique identification of each client or can be used as challenge
cookie for simple L7 DDoS mitigation when bots are unable to process cookies.

When used, Tempesta sticky cookie is expected in HTTP requests.
Otherwise, Tempesta asks in an HTTP response that sticky cookie is present in
HTTP requests from a client. Default behaviour is that Tempesta sticky cookies
are not used.

The use and behaviour of Tempesta sticky cookies is controlled by a single
configuration directive that can have several parameters. The full form of
the directive and parameters is as follows:
```
sticky [name=<COOKIE_NAME>] [enforce];
```

`name` parameter specifies a custom Tempesta sticky cookie name `COOKIE_NAME`
for use in HTTP requests. It is expected that it is a single word without
whitespaces. When not specified explicitly, a default name is used.

`enforce` parameter demands that Tempesta sticky cookie is present in each
HTTP request. If it is not present in a request, a client receives HTTP 302
response from Tempesta that redirects the client to the same URI, and prompts
that Tempesta sticky cookie is set in requests from the client.


Below are examples of Tempesta sticky cookie directive.

* **sticky;**
Enable Tempesta sticky cookie. Default cookie name is used. Tempesta expects
that Tempesta sticky cookie is present in each HTTP request. If it is not
present, then Tempesta includes `Set-Cookie` header field in an HTTP response,
which prompts that Tempesta sticky cookie with default name is set in requests
from the client.

* **sticky enforce;**
Enable Tempesta sticky cookie. Default cookie name is used. Tempesta expects
that Tempesta sticky cookie is present in each HTTP request. If it is not
present, Tempesta sends HTTP 302 response that redirects the client to
the same URI and includes `Set-Cookie` header field, which prompts that
Tempesta sticky cookie with default name is set in requests from the client.

* **sticky name=`__cookie__`;**
Enable Tempesta sticky cookie. The name of the cookie is `__cookie__`.
Tempesta expects that Tempesta sticky cookie is present in each HTTP request.
If it is not present, then Tempesta includes `Set-Cookie` header field in
an HTTP response, which prompts that Tempesta sticky cookie with the name
`__cookie__` is set in requests from the client.

* **sticky name=`__cookie__` enforce;**
Enable Tempesta sticky cookie. The name of the cookie is `__cookie__`.
Tempesta expects that Tempesta sticky cookie is present in each HTTP request.
If it is not present, Tempesta sends HTTP 302 response that redirects
the client to the same URI and includes `Set-Cookie` header field,
which prompts that Tempesta sticky cookie with the name `__cookie__` is set
in requests from the client.

Sticky cookie value is calculated on top of client IP, User-Agent, session
timestamp and the **secret** used as a key for HMAC. `sticky_secret` config
option sets the secret string used for HMAC calculation. It's desirable to
keep this value in secret to prevent automatic cookies generation on attacker
side. By default Tempesta generates a new random value for the secret on start.
This means that all user HTTP sessions are invalidated on Tempesta restart.
Maximum length of the key is 20 bytes.

`sess_lifetime` config option defines HTTP session lifetime in seconds. Default
value is `0`, i.e. unlimited life time. When HTTP session expires the client
receives 302 redirect with new cookie value if enforced sticky cookie is used.
This option doesn't affect sticky cookie expire time - it's a session, temporal,
cookie.


### Frang

**Frang** is a separate Tempesta module for HTTP DoS and DDoS attacks
prevention. It uses static limiting and checking of ingress HTTP requests.
The main portion of it's logic is at HTTP layer, so it's recommended that
*ip_block* option (enabled by default) is used to block malicious users
at IP layer.

Use `-f` command key to start Tempesta with Frang:
```
$ ./scripts/tempesta.sh -f --start
```
Frang has a separate section in the configuration file, *"frang_limits"*.
The list of available options:

* **ip_block** - if the option is switched on, then Frang will add IP
addresses of clients who reaches the limits to ```filter_db``` table,
so that the clients traffic will be dropped much earlier.
See also [Filter](#Filter) section.

* **request_rate** - maximum number of requests per second from a client;

* **request_burst** - maximum number of requests per fraction of a second;

* **connection_rate** - maximum number of connections per client;

* **connection_burst** - maximum number of connections per fraction of a second;

* **concurrent_connections** - maximum number of concurrent connections per
client;

* **client_header_timeout** - maximum time for receiving the whole HTTP
message header of incoming request;

* **client_body_timeout** - maximum time between receiving parts of HTTP
message body of incoming request;

* **http_uri_len** - maximum length of URI part in a request;

* **http_field_len** - maximum length of a single HTTP header field of
incoming request. This limit is helpful to prevent
[HTTP Response Splitting](http://projects.webappsec.org/w/page/13246931/HTTP-Response-Splitting)
and other attacks using arbitrary injections in HTTP headers;

* **http_body_len** - maximum length of HTTP message body of incoming request;

* **http_header_cnt** - maximum number of HTTP header in a HTTP message;

* **http_header_chunk_cnt** - limit number of chunks in all headers for HTTP
request;

* **http_body_chunk_cnt** - limit number of chunks for HTTP request body;

* **http_host_required** - require presence of `Host` header in a request;

* **http_ct_required** - require presence of `Content-Type` header in a request;

* **http_ct_vals** - the list of accepted values for `Content-Type` header;

* **http_methods** - the list of accepted HTTP methods;

Various back end servers may differ in interpretation of certain aspects of
the standards. Some may follow strict standards, whereas others may allow a
more relaxed interpretation. An example of this is the `Host:` header field.
It must be present in all HTTP/1.1 requests. However, the `Host:` field value
may be empty in certain cases. Nginx is strict about that, while Apache allows
an empty `Host:` field value in more cases. This can present an opportunity
for a DoS attack. Frang's **http_host_required** option should be used in this
case. That would leave handling of the `Host:` header field to Tempesta.
Invalid requests would be denied before they reach a back end server.


### Filter

Let's see a simple example to understand Tempesta filtering.

Run Tempesta with [Frang](#Frang) enabled and put some load onto the system
to make Frang generate a blocking rule:
```
$ dmesg | grep frang
[tempesta] Warning: frang: connections max num. exceeded for ::ffff:7f00:1: 9 (lim=8)
```
`::ffff:7f00:1` is IPv4 mapped loopback address 127.0.0.1. Frang's rate limiting
calls the filter module that stores the blocked IPs in Tempesta DB, so now we
can run some queries on the database (you can read more about
[tdbq](https://github.com/tempesta-tech/tempesta/tree/master/tempesta_db#tempesta-db-query-tool)):
```
# ./tdbq -a info

Tempesta DB version: 0.1.14
Open tables: filter

INFO: records=1 status=OK zero-copy
```
The table `filter` contains all blocked IP addresses.


### Additional Directives

Tempesta has a number of additional directives that control varios aspects
of a running system. Possible directives are listed below.

* **hdr_via [string];** - As an intermediary between a client and a back end
server, Tempesta adds HTTP Via: header field to each message. This directive
sets the value of the header field, not includng the mandatory HTTP protocol
version number. Note that the value should be a single token. Multiple tokens
can be specified in apostrophes, however everything after the first token and
a white space will be considered a Via: header field comment. If no value is
specified in the directive, the default value is used.


### Performance Statistics

Tempesta has a set of performance statistics counters that show various
aspects of Tempesta operation. The counters and their values are
self-explanatory. Performance statistics can be shown when Tempesta is loaded
and running. Below is an example of the command to show the statistics,
and the output:
```
$ cat /proc/tempesta/perfstat
Client messages received                : 450
Client messages forwarded               : 450
Client messages parsing errors          : 0
Client messages filtered out            : 0
Client messages other errors            : 0
Client connections total                : 30
Client connections active               : 0
Client RX bytes                         : 47700
Server messages received                : 447
Server messages forwarded               : 447
Server messages parsing errors          : 0
Server messages filtered out            : 0
Server messages other errors            : 0
Server connections total                : 2220
Server connections active               : 4
Server RX bytes                         : 153145
```

Also, there's Application Performance Monitoring statistics. These stats show
the time it takes to receive a complete HTTP response to a complete HTTP request.
It's measured from the time Tempesta forwards an HTTP request to a back end server,
and until the time it receives an HTTP response to the request (the turnaround
time). The times are taken per each back end server. Minimum, maximim, median,
and average times are measured, as well as 50th, 75th, 90th, 95th, and 99th
percentiles. A file per each back end server/port is created in
`/proc/tempesta/servers/` directory. The APM stats can be seen as follows:
```
# cat /proc/tempesta/servers/192.168.10.230\:8080 
Minimal response time           : 0ms
Average response time           : 4ms
Median  response time           : 3ms
Maximum response time           : 66ms
Percentiles
50%:    3ms
75%:    7ms
90%:    11ms
95%:    15ms
99%:    29ms
```


### Build Status

[![Coverity](https://scan.coverity.com/projects/8336/badge.svg)](https://scan.coverity.com/projects/tempesta-tech-tempesta)
