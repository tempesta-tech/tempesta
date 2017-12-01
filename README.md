![Tempesta FW](https://raw.githubusercontent.com/wiki/tempesta-tech/tempesta/tempesta_technologies_logo_small.png)

# Tempesta FW


### What it is?

**Tempesta FW** is a hybrid solution that combines a reverse proxy and
a firewall at the same time. It accelerates Web applications and protects
them against DDoS attacks and several Web application attacks.

**Tempesta FW** is built into Linux TCP/IP stack for better and more stable
performance characteristics in comparison with TCP servers on top of common
Socket API or even kernel sockets.

We do our best to keep the kernel modifications as small as possible. Current
[patch](https://github.com/tempesta-tech/tempesta/blob/master/linux-4.9.35.patch)
is just about 2,000 lines.


### Prerequisites & Installation

Please see our [Wiki](https://github.com/tempesta-tech/tempesta/wiki) for system
requirements and installation procedures.


### Build

To build the module you need to do the following steps:

* Download [the patched Linux kernel](https://github.com/tempesta-tech/linux-4.9.35-tfw)
  or patch vanilla kernel on your own using
  [linux-4.9.35.patch](https://github.com/tempesta-tech/tempesta/blob/master/linux-4.9.35.patch).
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

Guide on starting and stopping TempestaFW can be found on the following
Wiki page:
[Run & Stop](https://github.com/tempesta-tech/tempesta/wiki/Run-&-Stop)


### Handling clients

Guide on configuring of various client-side handling settings (listening address, keep-alive timeout etc)
can be found on the following Wiki page:
* [Handling clients](https://github.com/tempesta-tech/tempesta/wiki/Handling-clients).


### TLS/SSL support

Tempesta allows the use of TLS-encrypted HTTP connections (HTTPS).
HTTPS traffic is terminated by Tempesta. Backend servers always receive
unecrypted traffic.

It is required that public certificate and private key are configured as
follows:
```
ssl_certificate /path/to/tfw-root.crt;
ssl_certificate_key /path/to/tfw-root.key;
```

Also, `proto=https` option is needed for the `listen` directive.

#### Self-signed certificate generation

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

Guide on response caching can be found on the following
Wiki page:
[Caching Responses](https://github.com/tempesta-tech/tempesta/wiki/Caching-Responses)

### Non-Idempotent Requests

The consideration of whether a request is considered non-idempotent may
depend on specific application, server, and/or service. A special directive
allows the definition of a request that will be considered non-idempotent:
```
nonidempotent <METHOD> <OP> <ARG>;
```
`METHOD` is one of supported HTTP methods, such as GET, HEAD, POST, etc.
`OP` is a string matching operator, such as `eq`, `prefix`, etc.
`ARG` is an argument for `OP`, such as `/foo/bar.html`, `example.com`, etc.

One or more of this directive may be specified. The directives apply to one
or more locations as defined below in the [Locations](#locations) section.

If this directive is not specified, then a non-idempotent request in defined
as a request that has an unsafe method.

Below are examples of this directive:
```
nonidempotent GET prefix "/users/";
nonidempotent POST prefix "/users/";
nonidempotent GET suffix "/data";
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

Only caching policy directives and the `nonidempotent` directive may
currently be grouped by the location directive. The directives defined
outside of any specific location are considered the default policy for
all locations.

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
	nonidempotent GET prefix "/society/users/";
}
```

### Server Load Balancing

Guide on configuring servers and load balancers can be found on the following
Wiki pages:
* [Servers: Tempesta's side](https://github.com/tempesta-tech/tempesta/wiki/Servers:-Tempesta's-side),
* [Servers: backend side](https://github.com/tempesta-tech/tempesta/wiki/Servers:-backend-side),
* [Load Balancing](https://github.com/tempesta-tech/tempesta/wiki/Scheduling-and-Load-Balancing).

### Sticky Cookie

**Sticky cookie** is a special HTTP cookie that is generated by Tempesta.
It allows for unique identification of each client or can be used as challenge
cookie for simple L7 DDoS mitigation when bots are unable to process cookies.
It is also used for a [load balancing](sticky-sessions).

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
See also [Filter](#filter) section.

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

* **http_resp_code_block** - the list of HTTP response codes followed by the limit
 of such responses in a time frame in seconds as the last parameter;

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

Run Tempesta with [Frang](#frang) enabled and put some load onto the system
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

Tempesta has a number of additional directives that control various aspects
of a running system. Possible directives are listed below.

* **hdr_via [string];** - As an intermediary between a client and a back end
server, Tempesta adds HTTP Via: header field to each message. This directive
sets the value of the header field, not including the mandatory HTTP protocol
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
SS pfl hits                             : 5836412
SS pfl misses                           : 5836412
Cache hits                              : 0
Cache misses                            : 0
Client messages received                : 2918206
Client messages forwarded               : 2918206
Client messages served from cache       : 0
Client messages parsing errors          : 0
Client messages filtered out            : 0
Client messages other errors            : 0
Clients online                          : 0
Client connection attempts              : 2048
Client established connections          : 2048
Client connections active               : 0
Client RX bytes                         : 309329836
Server messages received                : 2918206
Server messages forwarded               : 2918206
Server messages parsing errors          : 0
Server messages filtered out            : 0
Server messages other errors            : 0
Server connection attempts              : 8896
Server established connections          : 8896
Server connections active               : 32
Server connections schedulable          : 32
Server RX bytes                         : 11494813434
```

Also, there's Application Performance Monitoring statistics. These stats show
the time it takes to receive a complete HTTP response to a complete HTTP request.
It's measured from the time Tempesta forwards an HTTP request to a back end server,
and until the time it receives an HTTP response to the request (the turnaround
time). The times are taken per each back end server. Minimum, maximum, median,
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
