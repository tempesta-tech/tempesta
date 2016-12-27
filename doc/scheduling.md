# Scheduling in TempestaFW

TempestaFW uses various schedulers to distribute load among known servers.
Every [Server Group]() uses independent scheduling policy.


## User Guide

TempestaFW implements two types of schedulers: **group** and **server** schedulers.
**Group schedulers** are used to classify request and distribute it to corresponding
server group. **Server schedulers** are used to distribute request to specific
server in chosen [Server Group]().


### Scheduling Requests among Server Groups


#### HTTP Scheduler

**HTTP Scheduler** inspects headers of an HTTP request and chooses target [Server Group]()
according to scheduling rules. Scheduling rules are defined by user in TempestaFW
configuration and map headers patterns to server groups. By default no rules 
are defined. Syntax is:
```
sched_http_rules {
	match <SRV_GROUP> <FIELD> <OP> <ARG> [backup=<BACKUP_SRV_GROUP>];
	...
}
```
`SRV_GROUP` and `BACKUP_SRV_GROUP` -- the reference to a previously defined 
server groups. `BACKUP_SRV_GROUP` is optional parameter and can be skipped, while
main `SRV_GROUP` option is mandatory. 

If whole `SRV_GROUP` group is offline, request
will be scheduled to `BACKUP_SRV_GROUP`. Backup server groups are very handy for 
[A/B testing](https://en.wikipedia.org/wiki/A/B_testing) purposes: in that case
`SRV_GROUP` can represent unstable/test service, and `BACKUP_SRV_GROUP` -- stable
production service; if test service is under the maintenance users will be
forwarded to stable service.

`FIELD` -- an HTTP request field, following are supported:
* **uri** Only a part of URI is looked at that contains the path and the query
string if any. (e.g. `/abs/path.html?query&key=val#fragment`);
* **host** The host part from URI in HTTP request line, or the value of `Host`
header. Host part in URI takes priority over the `Host` header value;
* **hdr_host** The value of `Host` header;
* **hdr_conn**  The value of `Connection` header;
* **hdr_raw** The contents of any other HTTP header field as specified by
`ARG`. `ARG` must include contents of an HTTP header starting with the header
field name. The `suffix` `OP` is not supported for this `FIELD`. Processing
of `hdr_raw` may be slow because it requires walking over all headers of an
HTTP request.

`OP` -- a string comparison operator:
* **eq** `FIELD` is fully equal to the string specified in `ARG`;
* **prefix** `FIELD` starts with the string specified in `ARG`;
* **suffix** `FIELD` ends with the string specified in `ARG`;

`ARG` -- an argument for the operator `OP`.

Example configuration:
```
srv_group static { ... }
srv_group foo_app { ... }
srv_group foo_beta { ... }
srv_group bar_app { ... }

sched_http_rules {
	match static   uri       prefix  "/static" ;
	match static   uri       suffix  ".php";
	match static   host      prefix  "static.";
	match static   host      suffix  "tempesta-tech.com";
	match foo_beta host      eq      "beta-foo.example.com" backup=foo_app;
	match foo_app  host      eq      "foo.example.com";
	match bar_app  hdr_conn  eq      "keep-alive";
	match bar_app  hdr_host  prefix  "bar.";
	match bar_app  hdr_host  suffix  "natsys-lab.com";
	match bar_app  hdr_host  eq      "bar.natsys-lab.com";
	match bar_app  hdr_raw   prefix  "X-Custom-Bar-Hdr: ";
}
```

**HTTP Scheduler** matches request to rules in _top-down order_. If requests
fits some rule, rule is applied and further matching is skipped. User can provide
default match rule that matches any request. If no default rule provided and
[default server group]() is defined, default match rule to group `default` will
be added implicitly to the end of the list. The syntax is as follows:
```
match <SRV_GROUP> * * * ;
```


### Scheduling Requests inside Server Groups

**Server Schedulers** are bound to exact server groups, see 
[Setting scheduler]() section in [Server Group]() description.

User can override default server scheduler for all groups using `sched`
configuration option:
```
sched <SCHED_NAME>;
```


#### Round-Robin Scheduler

**TODO:** update to Ratio and extended weights.

Rotates all servers in a group in round-robin manner, parallel connections to 
the same server are also rotated in the round-robin manner, so requests are 
distributed to all the servers in a group in a fair way.

Scheduler name for use in configuration file: `round-robin`.


#### Hash Scheduler

Chooses server to schedule request to by hashed key value. Key is built using
_uri_, _request method_ and host header of the request. In most cases load will
be distributed among all the servers in group, but situations when single server
pulls all the load are also possible. Although it is quite improbable, such 
condition is quite stable: it cannot be fixed by adding/removing servers and 
restarting Tempesta FW.

Scheduler name for use in configuration file: `hash`.


### Scheduling HTTP sessions to the same server

None of the schedulers is responsible for forwarding requests from the same HTTP
session to the same server. [Sticky Sessions]() option should be used instead.


### Effects caused to schedulers by other configuration options


#### Limitations

- [HTTP Scheduler](#HTTP Scheduler) must not provide multiple backup groups to the same group
if [Sticky Sessions]() are enabled.


### Troubleshooting


## Developer Guide

Both schedulers Group and Server are derived from the same `TfwScheduler` class,
declared in `server.h`.
Group schedulers must implement `sched_grp()` callback, where the scheduler must
find target main and backup server groups for the request. Server schedulers
must implement `sched_sg_conn()` and `sched_srv_conn()` to schedule request to any or
exact server in the group. This functions must be designed to work in highly
concurrent environment.

Usually schedulers are implemented as a separate modules and register/deregister themselves 
in TempestaFW by calling `tfw_sched_register()`/`tfw_sched_unregister()` on module 
initialization. Group schedulers are stored at the head of the list, Server schedulers -
at the end.


### Schedulers work flow

Each request that cannot be served from cache must be scheduled to appropriate 
server. This happens in SoftIRQ during `tfw_http_req_cache_cb()` right after
obtaining HTTP session for the request. 
 
