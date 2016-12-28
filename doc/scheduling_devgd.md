# Scheduling in TempestaFW: Developer Guide

Normally schedulers are separate modules with sources under `tempesta_fw/sched/`
directory. Common scheduling routines and helpers implemented in `tempesta_fw/sched.c`.

Both schedulers Group and Server are derived from the same `TfwScheduler` class,
declared in `server.h`. Group schedulers must implement `sched_grp()` callback,
where the scheduler must find target main and backup server groups for the request.
Group scheduler must find target main and backup server groups and use 
`tfw_sched_sg_get_conn()` to schedule request to a server in one of that groups.

Server schedulers must implement `sched_sg_conn()` and `sched_srv_conn()` to 
schedule request to any or to exact server in the group; `add_group()` and 
`del_group()` for binding scheduler to group; `add_conn()` for adding server's 
connection to list of known by scheduler. All the functions and `sched*()` in 
particular must be designed to work in highly concurrent environment.

Schedulers register/deregister themselves 
in TempestaFW by calling `tfw_sched_register()`/`tfw_sched_unregister()` on module 
initialisation. Group schedulers are stored at the head of the list `sched_list`,
Server schedulers - at the end of it.

After new [Server group]() created, it binds itself to scheduler defined in
Tempesta configuration by calling `add_group()`. During that call scheduler
allocate it's private structure of server connections and theirs metadata in
server group's member `sched_data`. When new connections for servers in the group
is added by `add_conn()`.


## Scheduling request

Each request that cannot be served from cache must be scheduled to appropriate 
server by `tfw_sched_get_conn()` call. HTTP session for the request must be obtained
before call. This happens in SoftIRQ during `tfw_http_req_cache_cb()`.

In order to get target connection message is passed to the Group schedulers.
Group schedulers must find target main and backup server groups and use 
`tfw_sched_sg_get_conn()` to schedule request to a server in one of that groups.

If [Sticky Sessions]() are not enabled `tfw_sched_sg_get_conn()` try to schedule
request to main server group or to backup server group if main group is offline.
To do so callbacks `sched_sg_conn()` of schedulers registered for main and backup
groups are called.

If [Sticky Sessions]() enabled, but HTTP session for the request was not found
situation is the same. That happens if client does not
support cookies and [Sticky cookies are not enforced]().

Situation became a little bit tricky if [Sticky Sessions]() and HTTP session
for request was found. We must schedule request to the same servers whenever it
is possible:

- Current HTTP session was not scheduled to main server group.

Schedule to any server in main group. If main group is offline, schedule to
backup group. If the session was scheduled to backup group, last used connection
must be reused, otherwise session must be scheduled to any server in backup
group.

There still can be a situation, when session _was_ scheduled to main server
group. This happens when main server group is used as a backup group for some 
other group. In that case we must reuse that connection.

- Current session was scheduled to main server group before.

Reuse last connection. Note, that last connection may lead to server in backup
group. That is normal situation and we have to keep scheduling to that server
even if main server group is back online. Connection must be rescheduled to
main server group and to backup (if main is offline) only when last used server
offline and [user allowed us to do so]().

After connection to desired server group was obtained it saved in HTTP session.
This logic is described in `tfw_sched_srv_get_sticky_conn()` in `sched.c`.
