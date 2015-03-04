## Tempesta DB

**Tempesta DB** is persistent in-memory in-kernel key-value database.
The typical applications are: application caches, filter rules,
resolver results, events, staistics and access logs or traffic dumps.

**libtdb** provices access to the database from user-space. Unlike other common
embedded databases, Tempesta DB can be used by many processes concurrently.
Meantime, the database has much lower overhead for data transport in comparison
with client-server databases. The library should be considered as an embedded
database.

The database is designed to work in deffered interrupt context, so it doesn't
sleep on read or write operations.

Fixed and variable length records can be stored. However, fixed size records
can't have zero key and data at the same time - such records treated as deleted.


### Tempesta DB Query Tool

**tdbq** is user-space CLI tool to query the in-kernel database.
The tool is built on top of **libtdb**.
Please see the below some some usage examples.

#### .....
