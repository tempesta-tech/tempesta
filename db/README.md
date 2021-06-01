## Tempesta DB

**Tempesta DB** (TDB) is persistent in-memory in-kernel key-value database.
The typical applications are: application caches, filter rules,
resolver results, events, staistics and access logs or traffic dumps.

**libtdb** provices access to the database from user-space. Unlike other common
embedded databases, Tempesta DB can be used by many processes concurrently.
Meantime, the database has much lower overhead for data transport in comparison
with client-server databases. The library should be considered as an embedded
database.

The database is designed to work in deferred interrupt context, so it doesn't
sleep on read or write operations.

Fixed and variable length records can be stored. However, fixed size records
can't have zero key and data at the same time - such records treated as deleted.


### Tempesta DB Query Tool

**tdbq** is user-space CLI tool to query the in-kernel database.
The tool is built on top of **libtdb**.
Please see the below some usage examples.

#### Prerequisites

To start to use TDB load the module and add **libtdb** to LD\_LIBRARY\_PATH

        $ insmod tempesta_db.ko
        $ export LD_LIBRARY_PATH=`pwd`/libtdb/

#### Open a Table

TDB mainatins tables as binarys files, so to create a table you must specify the
path to its file and its name:

        $ tdbq -a open -p /tmp -t test
        table test opened
        OPEN: records=0 status=OK zero-copy

Command line key `-a` specifies required action, open in this case. The command
above creates `/tmp/test.tdb` with default size of 2MB. TDB uses extents,
so size of its files must be multiple of 2MB. Please, see built-in **tdbq** help
for other command line switches.

At end of successful output **tdbq** prints status line with the operation name,
number of affected records, the command status and kerne/user-space transport
method - zero-copy or copying.

#### Insert a New Record

        $ tdbq -t test -a insert -k 'KEY' -v 'THE_DATA'
        INSERT: records=1 status=OK zero-copy

#### Select a Record

        $ tdbq -t test -a select -k 'KEY'
        'KEY' -> 'THE_DATA'
        SELECT: records=1 status=OK zero-copy

