## Tempesta DB

**Tempesta DB** is in-memory in-kernel key-value database with weak persistency.
The typical applications are: application caches, filter rules, resolver
results, events, staistics and access logs or traffic dumps.

It can work in deffered interrupt context, so it doesn't sleep on disk
operations, but it is still persistent. All data is mmap()'ed and mlock()'ed
which makes Linux syncronize the memory region with disk and vise versa.

Fixed and variable length records can be stored. However, fixed size records
can't have zero key and data at the same time - such records treated as deleted.
