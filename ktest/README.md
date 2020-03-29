# Tempesta Kernel Emulation Framework for Unit Testing

Light-weigh Linux kernel mocking headers-only library for unit testing.
Read description and comparison with other testing framework at the
[Wiki](https://github.com/tempesta-tech/tempesta/wiki/Testing).

See usage examples in tempesta\_db/t/tdb\_htrie.c and tls/t/test\_tls.c.


# Multi-processing

The framework emulates 32 CPUs by default using pthreads and arrays for
per-cpu variables. To use it for single-threaded testing, redefine `NR_CPUS`
before the file include:
```C
#define NR_CPUS 1
#include "ktest.h"
```
