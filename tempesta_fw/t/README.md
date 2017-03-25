# Tempesta FW tests

To compile and run tests, do:

    cd /root/of/tempesta/git/repo
    make test

That will compile and execute both unit and functional tests.


## `unit/`

Unit tests are relatively low-level tests single C functions and module (translation units) of the Tempesta FW source code.

The implementation is done as simple as possible:

- Unit tests are implemented in C as a plain kernel module. Yes, they run in the kernel space, which is not an elegant solution, but it saves a lot of time that otherwise could be spent for mocking the kernel. The module is called `tfw_test`.

- All unit tests are contained in this single kernel module in order to avoid polluting real-world systems with testing code.

- Tests are plain C functions that call another functions. Tempesta FW functions live in a separate module, so all tested functions should be exported in order to be visible in another module. We export them, but only in the `DEBUG` build to avoid polluting the global symbol table in a release build.

- Test functions are organized into suites, one suite per file, for example: `test_http_parser.c`, `test_str.c`. Usually for each suite there is a corresponding unit in the Tempesta code (i.e. `test_http_parser.c` -> `http_parser.c`, `test_str.c` -> `str.c`, etc).

- There is a tiny testing framework located at `unit/test.h` which is just a bunch of macros mimicing Google Test API. We hope to run tests in the user-space in future.

- The `tfw_test` module are compiled together with the main Tempesta FW module, there is no separate build system or configuration for them. The process is controlled by the root `Makefile`. When you compile Tempesta Fw, you get tests compiled for free. That allows to keep `Makefile`s simple and ensure that you always run recent tests for the recent main module.

- All tests are executed when the `tfw_test` module is loaded. At this point there is no way to select particular suites/cases to run. Tests are pretty fast, so this is not a problem. To run tests, we just insert the module and collect the test output from the `dmesg` buffer. This is done by the script: `unit/run_all_tests.sh`. The script should be executed after the main Tempesta FW module is loaded.


## `functional/`

Functional tests don't work with source code entities, they are more higher-level tests. 

Functional tests are written in Python because it has rich standard library that includes things like sockets, HTTP client/server and easy integration with C code.

A typical scenario for such test looks like this:

1. Start a small HTTP server that acts like a back-end for Tempesta FW.
2. Configure Tempesta to connect to our back-end server.
3. Send some HTTP requests to check certain behavior, e.g. send a malicious request and check that it is filtered-out by Tempesta (didn't received by the back-end server).

So in contrast to unit tests, the functional testing is (mostly) a black-box testing. We don't check source code here, but rather certain features like "caching" or "ratio load balancing". Also we run tests in a realistic environment: we send real HTTP requests via real sockets, configuring Tempesta as it was working on a real-world server, etc.

We also trying to keep things simple here. Each test is a separate `.py` file under the `functional/` directory. It is executed linearly as a script without usual complicated stuff like organizing tests into classes that represents suites. Every test is a separate program that executes whatever it likes to. To run a test, just execute the corresponding `.py` file.

A bunch of shared helper utils is located in the `functional/helpers` subdirectory. They do all the dirty job of initializing Tempesta, starting the back-end HTTP server, sending packets via sockets, etc.

Also there is a script that runs all tests: `run_all_tests.sh`. It simply enumerates all those separate test scripts. In contrast to unit tests, the script should be executed when Tempesta FW is not running.

