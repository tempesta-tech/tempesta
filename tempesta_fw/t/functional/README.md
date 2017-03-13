
# Tempesta FW Functional tests.

## Prerequisites

Before runing functional tests you need to compile the Tempesta with its prerequisites.
Most of the functional test use the Apache web server as back-end. So you need to install it.
A Integrated test back-end requires package python-setproctitle.


## Run tests

To run one test you can use from a tempesta directory:

  $ tempesta_fw/t/functional/run_tests.sh [test_name]

Or:

  $ tempesta_fw/t/functional/tests.py [test_name]

To run all tests:

  $ tempesta_fw/t/functional/run_tests.sh all

Or:

  $ tempesta_fw/t/functional/tests.py all

To set the ip port of the test http backend server you can use a parameter:

-p <port>.

For example:

 $ tempesta_fw/t/functional/run_tests.sh test_parser -p 8080
 



## Add new tests

To add new tests you need to write a new functional tests in python and
put it in directory:

  $ tempesta_fw/t/functional/tests/

And add the name of the new test in the init-file:


  $ tempesta_fw/t/functional/tests/\_\_init\_\_.py.

When you write functional test, you can use helper modules from

  $ tempesta_fw/t/functional/test/helpers/


