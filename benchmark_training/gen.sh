#! /bin/bash

g++ mybenchmark.cc  -std=c++11 -isystem benchmark/include  -Lbenchmark/build/src -lbenchmark  -o mybenchmark
g++ check_accuracy.cc  -std=c++11 -o check_accuracy