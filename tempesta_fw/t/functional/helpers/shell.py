#!/usr/bin/env python2
from __future__ import print_function
import unittest
import os
import errno

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

# I'd use a recursive generator, but `yield from` is python 3.3+
def testsuite_flatten(dest, src):
    if isinstance(src, unittest.TestSuite):
        for t in src:
            testsuite_flatten(dest, t)
    else:
        dest.append(src)

def testcase_in(test, lst):
    test_id = test.id()
    for entry in lst:
        if test_id == entry or test_id.startswith(entry + '.'):
            return True
    return False

def test_id_parse(loader, name):
    if name and os.path.exists(name):
        return loader._get_name_from_path(name)
    return name
