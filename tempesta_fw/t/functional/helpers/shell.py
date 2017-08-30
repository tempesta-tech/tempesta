#!/usr/bin/env python2
from __future__ import print_function
import unittest
import os
import errno
import json
from helpers import tf_cfg

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class TestResume:
    # Filter is instantiated by TestResume.filter(), passing instance of the
    # matcher to the instance of the filter.
    class Filter:
        def __init__(self, matcher):
            self.matcher = matcher
            self.flag = False

        def __call__(self, test):
            if self.flag:
                return True
            if testcase_in(test, [self.matcher.last_id]):
                self.flag = True
                return not self.matcher.last_completed

    # Result is instantiated not under our control, so we can't pass a matcher
    # to Result.__init__(). Instead, we dynamically create derived classes
    # that will refer to a certain matcher as a class attribute.
    class Result(unittest.TextTestResult):
        matcher = None

        def __init__(self, *args, **kwargs):
            unittest.TextTestResult.__init__(self, *args, **kwargs)

        def startTest(self, test):
            self.matcher.advance(test.id())
            return unittest.TextTestResult.startTest(self, test)

        def stopTest(self, test):
            self.matcher.advance(test.id(), after=True)
            return unittest.TextTestResult.stopTest(self, test)

    state_file = os.path.relpath(os.path.join(
        os.path.dirname(__file__),
        '..',
        'tests_resume.json'
    ))

    def __init__(self, filename=None):
        self.last_id = None
        self.last_completed = False
        if filename is not None:
            self.state_file = filename
        self.inclusions = set()
        self.exclusions = set()
        self.from_file = False

    def unlink_file(self):
        try:
            os.unlink(self.state_file)
        except OSError as e:
            if e.errno != errno.ENOENT:
                raise

    def set_from_file(self):
        try:
            with open(self.state_file, 'r') as f:
                state = self.__parse_file(f)
        except IOError as e:
            if e.errno != errno.ENOENT:
                raise
            tf_cfg.dbg(2, 'Not resuming from "%s": file does not exist' %
                          self.state_file)
            return
        if not (self.inclusions == state['inclusions'] and
                self.exclusions == state['exclusions']):
            tf_cfg.dbg(1, 'Not resuming from "%s": different filters specified' %
                          self.state_file)
            return
        # will raise before changing anything if state object is incomplete
        self.set(test=state['last_id'],
                 after=state['last_completed'])
        self.from_file = True

    def set(self, test, after=False):
        self.last_id = test
        self.last_completed = after
        self.from_file = False

    def set_filters(self, inclusions, exclusions):
        self.inclusions = set(inclusions)
        self.exclusions = set(exclusions)

    def advance(self, test, after=False):
        self.last_id = test
        self.last_completed = after
        with open(self.state_file, 'w') as f:
            self.__build_file(f)

    def __nonzero__(self):
        return self.last_id is not None

    def __parse_file(self, f):
        dump = json.load(f)
        # convert lists to sets where needed
        for key in ('inclusions', 'exclusions'):
            dump[key] = set(dump[key])
        return dump

    def __build_file(self, f):
        dump = self.__dict__.copy()
        # convert sets to lists where needed
        for key in ('inclusions', 'exclusions'):
            dump[key] = list(dump[key])
        json.dump(dump, f)

    def filter(self):
        if self:
            return TestResume.Filter(self)
        else:
            return lambda test: True

    def resultclass(self):
        return type('Result', (TestResume.Result,), {'matcher': self})

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
