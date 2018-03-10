""" Helper for Tempesta system log operations."""

from __future__ import print_function
import re
from . import remote

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


class DmesgFinder(object):
    """dmesg helper class. """

    def __init__(self):
        self.node = remote.tempesta
        self.log = ''
        self.get_log_cmd = (
            'dmesg | tac | grep -m 1 -B 10000 "Start Tempesta DB" | tac')

    def update(self):
        """Get log from the last run."""
        self.log, _ = self.node.run_cmd(self.get_log_cmd)

    def show(self):
        """Show tempesta system log."""
        print(self.log)

    def warn_count(self, warn_str):
        """Count occurrences of given string in system log. Normally used to
        count warnings during test.
        """
        match = re.findall(warn_str, self.log)
        return len(match)

WARN_GENERIC = 'Warning: '
WARN_SPLIT_ATTACK = 'Warning: Paired request missing, HTTP Response Splitting attack?'

def count_warnings(msg):
    """Get system log and count occurrences of single warnings."""
    dmesg = DmesgFinder()
    dmesg.update()
    return dmesg.warn_count(msg)
