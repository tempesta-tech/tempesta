#!/usr/bin/env python3

import optparse
import os.path
import re
import sys

from debian_linux.kconfig import *


def merge(output, configs, overrides):
    kconfig = KconfigFile()
    for c in configs:
        kconfig.read(open(c))
    for key, value in overrides.items():
        kconfig.set(key, value)
    open(output, "w").write(str(kconfig))


def opt_callback_dict(option, opt, value, parser):
    match = re.match('^\s*(\S+)=(\S+)\s*$', value)
    if not match:
        raise optparse.OptionValueError('not key=value')
    dest = option.dest
    data = getattr(parser.values, dest)
    data[match.group(1)] = match.group(2)


if __name__ == '__main__':
    parser = optparse.OptionParser(usage="%prog [OPTION]... FILE...")
    parser.add_option(
        '-o', '--override',
        action='callback',
        callback=opt_callback_dict,
        default={},
        dest='overrides',
        help="Override option",
        type='string')
    options, args = parser.parse_args()

    merge(args[0], args[1:], options.overrides)
