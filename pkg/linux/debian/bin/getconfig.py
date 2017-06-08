#!/usr/bin/python3

import sys
sys.path.append(sys.path[0] + "/../lib/python")

from debian_linux.config import ConfigCoreDump

section = tuple(s or None for s in sys.argv[1:-1])
key = sys.argv[-1]
config = ConfigCoreDump(fp=open("debian/config.defines.dump", "rb"))
try:
    value = config[section][key]
except KeyError:
    sys.exit(1)

if isinstance(value, str):
    # Don't iterate over it
    print(value)
else:
    # In case it's a sequence, try printing each item
    try:
        for item in value:
            print(item)
    except TypeError:
        # Otherwise use the default format
        print(value)

