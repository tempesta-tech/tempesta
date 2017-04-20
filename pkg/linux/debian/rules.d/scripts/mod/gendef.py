#!/usr/bin/python
import re
import sys

for line in open(sys.argv[1]):
    match = re.search('getopt\(argc, argv, "([\w:]*?)"\)', line)
    if match:
        options = match.group(1)
        break
else:
    raise RuntimeError

print '#define GETOPT_OPTIONS "%s"' % options

print '#define GETOPT_CASE',
for c in options:
    if c == ':' or c == 'T':
        continue
    print "case '%c':" % c,
print
