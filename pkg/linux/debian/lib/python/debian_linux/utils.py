import codecs
import os
import re
import textwrap


class Templates(object):
    def __init__(self, dirs=["debian/templates"]):
        self.dirs = dirs

        self._cache = {}

    def __getitem__(self, key):
        ret = self.get(key)
        if ret is not None:
            return ret
        raise KeyError(key)

    def _read(self, name):
        prefix, id = name.split('.', 1)

        for suffix in ['.in', '']:
            for dir in self.dirs:
                filename = "%s/%s%s" % (dir, name, suffix)
                if os.path.exists(filename):
                    f = codecs.open(filename, 'r', 'utf-8')
                    if prefix == 'control':
                        return read_control(f)
                    if prefix == 'tests-control':
                        return read_tests_control(f)
                    return f.read()

    def get(self, key, default=None):
        if key in self._cache:
            return self._cache[key]

        value = self._cache.setdefault(key, self._read(key))
        if value is None:
            return default
        return value


def read_control(f):
    from .debian import Package
    return _read_rfc822(f, Package)

def read_tests_control(f):
    from .debian import TestsControl
    return _read_rfc822(f, TestsControl)

def _read_rfc822(f, cls):
    entries = []
    eof = False

    while not eof:
        e = cls()
        last = None
        lines = []
        while True:
            line = f.readline()
            if not line:
                eof = True
                break
            # Strip comments rather than trying to preserve them
            if line[0] == '#':
                continue
            line = line.strip('\n')
            if not line:
                break
            if line[0] in ' \t':
                if not last:
                    raise ValueError('Continuation line seen before first header')
                lines.append(line.lstrip())
                continue
            if last:
                e[last] = '\n'.join(lines)
            i = line.find(':')
            if i < 0:
                raise ValueError(u"Not a header, not a continuation: ``%s''" % line)
            last = line[:i]
            lines = [line[i + 1:].lstrip()]
        if last:
            e[last] = '\n'.join(lines)
        if e:
            entries.append(e)

    return entries


class TextWrapper(textwrap.TextWrapper):
    wordsep_re = re.compile(
        r'(\s+|'                                  # any whitespace
        r'(?<=[\w\!\"\'\&\.\,\?])-{2,}(?=\w))')   # em-dash
