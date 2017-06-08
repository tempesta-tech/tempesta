from collections import OrderedDict

__all__ = (
    "KconfigFile",
)


class KConfigEntry(object):
    __slots__ = 'name', 'value', 'comments'

    def __init__(self, name, value, comments=None):
        self.name, self.value = name, value
        self.comments = comments or []

    def __eq__(self, other):
        return self.name == other.name and self.value == other.value

    def __hash__(self):
        return hash(self.name) | hash(self.value)

    def __repr__(self):
        return '<{}({!r}, {!r}, {!r})>'.format(self.__class__.__name__, self.name, self.value, self.comments)

    def __str__(self):
        return 'CONFIG_{}={}'.format(self.name, self.value)

    def write(self):
        for comment in self.comments:
            yield '#. ' + comment
        yield str(self)


class KConfigEntryTristate(KConfigEntry):
    __slots__ = ()

    VALUE_NO = False
    VALUE_YES = True
    VALUE_MOD = object()

    def __init__(self, name, value, comments=None):
        if value == 'n' or value is None:
            value = self.VALUE_NO
        elif value == 'y':
            value = self.VALUE_YES
        elif value == 'm':
            value = self.VALUE_MOD
        else:
            raise NotImplementedError
        super(KConfigEntryTristate, self).__init__(name, value, comments)

    def __str__(self):
        if self.value is self.VALUE_MOD:
            return 'CONFIG_{}=m'.format(self.name)
        if self.value:
            return 'CONFIG_{}=y'.format(self.name)
        return '# CONFIG_{} is not set'.format(self.name)


class KconfigFile(OrderedDict):
    def __str__(self):
        ret = []
        for i in self.str_iter():
            ret.append(i)
        return '\n'.join(ret) + '\n'

    def read(self, f):
        for line in iter(f.readlines()):
            line = line.strip()
            if line.startswith("CONFIG_"):
                i = line.find('=')
                option = line[7:i]
                value = line[i + 1:]
                self.set(option, value)
            elif line.startswith("# CONFIG_"):
                option = line[9:-11]
                self.set(option, 'n')
            elif line.startswith("#") or not line:
                pass
            else:
                raise RuntimeError("Can't recognize %s" % line)

    def set(self, key, value):
        if value in ('y', 'm', 'n'):
            entry = KConfigEntryTristate(key, value)
        else:
            entry = KConfigEntry(key, value)
        self[key] = entry

    def str_iter(self):
        for key, value in self.items():
            yield str(value)
