import collections
import os.path
import re

from . import utils


class Changelog(list):
    _rules = r"""
^
(?P<source>
    \w[-+0-9a-z.]+
)
\ 
\(
(?P<version>
    [^\(\)\ \t]+
)
\)
\s+
(?P<distribution>
    [-+0-9a-zA-Z.]+
)
\;\s+urgency=
(?P<urgency>
    \w+
)
"""
    _re = re.compile(_rules, re.X)

    class Entry(object):
        __slot__ = 'distribution', 'source', 'version', 'urgency'

        def __init__(self, distribution, source, version, urgency):
            self.distribution, self.source, self.version, self.urgency = \
                distribution, source, version, urgency

    def __init__(self, dir='', version=None):
        if version is None:
            version = Version
        f = open(os.path.join(dir, "debian/changelog"), encoding="UTF-8")
        while True:
            line = f.readline()
            if not line:
                break
            match = self._re.match(line)
            if not match:
                continue
            try:
                v = version(match.group('version'))
            except Exception:
                if not len(self):
                    raise
                v = Version(match.group('version'))
            self.append(self.Entry(match.group('distribution'),
                                   match.group('source'), v,
                                   match.group('urgency')))


class Version(object):
    _version_rules = r"""
^
(?:
    (?P<epoch>
        \d+
    )
    :
)?
(?P<upstream>
    .+?
)   
(?:
    -
    (?P<revision>[^-]+)
)?
$
"""
    _version_re = re.compile(_version_rules, re.X)

    def __init__(self, version):
        match = self._version_re.match(version)
        if match is None:
            raise RuntimeError(u"Invalid debian version")
        self.epoch = None
        if match.group("epoch") is not None:
            self.epoch = int(match.group("epoch"))
        self.upstream = match.group("upstream")
        self.revision = match.group("revision")

    def __str__(self):
        return self.complete

    @property
    def complete(self):
        if self.epoch is not None:
            return u"%d:%s" % (self.epoch, self.complete_noepoch)
        return self.complete_noepoch

    @property
    def complete_noepoch(self):
        if self.revision is not None:
            return u"%s-%s" % (self.upstream, self.revision)
        return self.upstream

    @property
    def debian(self):
        from warnings import warn
        warn(u"debian argument was replaced by revision", DeprecationWarning, stacklevel=2)
        return self.revision


class VersionLinux(Version):
    _version_linux_rules = r"""
^
(?P<version>
    \d+\.\d+
)
(?P<update>
    (?:\.\d+)?
    (?:-[a-z]+\d+)?
)
(?:
    ~
    (?P<modifier>
        .+?
    )
)?
(?:
    \.dfsg\.
    (?P<dfsg>
        \d+
    )
)?
-
\d+
(\.\d+)?
(?:
    (?P<revision_experimental>
        ~exp\d+
    )
    |
    (?P<revision_security>
        [~+]deb\d+u\d+
    )?
    (?P<revision_backports>
        ~bpo\d+\+\d+
    )?
    |
    (?P<revision_other>
        [^-]+
    )
)
$
"""
    _version_linux_re = re.compile(_version_linux_rules, re.X)

    def __init__(self, version):
        super(VersionLinux, self).__init__(version)
        match = self._version_linux_re.match(version)
        if match is None:
            raise RuntimeError(u"Invalid debian linux version")
        d = match.groupdict()
        self.linux_modifier = d['modifier']
        self.linux_version = d['version']
        if d['modifier'] is not None:
            assert not d['update']
            self.linux_upstream = '-'.join((d['version'], d['modifier']))
        else:
            self.linux_upstream = d['version']
        self.linux_upstream_full = self.linux_upstream + d['update']
        self.linux_dfsg = d['dfsg']
        self.linux_revision_experimental = match.group('revision_experimental') and True
        self.linux_revision_security = match.group('revision_security') and True
        self.linux_revision_backports = match.group('revision_backports') and True
        self.linux_revision_other = match.group('revision_other') and True


class PackageArchitecture(collections.MutableSet):
    __slots__ = '_data'

    def __init__(self, value=None):
        self._data = set()
        if value:
            self.extend(value)

    def __contains__(self, value):
        return self._data.__contains__(value)

    def __iter__(self):
        return self._data.__iter__()

    def __len__(self):
        return self._data.__len__()

    def __str__(self):
        return ' '.join(sorted(self))

    def add(self, value):
        self._data.add(value)

    def discard(self, value):
        self._data.discard(value)

    def extend(self, value):
        if isinstance(value, str):
            for i in re.split('\s', value.strip()):
                self.add(i)
        else:
            raise RuntimeError


class PackageDescription(object):
    __slots__ = "short", "long"

    def __init__(self, value=None):
        self.short = []
        self.long = []
        if value is not None:
            desc_split = value.split("\n", 1)
            self.append_short(desc_split[0])
            if len(desc_split) == 2:
                self.append(desc_split[1])

    def __str__(self):
        wrap = utils.TextWrapper(width=74, fix_sentence_endings=True).wrap
        short = ', '.join(self.short)
        long_pars = []
        for i in self.long:
            long_pars.append(wrap(i))
        long = '\n .\n '.join(['\n '.join(i) for i in long_pars])
        return short + '\n ' + long if long else short

    def append(self, str):
        str = str.strip()
        if str:
            self.long.extend(str.split(u"\n.\n"))

    def append_short(self, str):
        for i in [i.strip() for i in str.split(u",")]:
            if i:
                self.short.append(i)

    def extend(self, desc):
        if isinstance(desc, PackageDescription):
            self.short.extend(desc.short)
            self.long.extend(desc.long)
        else:
            raise TypeError


class PackageRelation(list):
    def __init__(self, value=None, override_arches=None):
        if value:
            self.extend(value, override_arches)

    def __str__(self):
        return ', '.join(str(i) for i in self)

    def _search_value(self, value):
        for i in self:
            if i._search_value(value):
                return i
        return None

    def append(self, value, override_arches=None):
        if isinstance(value, str):
            value = PackageRelationGroup(value, override_arches)
        elif not isinstance(value, PackageRelationGroup):
            raise ValueError(u"got %s" % type(value))
        j = self._search_value(value)
        if j:
            j._update_arches(value)
        else:
            super(PackageRelation, self).append(value)

    def extend(self, value, override_arches=None):
        if isinstance(value, str):
            value = (j.strip() for j in re.split(',', value.strip()))
        for i in value:
            self.append(i, override_arches)


class PackageRelationGroup(list):
    def __init__(self, value=None, override_arches=None):
        if value:
            self.extend(value, override_arches)

    def __str__(self):
        return ' | '.join(str(i) for i in self)

    def _search_value(self, value):
        for i, j in zip(self, value):
            if i.name != j.name or i.operator != j.operator or \
               i.version != j.version or i.restrictions != j.restrictions:
                return None
        return self

    def _update_arches(self, value):
        for i, j in zip(self, value):
            if i.arches:
                for arch in j.arches:
                    if arch not in i.arches:
                        i.arches.append(arch)

    def append(self, value, override_arches=None):
        if isinstance(value, str):
            value = PackageRelationEntry(value, override_arches)
        elif not isinstance(value, PackageRelationEntry):
            raise ValueError
        super(PackageRelationGroup, self).append(value)

    def extend(self, value, override_arches=None):
        if isinstance(value, str):
            value = (j.strip() for j in re.split('\|', value.strip()))
        for i in value:
            self.append(i, override_arches)


class PackageRelationEntry(object):
    __slots__ = "name", "operator", "version", "arches", "restrictions"

    _re = re.compile(r'^(\S+)(?: \((<<|<=|=|!=|>=|>>)\s*([^)]+)\))?(?: \[([^]]+)\])?(?: <([^>]+)>)?$')

    class _operator(object):
        OP_LT = 1
        OP_LE = 2
        OP_EQ = 3
        OP_NE = 4
        OP_GE = 5
        OP_GT = 6

        operators = {
                '<<': OP_LT,
                '<=': OP_LE,
                '=': OP_EQ,
                '!=': OP_NE,
                '>=': OP_GE,
                '>>': OP_GT,
        }

        operators_neg = {
                OP_LT: OP_GE,
                OP_LE: OP_GT,
                OP_EQ: OP_NE,
                OP_NE: OP_EQ,
                OP_GE: OP_LT,
                OP_GT: OP_LE,
        }

        operators_text = dict((b, a) for a, b in operators.items())

        __slots__ = '_op',

        def __init__(self, value):
            self._op = self.operators[value]

        def __neg__(self):
            return self.__class__(self.operators_text[self.operators_neg[self._op]])

        def __str__(self):
            return self.operators_text[self._op]

        def __eq__(self, other):
            return type(other) == type(self) and self._op == other._op

    def __init__(self, value=None, override_arches=None):
        if not isinstance(value, str):
            raise ValueError

        self.parse(value)

        if override_arches:
            self.arches = list(override_arches)

    def __str__(self):
        ret = [self.name]
        if self.operator is not None and self.version is not None:
            ret.extend((' (', str(self.operator), ' ', self.version, ')'))
        if self.arches:
            ret.extend((' [', ' '.join(self.arches), ']'))
        if self.restrictions:
            ret.extend((' <', ' '.join(self.restrictions), '>'))
        return ''.join(ret)

    def parse(self, value):
        match = self._re.match(value)
        if match is None:
            raise RuntimeError(u"Can't parse dependency %s" % value)
        match = match.groups()
        self.name = match[0]
        if match[1] is not None:
            self.operator = self._operator(match[1])
        else:
            self.operator = None
        self.version = match[2]
        if match[3] is not None:
            self.arches = re.split('\s+', match[3])
        else:
            self.arches = []
        if match[4] is not None:
            self.restrictions = re.split('\s+', match[4])
        else:
            self.restrictions = []


class _ControlFileDict(dict):
    def __setitem__(self, key, value):
        try:
            cls = self._fields[key]
            if not isinstance(value, cls):
                value = cls(value)
        except KeyError:
            pass
        super(_ControlFileDict, self).__setitem__(key, value)

    def keys(self):
        keys = set(super(_ControlFileDict, self).keys())
        for i in self._fields.keys():
            if i in self:
                keys.remove(i)
                yield i
        for i in sorted(list(keys)):
            yield i

    def items(self):
        for i in self.keys():
            yield (i, self[i])

    def values(self):
        for i in self.keys():
            yield self[i]


class Package(_ControlFileDict):
    _fields = collections.OrderedDict((
        ('Package', str),
        ('Source', str),
        ('Architecture', PackageArchitecture),
        ('Section', str),
        ('Priority', str),
        ('Maintainer', str),
        ('Uploaders', str),
        ('Standards-Version', str),
        ('Build-Depends', PackageRelation),
        ('Build-Depends-Indep', PackageRelation),
        ('Provides', PackageRelation),
        ('Pre-Depends', PackageRelation),
        ('Depends', PackageRelation),
        ('Recommends', PackageRelation),
        ('Suggests', PackageRelation),
        ('Replaces', PackageRelation),
        ('Breaks', PackageRelation),
        ('Conflicts', PackageRelation),
        ('Description', PackageDescription),
    ))


class TestsControl(_ControlFileDict):
    _fields = collections.OrderedDict((
        ('Tests', str),
        ('Test-Command', str),
        ('Restrictions', str),
        ('Features', str),
        ('Depends', PackageRelation),
        ('Tests-Directory', str),
        ('Classes', str),
    ))
