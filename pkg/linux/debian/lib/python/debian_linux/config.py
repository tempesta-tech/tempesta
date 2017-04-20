import os
import os.path
import pickle
import re
import sys
import textwrap

try:
    from configparser import RawConfigParser
except ImportError:
    from ConfigParser import RawConfigParser

__all__ = [
    'ConfigCoreDump',
    'ConfigCoreHierarchy',
    'ConfigParser',
]


class SchemaItemBoolean(object):
    def __call__(self, i):
        i = i.strip().lower()
        if i in ("true", "1"):
            return True
        if i in ("false", "0"):
            return False
        raise Error


class SchemaItemInteger(object):
    def __call__(self, i):
        try:
            return int(i.strip(), 0)
        except ValueError:
            raise Error


class SchemaItemList(object):
    def __init__(self, type="\s+"):
        self.type = type

    def __call__(self, i):
        i = i.strip()
        if not i:
            return []
        return [j.strip() for j in re.split(self.type, i)]


class ConfigCore(dict):
    def get_merge(self, section, arch, featureset, flavour, key, default=None):
        temp = []

        if arch and featureset and flavour:
            temp.append(self.get((section, arch, featureset, flavour), {}).get(key))
            temp.append(self.get((section, arch, None, flavour), {}).get(key))
        if arch and featureset:
            temp.append(self.get((section, arch, featureset), {}).get(key))
        if arch:
            temp.append(self.get((section, arch), {}).get(key))
        if featureset:
            temp.append(self.get((section, None, featureset), {}).get(key))
        temp.append(self.get((section,), {}).get(key))

        ret = []

        for i in temp:
            if i is None:
                continue
            elif isinstance(i, (list, tuple)):
                ret.extend(i)
            elif ret:
                # TODO
                return ret
            else:
                return i

        return ret or default

    def merge(self, section, arch=None, featureset=None, flavour=None):
        ret = {}
        ret.update(self.get((section,), {}))
        if featureset:
            ret.update(self.get((section, None, featureset), {}))
        if arch:
            ret.update(self.get((section, arch), {}))
        if arch and featureset:
            ret.update(self.get((section, arch, featureset), {}))
        if arch and featureset and flavour:
            ret.update(self.get((section, arch, None, flavour), {}))
            ret.update(self.get((section, arch, featureset, flavour), {}))
        return ret

    def dump(self, fp):
        pickle.dump(self, fp, 0)


class ConfigCoreDump(object):
    def __new__(self, fp):
        return pickle.load(fp)


class ConfigCoreHierarchy(object):
    schema_base = {
        'base': {
            'arches': SchemaItemList(),
            'enabled': SchemaItemBoolean(),
            'featuresets': SchemaItemList(),
            'flavours': SchemaItemList(),
        },
    }

    def __new__(cls, schema, dirs=[]):
        schema_complete = cls.schema_base.copy()
        for key, value in schema.items():
            schema_complete.setdefault(key, {}).update(value)
        return cls.Reader(dirs, schema_complete)()

    class Reader(object):
        config_name = "defines"

        def __init__(self, dirs, schema):
            self.dirs, self.schema = dirs, schema

        def __call__(self):
            ret = ConfigCore()
            self.read(ret)
            return ret

        def get_files(self, *dirs):
            dirs = list(dirs)
            dirs.append(self.config_name)
            return (os.path.join(i, *dirs) for i in self.dirs if i)

        def read_arch(self, ret, arch):
            config = ConfigParser(self.schema)
            config.read(self.get_files(arch))

            featuresets = config['base', ].get('featuresets', [])
            flavours = config['base', ].get('flavours', [])

            for section in iter(config):
                if section[0] in featuresets:
                    real = (section[-1], arch, section[0])
                elif len(section) > 1:
                    real = (section[-1], arch, None) + section[:-1]
                else:
                    real = (section[-1], arch) + section[:-1]
                s = ret.get(real, {})
                s.update(config[section])
                ret[tuple(real)] = s

            for featureset in featuresets:
                self.read_arch_featureset(ret, arch, featureset)

            if flavours:
                base = ret['base', arch]
                featuresets.insert(0, 'none')
                base['featuresets'] = featuresets
                del base['flavours']
                ret['base', arch] = base
                ret['base', arch, 'none'] = {'flavours': flavours, 'implicit-flavour': True}

        def read_arch_featureset(self, ret, arch, featureset):
            config = ConfigParser(self.schema)
            config.read(self.get_files(arch, featureset))

            flavours = config['base', ].get('flavours', [])

            for section in iter(config):
                real = (section[-1], arch, featureset) + section[:-1]
                s = ret.get(real, {})
                s.update(config[section])
                ret[tuple(real)] = s

        def read(self, ret):
            config = ConfigParser(self.schema)
            config.read(self.get_files())

            arches = config['base', ]['arches']
            featuresets = config['base', ].get('featuresets', [])

            for section in iter(config):
                if section[0].startswith('featureset-'):
                    real = (section[-1], None, section[0][11:])
                else:
                    real = (section[-1],) + section[1:]
                ret[real] = config[section]

            for arch in arches:
                self.read_arch(ret, arch)
            for featureset in featuresets:
                self.read_featureset(ret, featureset)

        def read_featureset(self, ret, featureset):
            config = ConfigParser(self.schema)
            config.read(self.get_files('featureset-%s' % featureset))

            for section in iter(config):
                real = (section[-1], None, featureset)
                s = ret.get(real, {})
                s.update(config[section])
                ret[real] = s


class ConfigParser(object):
    __slots__ = '_config', 'schemas'

    def __init__(self, schemas):
        self.schemas = schemas

        self._config = config = RawConfigParser()

    def __getitem__(self, key):
        return self._convert()[key]

    def __iter__(self):
        return iter(self._convert())

    def __str__(self):
        return '<%s(%s)>' % (self.__class__.__name__, self._convert())

    def _convert(self):
        ret = {}
        for section in self._config.sections():
            data = {}
            for key, value in self._config.items(section):
                data[key] = value
            section_list = section.split('_')
            section_base = section_list[-1]
            if section_base in self.schemas:
                section_ret = tuple(section_list)
                data = self._convert_one(self.schemas[section_base], data)
            else:
                section_ret = (section, )
            ret[section_ret] = data
        return ret

    def _convert_one(self, schema, data):
        ret = {}
        for key, value in data.items():
            if key in schema:
                value = schema[key](value)
            ret[key] = value
        return ret
 
    def keys(self):
        return self._convert().keys()

    def read(self, data):
        return self._config.read(data)


if __name__ == '__main__':
    import sys
    sys.path.append('debian/lib/python')
    config = ConfigCoreDump(open('debian/config.defines.dump', 'rb'))
    for section, items in sorted(config.items(), key=lambda a:tuple(i or '' for i in a[0])):
        print(u"[%s]" % (section,))
        for item, value in sorted(items.items()):
            print(u"%s: %s" % (item, value))
        print()
