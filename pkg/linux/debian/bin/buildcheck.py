#!/usr/bin/python3

import sys
sys.path.append('debian/lib/python')

import fnmatch
import glob
import stat

from debian_linux.abi import Symbols
from debian_linux.config import ConfigCoreDump
from debian_linux.debian import *


class CheckAbi(object):
    class SymbolInfo(object):
        def __init__(self, symbol, symbol_ref=None):
            self.symbol = symbol
            self.symbol_ref = symbol_ref or symbol

        @property
        def module(self):
            return self.symbol.module

        @property
        def name(self):
            return self.symbol.name

        def write(self, out, ignored):
            info = []
            if ignored:
                info.append("ignored")
            for name in ('module', 'version', 'export'):
                data = getattr(self.symbol, name)
                data_ref = getattr(self.symbol_ref, name)
                if data != data_ref:
                    info.append("%s: %s -> %s" % (name, data_ref, data))
                else:
                    info.append("%s: %s" % (name, data))
            out.write("%-48s %s\n" % (self.symbol.name, ", ".join(info)))

    def __init__(self, config, dir, arch, featureset, flavour):
        self.config = config
        self.arch, self.featureset, self.flavour = arch, featureset, flavour

        self.filename_new = "%s/Module.symvers" % dir

        try:
            version_abi = (self.config['version',]['abiname_base'] + '-' +
                           self.config['abi', arch]['abiname'])
        except KeyError:
            version_abi = self.config['version',]['abiname']
        self.filename_ref = "debian/abi/%s/%s_%s_%s" % (version_abi, arch, featureset, flavour)

    def __call__(self, out):
        ret = 0

        new = Symbols(open(self.filename_new))
        try:
            ref = Symbols(open(self.filename_ref))
        except IOError:
            out.write("Can't read ABI reference.  ABI not checked!  Continuing.\n")
            return 0

        symbols, add, change, remove = self._cmp(ref, new)

        ignore = self._ignore(symbols)

        add_effective = add - ignore
        change_effective = change - ignore
        remove_effective = remove - ignore

        if change_effective or remove_effective:
            out.write("ABI has changed!  Refusing to continue.\n")
            ret = 1
        elif change or remove:
            out.write("ABI has changed but all changes have been ignored.  Continuing.\n")
        elif add_effective:
            out.write("New symbols have been added.  Continuing.\n")
        elif add:
            out.write("New symbols have been added but have been ignored.  Continuing.\n")
        else:
            out.write("No ABI changes.\n")

        if add:
            out.write("\nAdded symbols:\n")
            for name in sorted(add):
                symbols[name].write(out, name in ignore)

        if change:
            out.write("\nChanged symbols:\n")
            for name in sorted(change):
                symbols[name].write(out, name in ignore)

        if remove:
            out.write("\nRemoved symbols:\n")
            for name in sorted(remove):
                symbols[name].write(out, name in ignore)

        return ret

    def _cmp(self, ref, new):
        ref_names = set(ref.keys())
        new_names = set(new.keys())

        add = set()
        change = set()
        remove = set()

        symbols = {}

        for name in new_names - ref_names:
            add.add(name)
            symbols[name] = self.SymbolInfo(new[name])

        for name in ref_names.intersection(new_names):
            s_ref = ref[name]
            s_new = new[name]

            if s_ref != s_new:
                change.add(name)
                symbols[name] = self.SymbolInfo(s_new, s_ref)

        for name in ref_names - new_names:
            remove.add(name)
            symbols[name] = self.SymbolInfo(ref[name])

        return symbols, add, change, remove

    def _ignore_pattern(self, pattern):
        ret = []
        for i in re.split(r'(\*\*?)', pattern):
            if i == '*':
                ret.append(r'[^!]+')
            elif i == '**':
                ret.append(r'.+')
            elif i:
                ret.append(re.escape(i))
        return re.compile('^' + ''.join(ret) + '$')

    def _ignore(self, symbols):
        # TODO: let config merge this lists
        configs = []
        configs.append(self.config.get(('abi', self.arch, self.featureset, self.flavour), {}))
        configs.append(self.config.get(('abi', self.arch, None, self.flavour), {}))
        configs.append(self.config.get(('abi', self.arch, self.featureset), {}))
        configs.append(self.config.get(('abi', self.arch), {}))
        configs.append(self.config.get(('abi', None, self.featureset), {}))
        configs.append(self.config.get(('abi',), {}))

        ignores = set()
        for config in configs:
            ignores.update(config.get('ignore-changes', []))

        filtered = set()
        for ignore in ignores:
            type = 'name'
            if ':' in ignore:
                type, ignore = ignore.split(':')
            if type in ('name', 'module'):
                p = self._ignore_pattern(ignore)
                for symbol in symbols.values():
                    if p.match(getattr(symbol, type)):
                        filtered.add(symbol.name)
            else:
                raise NotImplementedError

        return filtered


class CheckImage(object):
    def __init__(self, config, dir, arch, featureset, flavour):
        self.dir = dir
        self.arch, self.featureset, self.flavour = arch, featureset, flavour

        self.changelog = Changelog(version=VersionLinux)[0]

        self.config_entry_base = config.merge('base', arch, featureset, flavour)
        self.config_entry_build = config.merge('build', arch, featureset, flavour)
        self.config_entry_image = config.merge('image', arch, featureset, flavour)

    def __call__(self, out):
        image = self.config_entry_build.get('image-file')

        if not image:
            # TODO: Bail out
            return 0

        image = os.path.join(self.dir, image)

        fail = 0

        fail |= self.check_size(out, image)

        return fail

    def check_size(self, out, image):
        value = self.config_entry_image.get('check-size')

        if not value:
            return 0

        dtb_size = 0
        if self.config_entry_image.get('check-size-with-dtb'):
            for dtb in glob.glob(
                    os.path.join(self.dir, 'arch',
                                 self.config_entry_base['kernel-arch'],
                                 'boot/dts/*.dtb')):
                dtb_size = max(dtb_size, os.stat(dtb).st_size)

        size = os.stat(image).st_size + dtb_size

        if size > value:
            out.write('Image too large (%d > %d)!  Refusing to continue.\n' % (size, value))
            return 1

        # 1% overhead is desirable in order to cope with growth
        # through the lifetime of a stable release. Warn if this is
        # not the case.
        usage = (float(size)/value) * 100.0
        out.write('Image size %d/%d, using %.2f%%.  ' % (size, value, usage))
        if size > value:
            out.write('Too large.  Refusing to continue.\n')
            return 1
        elif usage >= 99.0:
            out.write('Under 1%% space in %s.  ' % self.changelog.distribution)
        else:
            out.write('Image fits.  ')
        out.write('Continuing.\n')

        return 0


class Main(object):
    def __init__(self, dir, arch, featureset, flavour):
        self.args = dir, arch, featureset, flavour

        self.config = ConfigCoreDump(open("debian/config.defines.dump", "rb"))

    def __call__(self):
        fail = 0

        for c in CheckAbi, CheckImage:
            fail |= c(self.config, *self.args)(sys.stdout)

        return fail


if __name__ == '__main__':
    sys.exit(Main(*sys.argv[1:])())
