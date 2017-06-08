#!/usr/bin/env python3

import sys
sys.path.append(sys.path[0] + "/../lib/python")

import optparse
import os
import shutil
import tempfile

try:
    from urllib.request import urlopen
    from urllib.error import HTTPError
except ImportError:
    from urllib2 import urlopen, HTTPError

from debian_linux.abi import Symbols
from debian_linux.config import *
from debian_linux.debian import *

default_url_base = "http://ftp.de.debian.org/debian/"
default_url_base_incoming = "http://incoming.debian.org/"
default_url_base_ports = "http://ftp.debian-ports.org/debian/"


class url_debian_flat(object):
    def __init__(self, base):
        self.base = base

    def __call__(self, source, filename, arch):
        return self.base + filename


class url_debian_pool(object):
    def __init__(self, base):
        self.base = base

    def __call__(self, source, filename, arch):
        return self.base + "pool/main/" + source[0] + "/" + source + "/" + filename


class url_debian_ports_pool(url_debian_pool):
    def __call__(self, source, filename, arch):
        if arch == 'all':
            return url_debian_pool.__call__(self, source, filename, arch)
        return self.base + "pool-" + arch + "/main/" + source[0] + "/" + source + "/" + filename


class Main(object):
    dir = None

    def __init__(self, url, url_config=None, arch=None, featureset=None, flavour=None):
        self.log = sys.stdout.write

        self.url = self.url_config = url
        if url_config is not None:
            self.url_config = url_config
        self.override_arch = arch
        self.override_featureset = featureset
        self.override_flavour = flavour

        changelog = Changelog(version=VersionLinux)
        while changelog[0].distribution == 'UNRELEASED':
            changelog.pop(0)
        changelog = changelog[0]

        self.source = changelog.source
        self.version = changelog.version.linux_version
        self.version_source = changelog.version.complete

        self.config = ConfigCoreDump(fp=open("debian/config.defines.dump", "rb"))

        self.version_abi = self.config['version', ]['abiname']

    def __call__(self):
        self.dir = tempfile.mkdtemp(prefix='abiupdate')
        try:
            self.log("Retrieve config\n")

            try:
                config = self.get_config()
            except HTTPError as e:
                self.log("Failed to retrieve %s: %s\n" % (e.filename, e))
                sys.exit(1)

            if self.override_arch:
                arches = [self.override_arch]
            else:
                arches = config[('base',)]['arches']
            for arch in arches:
                self.update_arch(config, arch)
        finally:
            shutil.rmtree(self.dir)

    def extract_package(self, filename, base):
        base_out = self.dir + "/" + base
        os.mkdir(base_out)
        os.system("dpkg-deb --extract %s %s" % (filename, base_out))
        return base_out

    def get_abi(self, arch, prefix):
        try:
            version_abi = (self.config['version',]['abiname_base'] + '-' +
                           self.config['abi', arch]['abiname'])
        except KeyError:
            version_abi = self.version_abi
        filename = "linux-headers-%s-%s_%s_%s.deb" % (version_abi, prefix, self.version_source, arch)
        f = self.retrieve_package(self.url, filename, arch)
        d = self.extract_package(f, "linux-headers-%s_%s" % (prefix, arch))
        f1 = d + "/usr/src/linux-headers-%s-%s/Module.symvers" % (version_abi, prefix)
        s = Symbols(open(f1))
        shutil.rmtree(d)
        return version_abi, s

    def get_config(self):
        filename = "linux-support-%s_%s_all.deb" % (self.version_abi, self.version_source)
        f = self.retrieve_package(self.url_config, filename, 'all')
        d = self.extract_package(f, "linux-support")
        c = d + "/usr/src/linux-support-" + self.version_abi + "/config.defines.dump"
        config = ConfigCoreDump(fp=open(c, "rb"))
        shutil.rmtree(d)
        return config

    def retrieve_package(self, url, filename, arch):
        u = url(self.source, filename, arch)
        filename_out = self.dir + "/" + filename

        f_in = urlopen(u)
        f_out = open(filename_out, 'wb')
        while 1:
            r = f_in.read()
            if not r:
                break
            f_out.write(r)
        return filename_out

    def save_abi(self, version_abi, symbols, arch, featureset, flavour):
        dir = "debian/abi/%s" % version_abi
        if not os.path.exists(dir):
            os.makedirs(dir)
        out = "%s/%s_%s_%s" % (dir, arch, featureset, flavour)
        symbols.write(open(out, 'w'))

    def update_arch(self, config, arch):
        if self.override_featureset:
            featuresets = [self.override_featureset]
        else:
            featuresets = config[('base', arch)]['featuresets']
        for featureset in featuresets:
            self.update_featureset(config, arch, featureset)

    def update_featureset(self, config, arch, featureset):
        config_base = config.merge('base', arch, featureset)

        if not config_base.get('enabled', True):
            return

        if self.override_flavour:
            flavours = [self.override_flavour]
        else:
            flavours = config_base['flavours']
        for flavour in flavours:
            self.update_flavour(config, arch, featureset, flavour)

    def update_flavour(self, config, arch, featureset, flavour):
        config_base = config.merge('base', arch, featureset, flavour)

        self.log("Updating ABI for arch %s, featureset %s, flavour %s: " % (arch, featureset, flavour))
        try:
            if featureset == 'none':
                localversion = flavour
            else:
                localversion = featureset + '-' + flavour

            version_abi, abi = self.get_abi(arch, localversion)
            self.save_abi(version_abi, abi, arch, featureset, flavour)
            self.log("Ok.\n")
        except HTTPError as e:
            self.log("Failed to retrieve %s: %s\n" % (e.filename, e))
        except Exception:
            self.log("FAILED!\n")
            import traceback
            traceback.print_exc(None, sys.stdout)

if __name__ == '__main__':
    options = optparse.OptionParser()
    options.add_option("-i", "--incoming", action="store_true", dest="incoming")
    options.add_option("--incoming-config", action="store_true", dest="incoming_config")
    options.add_option("--ports", action="store_true", dest="ports")
    options.add_option("-u", "--url-base", dest="url_base", default=default_url_base)
    options.add_option("--url-base-incoming", dest="url_base_incoming", default=default_url_base_incoming)
    options.add_option("--url-base-ports", dest="url_base_ports", default=default_url_base_ports)

    opts, args = options.parse_args()

    kw = {}
    if len(args) >= 1:
        kw['arch'] = args[0]
    if len(args) >= 2:
        kw['featureset'] = args[1]
    if len(args) >= 3:
        kw['flavour'] = args[2]

    url_base = url_debian_pool(opts.url_base)
    url_base_incoming = url_debian_flat(opts.url_base_incoming)
    url_base_ports = url_debian_ports_pool(opts.url_base_ports)
    if opts.incoming_config:
        url = url_config = url_base_incoming
    else:
        url_config = url_base
        if opts.incoming:
            url = url_base_incoming
        elif opts.ports:
            url = url_base_ports
        else:
            url = url_base

    Main(url, url_config, **kw)()
