#!/usr/bin/env python3

import sys
sys.path.append("debian/lib/python")

import os
import os.path
import re
import shutil
import subprocess
import time

from debian_linux.debian import Changelog, VersionLinux
from debian_linux.patches import PatchSeries


class Main(object):
    def __init__(self, input_files, override_version):
        self.log = sys.stdout.write

        self.input_files = input_files

        changelog = Changelog(version=VersionLinux)[0]
        source = changelog.source
        version = changelog.version

        if override_version:
            version = VersionLinux('%s-0' % override_version)

        self.version_dfsg = version.linux_dfsg
        if self.version_dfsg is None:
            self.version_dfsg = '0'

        self.log('Using source name %s, version %s, dfsg %s\n' % (source, version.upstream, self.version_dfsg))

        self.orig = '%s-%s' % (source, version.upstream)
        self.orig_tar = '%s_%s.orig.tar.xz' % (source, version.upstream)
        self.tag = 'v' + version.linux_upstream_full

    def __call__(self):
        import tempfile
        self.dir = tempfile.mkdtemp(prefix='genorig', dir='debian')
        old_umask = os.umask(0o022)
        try:
            if os.path.isdir(self.input_files[0]):
                self.upstream_export(self.input_files[0])
            else:
                self.upstream_extract(self.input_files[0])
            if len(self.input_files) > 1:
                self.upstream_patch(self.input_files[1])

            # debian_patch() will change file mtimes.  Capture the
            # original release time so we can apply it to the final
            # tarball.  Note this doesn't work in case we apply an
            # upstream patch, as that doesn't carry a release time.
            orig_date = time.strftime(
                "%a, %d %b %Y %H:%M:%S +0000",
                time.gmtime(
                    os.stat(os.path.join(self.dir, self.orig, 'Makefile'))
                    .st_mtime))

            self.debian_patch()
            os.umask(old_umask)
            self.tar(orig_date)
        finally:
            os.umask(old_umask)
            shutil.rmtree(self.dir)

    def upstream_export(self, input_repo):
        self.log("Exporting %s from %s\n" % (self.tag, input_repo))

        archive_proc = subprocess.Popen(['git', 'archive', '--format=tar',
                                         '--prefix=%s/' % self.orig, self.tag],
                                        cwd=input_repo,
                                        stdout=subprocess.PIPE)
        extract_proc = subprocess.Popen(['tar', '-xaf', '-'], cwd=self.dir,
                                        stdin=archive_proc.stdout)

        ret1 = archive_proc.wait()
        ret2 = extract_proc.wait()
        if ret1 or ret2:
            raise RuntimeError("Can't create archive")

    def upstream_extract(self, input_tar):
        self.log("Extracting tarball %s\n" % input_tar)
        match = re.match(r'(^|.*/)(?P<dir>linux-\d+\.\d+(\.\d+)?(-\S+)?)\.tar(\.(?P<extension>(bz2|gz|xz)))?$', input_tar)
        if not match:
            raise RuntimeError("Can't identify name of tarball")

        cmdline = ['tar', '-xaf', input_tar, '-C', self.dir]

        if subprocess.Popen(cmdline).wait():
            raise RuntimeError("Can't extract tarball")

        os.rename(os.path.join(self.dir, match.group('dir')), os.path.join(self.dir, self.orig))

    def upstream_patch(self, input_patch):
        self.log("Patching source with %s\n" % input_patch)
        match = re.match(r'(^|.*/)patch-\d+\.\d+(\.\d+)?(-\S+?)?(\.(?P<extension>(bz2|gz|xz)))?$', input_patch)
        if not match:
            raise RuntimeError("Can't identify name of patch")
        cmdline = []
        if match.group('extension') == 'bz2':
            cmdline.append('bzcat')
        elif match.group('extension') == 'gz':
            cmdline.append('zcat')
        elif match.group('extension') == 'xz':
            cmdline.append('xzcat')
        else:
            cmdline.append('cat')
        cmdline.append(input_patch)
        cmdline.append('| (cd %s; patch -p1 -f -s -t --no-backup-if-mismatch)' % os.path.join(self.dir, self.orig))
        if os.spawnv(os.P_WAIT, '/bin/sh', ['sh', '-c', ' '.join(cmdline)]):
            raise RuntimeError("Can't patch source")

    def debian_patch(self):
        name = "orig"
        self.log("Patching source with debian patch (series %s)\n" % name)
        fp = open("debian/patches/series-" + name)
        series = PatchSeries(name, "debian/patches", fp)
        series(dir=os.path.join(self.dir, self.orig))

    def tar(self, orig_date):
        out = os.path.join("../orig", self.orig_tar)
        try:
            os.mkdir("../orig")
        except OSError:
            pass
        try:
            os.stat(out)
            raise RuntimeError("Destination already exists")
        except OSError:
            pass
        self.log("Generate tarball %s\n" % out)
        cmdline = '''(cd '%s' && find '%s' -print0) |
                     LC_ALL=C sort -z |
                     tar -C '%s' --no-recursion --null -T - --mtime '%s' --owner root --group root -caf '%s'
                  ''' % (self.dir, self.orig, self.dir, orig_date, out)
        try:
            if os.spawnv(os.P_WAIT, '/bin/sh', ['sh', '-c', cmdline]):
                raise RuntimeError("Can't patch source")
            os.chmod(out, 0o644)
        except:
            try:
                os.unlink(out)
            except OSError:
                pass
            raise
        try:
            os.symlink(os.path.join('orig', self.orig_tar), os.path.join('..', self.orig_tar))
        except OSError:
            pass

if __name__ == '__main__':
    from optparse import OptionParser
    parser = OptionParser(usage="%prog [OPTION]... {TAR [PATCH] | REPO}")
    parser.add_option("-V", "--override-version", dest="override_version", help="Override version", metavar="VERSION")
    options, args = parser.parse_args()

    assert 1 <= len(args) <= 2
    Main(args, options.override_version)()
