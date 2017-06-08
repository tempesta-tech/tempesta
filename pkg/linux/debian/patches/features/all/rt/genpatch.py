#!/usr/bin/python3

import errno, os, os.path, re, shutil, subprocess, sys, tempfile

def main(source, version=None):
    patch_dir = 'debian/patches'
    rt_patch_dir = 'features/all/rt'
    series_name = 'series-rt'
    old_series = set()
    new_series = set()

    try:
        with open(os.path.join(patch_dir, series_name), 'r') as series_fh:
            for line in series_fh:
                name = line.strip()
                if name != '' and name[0] != '#':
                    old_series.add(name)
    except IOError as e:
        if e.errno != errno.ENOENT:
            raise

    with open(os.path.join(patch_dir, series_name), 'w') as series_fh:
        # Add directory prefix to all filenames.
        # Add Origin to all patch headers.
        def add_patch(name, source_patch, origin):
            name = os.path.join(rt_patch_dir, name)
            path = os.path.join(patch_dir, name)
            try:
                os.unlink(path)
            except OSError as e:
                if e.errno != errno.ENOENT:
                    raise
            with open(path, 'w') as patch:
                in_header = True
                for line in source_patch:
                    if in_header and re.match(r'^(\n|[^\w\s]|Index:)', line):
                        patch.write('Origin: %s\n' % origin)
                        if line != '\n':
                            patch.write('\n')
                        in_header = False
                    patch.write(line)
            series_fh.write(name)
            series_fh.write('\n')
            new_series.add(name)

        if os.path.isdir(os.path.join(source, '.git')):
            # Export rebased branch from stable-rt git as patch series
            up_ver = re.sub(r'-rt\d+$', '', version)
            args = ['git', 'format-patch', 'v%s..v%s-rebase' % (up_ver, version)]
            env = os.environ.copy()
            env['GIT_DIR'] = os.path.join(source, '.git')
            child = subprocess.Popen(args,
                                     cwd=os.path.join(patch_dir, rt_patch_dir),
                                     env=env, stdout=subprocess.PIPE)
            with child.stdout as pipe:
                for line in pipe:
                    name = line.strip('\n')
                    with open(os.path.join(patch_dir, rt_patch_dir, name)) as \
                            source_patch:
                        patch_from = source_patch.readline()
                        match = re.match(r'From ([0-9a-f]{40}) ', patch_from)
                        assert match
                        origin = 'https://git.kernel.org/cgit/linux/kernel/git/rt/linux-stable-rt.git/commit?id=%s' % match.group(1)
                        add_patch(name, source_patch, origin)
        else:
            # Get version and upstream version
            if version is None:
                match = re.search(r'(?:^|/)patches-(.+)\.tar\.[gx]z$', source)
                assert match, 'no version specified or found in filename'
                version = match.group(1)
            match = re.match(r'^(\d+\.\d+)(?:\.\d+|-rc\d+)?-rt\d+$', version)
            assert match, 'could not parse version string'
            up_ver = match.group(1)

            temp_dir = tempfile.mkdtemp(prefix='rt-genpatch', dir='debian')
            try:
                # Unpack tarball
                subprocess.check_call(['tar', '-C', temp_dir, '-xaf', source])
                source_dir = os.path.join(temp_dir, 'patches')
                assert os.path.isdir(source_dir), 'tarball does not contain patches directory'

                # Copy patch series
                origin = 'https://www.kernel.org/pub/linux/kernel/projects/rt/%s/older/patches-%s.tar.xz' % (up_ver, version)
                with open(os.path.join(source_dir, 'series'), 'r') as \
                        source_series_fh:
                    for line in source_series_fh:
                        name = line.strip()
                        if name != '' and name[0] != '#':
                            with open(os.path.join(source_dir, name)) as source_patch:
                                add_patch(name, source_patch, origin)
                        else:
                            # Leave comments and empty lines unchanged
                            series_fh.write(line)
            finally:
                shutil.rmtree(temp_dir)

    for name in new_series:
        if name in old_series:
            old_series.remove(name)
        else:
            print('Added patch', os.path.join(patch_dir, name))

    for name in old_series:
        print('Obsoleted patch', os.path.join(patch_dir, name))

if __name__ == '__main__':
    if not (1 <= len(sys.argv) <= 2):
        print('Usage: %s {TAR [RT-VERSION] | REPO RT-VERSION}' % sys.argv[0], file=sys.stderr)
        print('TAR is a tarball of patches.', file=sys.stderr)
        print('REPO is a git repo containing the given RT-VERSION.', file=sys.stderr)
        sys.exit(2)
    main(*sys.argv[1:])
