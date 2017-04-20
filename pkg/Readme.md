# Packaging for Debian

## Prerequisites

All the necessary packages can be installed with two commands:
```sh
apt-get install git-buildpackage
apt-get build-dep linux
```
Note, least command require `/etc/apt/sources.list` to have entry:
```
deb-src http://ftp.debian.org/debian stretch main
```

Variables `DEBEMAIL` and `DEBFULLNAME` must be exported before updating
change logs. E.g.:
```sh
export DEBEMAIL="info@tempesta-tech.com"
export DEBFULLNAME="Tempesta Technologies, Inc."
```

# Publishing on Github

Every time package is build and published, commit used to build package **must**
be marked with tag formatted as:
```
[debian|centos|ubuntu|...]/[version]-[revision]

e.g:
debian/0.5.0-1
debian/0.5.0-pre7
centos/0.5.0-1
```

Once tag is pushed to Github, new release can be assigned to the tag. That
allows to publish packages and changelog in one place. Normally changelog
on Releases page should follow packets changelog.


## Packaging Tempesta

TempestaFW packaging is plain and simple. First of all it is build as DKMS
module rather than a binary Linux kernel module. This approach allows:

- Build single package for all supported CPUs. Since user will build the module
on the target server, build system will be aware of all supported x86
extensions, such as AVX2.

- Have a weak dependency between kernel image and the module. End user can
use the module with the custom kernel.

### Workflow

To simplify the build, TempestaFW is built as native Debian module using
`git-buildpackage` tool set. The tool set does not honor builds from any
branches except `master` or builds with dirty index, so warning will appear
and build will fail. But the tool set does not track ignored files, so unneeded
files may appear in package. Clone the the repo to a new directory or remove
untracked files with:
```sh
git clean -fd
```

Packaging require to hame `debian` directory in repo root, create symlink:
```sh
ln -s pkg/tempesta/debian debian
```

Update packet changelog with `dch` command. See manpages for more info.
Although `git-buildpackage` has a pretty `gbp dch` tool, which can update
changelog using git history, it is not suitable in our case, git history doesn't
hold information valuable for end user.

Finally, build the package using command:
```sh
gbp buildpackage --git-tag -us -uc
```
`--git-tag` option will add git tag, formatted as `debian/0.1-2`, where `0.1-2`
- debian version, stated in the log. Push the tag to upstream to indicate
exact commit used for packaging.

`-us -uc` options are similar to `dpkg-buildpackage`. If stated, source package
and `.changes` files will remain unsigned.


## Packaging Linux

Sadly, packaging Linux kernel is not so simple. It is packaged as foreign
package, so packaging directory contains a number of patches from Debian team.
Packaging system was forked from `git://anonscm.debian.org/kernel/linux.git`.

Copy `pkg/linux/debian` to separate empty directory. At least 25GB of free space
must be available.

Prepare _orig_ tarball - tarball that contains mostly unpached sources of
original package. Unpack it to package directory and apply patches from
`debian/pacthes/`.  This can be done in one of the following ways:

- `uscan`. This command prepares origin tarball automatically, if original git
repo have tag with newer version than stated in  `debian/changelog`. Refer
to `debian/watch` for more info.

- `debian/rules get-orig-source && debian/rules orig` to make the same for the
current version.

Generate control file:
```sh
debian/rules debian/control
```

Finally create the set of the packages:
```sh
dpkg-buildpackage -uc -us -jN
```
Where `N` - number of concurrent jobs.

That will take a while. For more info refer to
[Rebuilding official Debian kernel packages](https://kernel-handbook.alioth.debian.org/ch-common-tasks.html#s-common-official)
manual.


# TODOs

1. Instead of publishing packages on Github Releases page, distribute software
to end users using custom Debian/Centos/other repositories.

2. When packaging _linux_, use vanilla sources and apply Tempesta-Tech patches
in the same way Debian/Centos maintainers applies their own patches.

