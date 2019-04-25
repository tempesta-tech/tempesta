## Packaging Tempesta

TempestaFW packaging is plain and simple. First of all it is build as DKMS
module rather than a binary Linux kernel module. This approach allows:

- Build single package for all supported CPUs. Since user will build the module
on the target server, build system will be aware of all supported x86
extensions, such as AVX2.

- Have a weak dependency between kernel image and the module. End user can
use the module with the custom kernel.


### Dependencies between Tempesta and Kernel

TempestaFW requires patched kernel, and it has minimum required version. Thus
variable `BUILD_EXCLUSIVE_KERNEL` in `pkg/debian/tempesta-fw-dkms.dkms` gives
regexp to match supported versions.

Every time a new module is added or removed in Tempesta sources, `BUILT_MODULE_*`
modules list must be udated.


### Workflow

To simplify the build, TempestaFW is built as native Debian module using
`git-buildpackage` tool set. The tool set does not honor builds from any
branches except `master` or builds with dirty index, so warning will appear
and build will fail. But the tool set does not track ignored files, so unneeded
files may appear in package. Clone the repo to a new directory or remove
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


### TODO

Add dependencies into `debian/control` to allow dependency tracking via package
manager.
