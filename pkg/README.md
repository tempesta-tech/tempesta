## Packaging Tempesta

TempestaFW packaging is plain and simple. It is build as a binary Linux package.

### Structure
```text
├── debian
│   ├── changelog
│   ├── compat
│   ├── control
│   ├── copyright
│   ├── dirs
│   ├── rules
│   ├── tempesta-fw.service
```

- changelog - contains a log of changes made to the package in each version. 
It follows a specific format and is important for users to understand what 
has been added, changed, or fixed in each release. It is also used by package 
management tools to display version history.
- compat - specifies the debhelper compatibility level that should be used when 
building the package. It indicates which features of debhelper are available 
for use in the rules file.
- control - contains essential metadata about the package, such as its name, 
version, architecture, description, maintainer information and dependencies. 
Must contain the necessary kernel patch in dependencies. 
For example: `linux-headers-5.10.35.tfw-669c591, linux-image-5.10.35.tfw-669c591`.
- copyright - provides information about the licensing of the package and its components.
- dirs - lists of directories that need to be created during the installation process. 
- rules - is a makefile that defines how the package is built and installed. 
It contains instructions on how to install files and other tasks necessary to 
create a Debian package.
- tempesta-fw.service - defines a systemd service unit for TempestaFW. It specifies
 virtual variables in the system.
