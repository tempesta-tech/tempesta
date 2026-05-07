## Description of the implementation

[The G-Core Linux regex module](https://github.com/G-Core/linux-regex-module) has been added to Tempesta FW as a loadable module.
When the Tempesta FW module reads the configuration file, each regular expression is written to a separate text file that also contains a unique regex identifier. This identifier is associated with the corresponding regular expression inside the Tempesta FW module.

After the Tempesta FW module has started, the external application `hscollider` compiles all generated text files containing regular expressions and saves the results in DB format. The resulting DB files are then placed into a special directory for `tempesta_regex` (`/sys/kernel/config/rex/`). This process may take a couple of seconds.

Before stopping the `tempesta_regex` module, all databases must be removed from the `/sys/kernel/config/rex/` directory.

## How to build userspace tools

### Dependencies

Build **Colm** (Colm Programming Language)

```
git clone ttps://github.com/adrian-thurston/colm.git
cd colm
./autogen.sh
./configure --prefix=/usr
make -j$(nproc)
sudo make install
```

Build **Ragel**

```
git clone https://github.com/adrian-thurston/ragel.git
cd ragel
./autogen.sh
./configure --with-colm=/usr --prefix=/usr/local
make -j$(nproc)
sudo make install
```

Build **PCRE**

```
git clone https://github.com/tempesta-tech/pcre
cd pcre
./configure  --enable-pcre16 --enable-pcre32 --enable-jit --disable-shared
make -j$(nproc)
sudo make install
```

### Hscollider

```
git clone https://github.com/tempesta-tech/linux-regex-module.git

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cd build
make
```
[List of Cmake build options for Hyperscan](http://intel.github.io/hyperscan/dev-reference/getting_started.html#cmake-configuration) After the build is complete, `hscollider` will be located in the `tools` directory.

### Debian package
The [Linux regex](https://github.com/tempesta-tech/linux-regex-module/) repository contains instructions for building a Debian package for `hscollider`.
