#!/bin/bash

INST_DIR="/tmp/Hyperscan"
mkdir $INST_DIR
cd $INST_DIR

git clone https://github.com/adrian-thurston/colm.git
cd colm
./autogen.sh
./configure
make -j$(nproc)
make install

cd $INST_DIR

if [[ $LD_LIBRARY_PATH =~ "/usr/local/lib" ]]; then
    echo "Path already set."
else
    export LD_LIBRARY_PATH="/usr/local/lib"
    TTT="$(cat /etc/environment | grep LD_LIBRARY_PATH)"
    if [[ ! $TTT =~ "/usr/local/lib" ]]; then
        echo "LD_LIBRARY_PATH=\"/usr/local/lib\"" >> /etc/environment
    fi
    
fi


git clone https://github.com/adrian-thurston/ragel.git
cd ragel
./autogen.sh
./configure --with-colm=/usr/local
make -j$(nproc)
make install

cd $INST_DIR

wget https://sourceforge.net/projects/pcre/files/pcre/8.45/pcre-8.45.tar.gz
tar -xf pcre-8.45.tar.gz

cd pcre-8.45
./configure  --enable-pcre16 --enable-pcre32
make -j$(nproc)
make install

cd $INST_DIR

git clone https://github.com/tempesta-tech/linux-regex-module.git
cd linux-regex-module
git checkout ag_changes_for_easy_installation

cmake -DCMAKE_BUILD_TYPE=Release ./
make -j$(nproc)
make install

cd $INST_DIR

