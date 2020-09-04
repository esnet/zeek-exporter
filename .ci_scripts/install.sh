#!/bin/bash

set -e

export PATH=/usr/local/zeek/bin:$PATH

cd $GITHUB_WORKSPACE

if scl -l; then
    echo "./configure && make && make install" | scl enable devtoolset-7 -
else
    ./configure
    make
    make install
fi
