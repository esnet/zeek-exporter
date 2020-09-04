#!/bin/bash

set -e

export PATH=/usr/local/zeek/bin:$PATH

cd $GITHUB_WORKSPACE/tests

if scl -l; then
    scl enable devtoolset-7 make
else
    make
fi
