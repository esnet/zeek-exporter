#!/bin/bash

set -e

export PATH=/usr/local/zeek/bin:$PATH

cd $GITHUB_WORKSPACE

zkg install --force .
