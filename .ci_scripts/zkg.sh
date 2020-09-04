#!/bin/bash

set -e

export PATH=/usr/local/zeek/bin:$PATH

zkg install --force https://github.com${GITHUB_REPOSITORY}.git --version ${GITHUB_SHA}
