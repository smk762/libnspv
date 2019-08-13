#!/bin/bash
# A few commands to prepare libnspv build

set -ev

echo "Preparing libnspv build"
make clean
./autogen.sh
./configure
make
