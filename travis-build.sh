#!/bin/bash
# A few commands to prepare libnspv build

set -ev

echo "Preparing libnspv build"
FILE=./nspv
if test -f "$FILE"; then
    make clean
fi
cd src/tools/cryptoconditions
./autogen.sh
./configure
make
cd ../../..
./autogen.sh
./configure
make
