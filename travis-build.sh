#!/bin/bash

set -ev

echo "Preparing libnspv build"
./autogen.sh
./configure
