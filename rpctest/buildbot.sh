#!/bin/bash

#DIR=$(pwd)
# steps:
# 1. run nspv, wait 10 seconds to find good peers
# 2. run tests, write log
# 3. wait 4 seconds for tests to start and write log to stdout with tail
./nspv ILN &>./testnspv.log &
sleep 10  \
&&  /usr/bin/python3 -m pytest rpctest/test_nspv.py -s | tee ./pytest.log
