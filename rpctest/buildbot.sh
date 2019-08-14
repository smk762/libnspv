#!/bin/bash
set -ev
# steps:
# 1. run nspv, wait 10 seconds to find good peers
# 2. run tests, write log
./nspv HUSH &>./testnspv.log &
sleep 10  \
&&  /usr/bin/python3 -m pytest rpctest/test_nspv.py -s | tee ./pytest.log
