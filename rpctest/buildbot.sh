#!/bin/bash
set -ev
trap "echo EXIT;  exit" 0
trap "echo HUP;   exit" 1
trap "echo CTL-C; exit" 2
trap "echo QUIT;  exit" 3
trap "echo ERR;   exit" ERR
# steps:
# 1. run nspv, wait 10 seconds to find good peers
# 2. run tests, write log
./nspv HUSH &>./testnspv.log &
sleep 10  \
&&  /usr/bin/python3 -m pytest rpctest/test_nspv.py -s | tee ./pytest.log
