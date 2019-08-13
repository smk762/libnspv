#!/bin/bash

#DIR=$(pwd)
./nspv ILN &>./testnspv.log &
sleep 10  \
  &&  /usr/bin/python3 -m pytest rpctest/test_nspv.py -s &>./pytest.log &
  tail -f ./pytest.log
