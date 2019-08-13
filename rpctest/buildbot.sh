#!/bin/bash

#DIR=$(pwd)
./nspv ILN &>./testnspv.log &
/usr/bin/python3 -m pytest rpctest/test_nspv.py
