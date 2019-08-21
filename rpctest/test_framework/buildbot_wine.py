#!/usr/bin/env python3
# Copyright (c) 2019 SuperNET developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import subprocess
import time
import json

"""
    steps:
    1. run nspv, wait 10 seconds to find good peers
    2. run tests, write log
    3. wait 4 seconds for tests to start and write log to stdout with tail
"""


def main():
    f = open("test_setup.txt", "r")
    test_setup = json.load(f)
    f.close()
    coin = test_setup.get("chain")
    if not coin:
        raise Exception("Invalid setup file")

    command1 = ["wine64 nspv.exe", coin]
    print("command: ", command1)
    command2 = ["/usr/bin/python3", "-m", "pytest", "./test_nspv.py", "-s"]

    nspv = subprocess.Popen(command1, shell=False, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    if nspv.poll():
        print("nspv not running")
    else:
        print("nspv is running")
    time.sleep(15)
    test = subprocess.Popen(command2, shell=False, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    while True:
        output = test.stdout.readline()
        if test.poll() is not None:
            break
        if output:
            print(output.strip().decode("utf-8"))
    rc = test.poll()
    if rc != 0:
        raise RuntimeError("tests return code: ", rc)


if __name__ == "__main__":
    main()
