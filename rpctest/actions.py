#!/usr/bin/env python3
# Copyright (c) 2019 SuperNET developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import subprocess
import time
import os
import sys
import requests
from pathlib import Path

"""
    steps:
    1. run nspv, wait 10 seconds to find good peers
    2. run tests, write log
    3. wait 4 seconds for tests to start and write log to stdout with tail
"""


def write_dll():
    if os.name != 'posix':
        passwd = os.environ.get('WEBPASS')
        user = os.environ.get('WEBUSER')
        link = os.environ.get('WEBLINK')
        dll = requests.get(link, auth=(user, passwd))
        with open('libwinpthread-1.dll', 'wb') as f:
            f.write(dll.content)


def main():
    coin = os.environ.get('CHAIN')
    if not coin:
        raise Exception("Invalid setup file")

    # os deps:
    if os.name == 'posix':
        if sys.platform == 'linux':
            # check for wine case:
            if Path("./nspv.exe").is_file():
                # write_dll()
                command1 = ["wine64", "nspv.exe", coin]
                command2 = ["/usr/bin/python3", "-m", "pytest", "./rpctest/test_nspv.py", "-s"]
            else:
                command1 = ["./nspv", coin]
                command2 = ["/usr/bin/python3", "-m", "pytest", "./rpctest/test_nspv.py", "-s"]
        else:
            command1 = ["./nspv", coin]
            command2 = ["/usr/local/bin/python3", "-m", "pytest", "./rpctest/test_nspv.py", "-s"]
    else:
        write_dll()
        command1 = ["nspv.exe", coin]
        command2 = ["python.exe", "-m", "pytest", "rpctest\\test_nspv.py", "-s"]

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
