#!/usr/bin/env python3
# Copyright (c) 2019 SuperNET developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from os import subprocess as sub
import daemon
import time

with daemon.DaemonContext():
    sub.run(["/usr/bin/nohup", "./nspv", "ILN"])
time.sleep(5)  # give nspv daemon 5 sec to connect nodes
