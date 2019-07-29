#!/usr/bin/env python3
import itertools
from nspvlib import *

local_ip = "http://127.0.0.1:7771"
userpass = "userpass"


for method in nspv_methods:
  param_lists = []
  for param_list in nspv_methods[method]:
    param_lists.append(param_list)
  test_params = list(itertools.product(*param_lists))
  for x in test_params:
    csv_row = []
    print("nspv_"+method+str(x))
    if method == 'broadcast':
      resp = nspv_broadcast(local_ip, userpass, *x)
    elif method == 'getnewaddress':
      resp = nspv_getnewaddress(local_ip, userpass, *x)
    elif method == 'getpeerinfo':
      resp = nspv_getpeerinfo(local_ip, userpass, *x)
    elif method == 'hdrsproof':
      resp = nspv_hdrsproof(local_ip, userpass, *x)
    elif method == 'help':
      resp = nspv_help(local_ip, userpass, *x)
    elif method == 'listtransactions1':
      resp = nspv_listtransactions(local_ip, userpass, *x)
    elif method == 'listtransactions2':
      resp = nspv_listtransactions(local_ip, userpass, *x)
    elif method == 'listunspent1':
      resp = nspv_listunspent(local_ip, userpass, *x)
    elif method == 'listunspent2':
      resp = nspv_listunspent(local_ip, userpass, *x)
    elif method == 'login':
      resp = nspv_login(local_ip, userpass, *x)
    elif method == 'notarizations':
      resp = nspv_notarizations(local_ip, userpass, *x)
    elif method == 'spend':
      resp = nspv_spend(local_ip, userpass, *x)
    elif method == 'spentinfo':
      resp = nspv_spentinfo(local_ip, userpass, *x)
    elif method == 'stop':
      resp = nspv_stop(local_ip, userpass, *x)
    elif method == 'txproof':
      resp = nspv_txproof(local_ip, userpass, *x)
    try:
      result = resp.json()
    except:
      result = resp.text
      pass
    time.sleep(1)
    print(result)

