#!/usr/bin/env python3
import requests
import json
import ast
import time
import os.path
import sys
sys.path.append(os.path.join(os.path.dirname(__file__)))
from util import assert_equal


def assert_success(result):
    result_d = type_convert(result)
    assert_equal(result_d.get('result'), 'success')


def assert_in(result, key, compare_list):
    result_d = type_convert(result)
    content = result_d.get(key)
    if content in compare_list:
        pass
    else:
        raise AssertionError("Error:", content, "not in", compare_list)


def assert_contains(result, key):
    """assert key contains expected data"""
    result_d = type_convert(result)
    content = result_d.get(key)
    if content:
        pass
    else:
        raise AssertionError("Unexpected response, missing param: ", key)


def assert_not_contains(result, key):
    """assert key contains expected data"""
    result_d = type_convert(result)
    content = result_d.get(key)
    if not content:
        pass
    else:
        raise AssertionError("Unexpected response, missing param: ", key)


def assert_error(result):
    """ assert there is an error with known error message """
    error_msg = ['no height', 'invalid height range', 'invalid method', 'timeout', 'error', 'no hex',
                 'couldnt get addressutxos', 'invalid address or amount too small', 'not enough funds',
                 'invalid address or amount too small', 'invalid utxo']
    result_d = type_convert(result)
    error = result_d.get('error')
    if error:
        if error in error_msg:
            pass
        else:
            raise AssertionError("Unknown error message")
    else:
        raise AssertionError("Unexpected response")


def type_convert(bytez):
    """Wraps nspv_call response"""
    # r = json.loads(bytes.decode("utf-8"))
    r = ast.literal_eval(bytez.decode("utf-8"))
    time.sleep(1)
    return r


def nspv_broadcast(node_ip, user_pass, rawhex):
    params = {'userpass': user_pass,
              'method': 'broadcast'}
    if rawhex:
        params.update({'hex': rawhex})
    r = requests.post(node_ip, json=params)
    time.sleep(1)
    return r.content


def nspv_getinfo(node_ip, user_pass, height=False):
    params = {'userpass': user_pass,
              'method': 'getinfo'}
    if height:
        params.update({'height':height})
    r = requests.post(node_ip, json=params)
    time.sleep(1)
    return r.content


def nspv_getnewaddress(node_ip, user_pass):
    params = {'userpass': user_pass,
              'method': 'getnewaddress'}
    r = requests.post(node_ip, json=params)
    time.sleep(1)
    return r.content


def nspv_getpeerinfo(node_ip, user_pass):
    params = {'userpass': user_pass,
              'method': 'getpeerinfo'}
    r = requests.post(node_ip, json=params)
    time.sleep(1)
    return r.content


def nspv_hdrsproof(node_ip, user_pass, prevheight, nextheight):
    params = {'userpass': user_pass,
              'method': 'hdrsproof'}
    if prevheight:
        params.update({'prevheight':prevheight})
    if nextheight:
        params.update({'nextheight':nextheight})
    r = requests.post(node_ip, json=params)
    time.sleep(1)
    return r.content


def nspv_help(node_ip, user_pass):
    params = {'userpass': user_pass,
              'method': 'help'}
    r = requests.post(node_ip, json=params)
    time.sleep(1)
    return r.content


def nspv_listtransactions(node_ip, user_pass, address=False, isCC=False, skipcount=False, txfilter=False):
    params = {'userpass': user_pass,
              'method': 'listtransactions'}
    if address:
        params.update({'address': address})
    if isCC:
        params.update({'isCC': isCC})
    if skipcount:
        params.update({'skipcount': skipcount})
    if txfilter:
        params.update({'filter': txfilter})
    r = requests.post(node_ip, json=params)
    time.sleep(1)
    return r.content


def nspv_listunspent(node_ip, user_pass, address=False, isCC=False, skipcount=False, txfilter=False):
    params = {'userpass': user_pass,
              'method': 'listunspent'}
    if address:
        params.update({'address': address})
    if isCC:
        params.update({'isCC': isCC})
    if skipcount:
        params.update({'skipcount': skipcount})
    if txfilter:
        params.update({'filter': txfilter})
    r = requests.post(node_ip, json=params)
    time.sleep(1)
    return r.content


def nspv_login(node_ip, user_pass, wif=False):
    params = {'userpass': user_pass,
              'method': 'login'}
    if wif:
        params.update({'wif': wif})
    r = requests.post(node_ip, json=params)
    time.sleep(1)
    return r.content


def nspv_logout(node_ip, user_pass):
    params = {'userpass': user_pass,
              'method': 'logout'}
    r = requests.post(node_ip, json=params)
    time.sleep(1)
    return r.content


def nspv_mempool(node_ip, user_pass):
    params = {'userpass': user_pass,
              'method': 'mempool'}
    r = requests.post(node_ip, json=params)
    time.sleep(1)
    return r.content


def nspv_notarizations(node_ip, user_pass, height):
    params = {'userpass': user_pass,
              'method': 'notarizations'}
    if height:
        params.update({'height': height})
    r = requests.post(node_ip, json=params)
    time.sleep(1)
    return r.content


def nspv_spend(node_ip, user_pass, address, amount):
    params = {'userpass': user_pass,
              'method': 'spend'}
    if address:
        params.update({'address': address})
    if amount:
        params.update({'amount': amount})
    r = requests.post(node_ip, json=params)
    time.sleep(1)
    return r.content


def nspv_spentinfo(node_ip, user_pass, txid, vout):
    params = {'userpass': user_pass,
              'method': 'spentinfo'}
    if txid:
        params.update({'txid': txid})
    if vout:
        params.update({'vout': vout})
    r = requests.post(node_ip, json=params)
    time.sleep(1)
    return r.content


def nspv_stop(node_ip, user_pass):
    params = {'userpass': user_pass,
              'method': 'stop'}
    r = requests.post(node_ip, json=params)
    time.sleep(1)
    return r.content


def nspv_txproof(node_ip, user_pass, txid, height):
    params = {'userpass': user_pass,
              'method': 'txproof'}
    if txid:
        params.update({'txid': txid})
    if height:
        params.update({'height': height})
    r = requests.post(node_ip, json=params)
    time.sleep(1)
    return r.content
