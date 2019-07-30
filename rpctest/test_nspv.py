#!/usr/bin/env python3
import itertools
import time
import test_framework.nspvlib as tf

def main():
    url = "http://127.0.0.1:7771"
    userpass = "userpass"

    #  params list format [no value (false), good value, bad value]
    wif = [False, 'UrJUbSqsb1chYxmQvScdnNhVc2tEJEBDUPMcxCCtgoUYuvyvLKvB', 'thiswontwork']
    # height = [False, 777, 'notnum']
    address = [False, 'RYPzyuLXdT9JYn7pemYaX3ytsY3btyaATY', 'not_an_addr']
    isCCno = [False, 0, 'notnum']
    isCCyes = [False, 1, 'notnum']
    skipcount = [False, 2, 'notnum']
    txfilter = ['not implemented yet']
    amount = [False, 2, 'notnum']
    txid = [False, 'f261773a389445100d8dfe4fc0b2d9daeaf90ef6264435e739fbd698624b77d6', 'not_txid']
    vout = [False, 1,'d']
    rawhex = [False, '', 'nothex']

    #  methods-to-param dic
#    nspv_methods = {#'broadcast': [rawhex],
                    #'getnewaddress': [],                                       V
                    #'getpeerinfo': [],                                         V
                    #'hdrsproof': [prevheight,nextheight],                      V
                    #'help': [],                                                V
                    #'listtransactions1': [address, isCCno, skipcount],
                    #'listtransactions2': [address, isCCyes, skipcount],
                    #'listunspent1': [address, isCCno, skipcount],
                    #'listunspent2': [address, isCCyes, skipcount],
                    #'login': [wif], 'logout': [], 'mempool': [],
                    #'notarizations': [height],                                 V
                    #'spend': [address, amount],
                    #'spentinfo': [txid, vout],
                    #'txproof': [txid, height],
                    #'stop': []
#    }

    # help call
    # Response should contain "result": "success"
    # Response should contain actual help data
    rpc_call = tf.nspv_help(url, userpass)
    tf.assert_success(rpc_call)
    tf.assert_contains(rpc_call, "methods")

    # getinfo call
    # Response should contain "result": "success"
    # Response should contain actual data
    rpc_call = tf.nspv_getinfo(url, userpass)
    tf.assert_success(rpc_call)
    tf.assert_contains(rpc_call, "notarization")
    tf.assert_contains(rpc_call, "header")
    tf.assert_contains(rpc_call, "protocolversion")

    # getpeerinfo call     -- needs it's own assertion and expected results WIP
    #rpc_call = tf.nspv_getpeerinfo(url, userpass)
    #tf.assert_success(rpc_call)

    # hdrsproof call
    # Response should be successful for case 2 and fail for others
    # Response should contain actual headers
    prevheight = [False, 1457769, 'notnum']
    nextheight = [False, 1457791, 'notnum']
    rpc_call = tf.nspv_hdrsproof(url, userpass, prevheight[1], nextheight[1])
    tf.assert_error(rpc_call)
    rpc_call = tf.nspv_hdrsproof(url, userpass, prevheight[2], nextheight[2])
    tf.assert_success(rpc_call)
    tf.assert_contains(rpc_call, "prevht")
    tf.assert_contains(rpc_call, "nextht")
    tf.assert_contains(rpc_call, "headers")
    rpc_call = tf.nspv_hdrsproof(url, userpass, prevheight[3], nextheight[3])
    tf.assert_error(rpc_call)

    # notarization call
    # Response should be successful for case 2
    # Successful response should contain prev and next notarizations data
    height = [False, 1457780, 'notnum']
    rpc_call = tf.nspv_notarizations(url, userpass, height[1])
    tf.assert_error(rpc_call)
    rpc_call = tf.nspv_notarizations(url, userpass, height[2])
    tf.assert_success(rpc_call)
    tf.assert_contains(rpc_call, "prev", "next")
    rpc_call = tf.nspv_notarizations(url, userpass, height[3])
    tf.assert_error(rpc_call)

    # getnewaddress call
    # Get a new address, save it for latter calls
    rpc_call = tf.nspv_getnewaddress(url, userpass)
    tf.asert_success(rpc_call)
    tf.assert_contains(rpc_call, "wifprefix")
    tf.assert_contains(rpc_call, "wif")
    tf.assert_contains(rpc_call, "address")
    tf.assert_contains(rpc_call, "pubkey")
    rep = tf.type_convert(rpc_call)
    wif = rep.get['wif']
    addr = rep.get['address']
    pkey = rep.get['pubkey']

    # login call
    # login with fresh credentials
    # Response should contain address, address should be equal to generated earlier one
    rpc_call = tf.nspv_login(url, userpass, wif)
    tf.asert_success(rpc_call)
    tf.assert_contains(rpc_call, "status")
    tf.assert_contains(rpc_call, "address")
    rep = tf.type_convert(rpc_call)
    address = rep.get['address']
    if address != addr:
        raise Exception("addr missmatch: ", addr, address)

    # listtransactions call
    # Successful response should contain txids and same address ass requested
    address = [False, 'RSjpS8bYqQh395cTaWpjDXq5ZuAM6Kdxmj', addr]
    isCCno = [False, 0, 0]
    isCCyes = [False, 1, 1]
    skipcount = [False, 2, 2]
    # Case 1 - False data
    rpc_call = tf.nspv_listtransactions(url, userpass, address[1], isCCno[1], skipcount[1])
    tf.assert_error(rpc_call)
    rpc_call = tf.nspv_listtransactions(url, userpass, address[1], isCCyes[1], skipcount[1])
    tf.assert_error(rpc_call)
    # Case 2 - known data
    rpc_call = tf.nspv_listtransactions(url, userpass, address[2], isCCno[2], skipcount[2])
    tf.assert_success(rpc_call)
    tf.assert_contains(rpc_call, "txids")
    rep = tf.type_convert(rpc_call)
    addr_response = rep.get['address']
    if addr_response != address[2]:
        raise Exception("addr missmatch: ", addr_response, address[2])
    rpc_call = tf.nspv_listtransactions(url, userpass, address[2], isCCyes[2], skipcount[2])
    tf.assert_success(rpc_call)
    tf.assert_contains(rpc_call, "txids")
    rep = tf.type_convert(rpc_call)
    addr_response = rep.get['address']
    if addr_response != address[2]:
        raise Exception("addr missmatch: ", addr_response, address[2])
    # Case 3 - fresh generated data
    rpc_call = tf.nspv_listtransactions(url, userpass, address[3], isCCno[3], skipcount[3])
    tf.assert_success(rpc_call)
    tf.assert_contains(rpc_call, "txids")
    rep = tf.type_convert(rpc_call)
    addr_response = rep.get['address']
    if addr_response != address[3]:
        raise Exception("addr missmatch: ", addr_response, address[3])
    rpc_call = tf.nspv_listtransactions(url, userpass, address[3], isCCyes[3], skipcount[3])
    tf.assert_success(rpc_call)
    tf.assert_contains(rpc_call, "txids")
    rep = tf.type_convert(rpc_call)
    addr_response = rep.get['address']
    if addr_response != address[2]:
        raise Exception("addr missmatch: ", addr_response, address[3])

    # litunspent call
    # Successful response should contain utxos and same address as requested
    address = [False, 'RSjpS8bYqQh395cTaWpjDXq5ZuAM6Kdxmj', addr]
    isCCno = [False, 0, 0]
    isCCyes = [False, 1, 1]
    skipcount = [False, 2, 2]
    # Case 1 - False data
    rpc_call = tf.nspv_listunspent(url, userpass, address[1], isCCno[1], skipcount[1])
    tf.assert_error(rpc_call)
    rpc_call = tf.nspv_listunspent(url, userpass, address[1], isCCyes[1], skipcount[1])
    tf.assert_error(rpc_call)
    # Case 2 - known data
    rpc_call = tf.nspv_listunspent(url, userpass, address[2], isCCno[2], skipcount[2])
    tf.assert_success(rpc_call)
    tf.assert_contains(rpc_call, "utxos")
    rep = tf.type_convert(rpc_call)
    addr_response = rep.get['address']
    if addr_response != address[2]:
        raise Exception("addr missmatch: ", addr_response, address[2])
    rpc_call = tf.nspv_listunspent(url, userpass, address[2], isCCyes[2], skipcount[2])
    tf.assert_success(rpc_call)
    tf.assert_contains(rpc_call, "utxos")
    rep = tf.type_convert(rpc_call)
    addr_response = rep.get['address']
    if addr_response != address[2]:
        raise Exception("addr missmatch: ", addr_response, address[2])
    # Case 3 - fresh generated data
    rpc_call = tf.nspv_listunspent(url, userpass, address[3], isCCno[3], skipcount[3])
    tf.assert_success(rpc_call)
    tf.assert_contains(rpc_call, "utxos")
    rep = tf.type_convert(rpc_call)
    addr_response = rep.get['address']
    if addr_response != address[3]:
        raise Exception("addr missmatch: ", addr_response, address[3])
    rpc_call = tf.nspv_listunspent(url, userpass, address[3], isCCyes[3], skipcount[3])
    tf.assert_success(rpc_call)
    tf.assert_contains(rpc_call, "utxos")
    rep = tf.type_convert(rpc_call)
    addr_response = rep.get['address']
    if addr_response != address[2]:
        raise Exception("addr missmatch: ", addr_response, address[3])

    

if __name__ == "__main__":
    main()
