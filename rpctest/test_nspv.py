#!/usr/bin/env python3
import time
import test_framework.nspvlib as tf


def wait():
    pass


def main():
    url = "http://127.0.0.1:7771"
    userpass = "userpass"

    # help call
    # Response should contain "result": "success"
    # Response should contain actual help data
    rpc_call = tf.nspv_help(url, userpass)
    tf.assert_success(rpc_call)
    tf.assert_contains(rpc_call, "methods")
    wait()

    # getinfo call
    # Response should contain "result": "success"
    # Response should contain actual data
    rpc_call = tf.nspv_getinfo(url, userpass)
    tf.assert_success(rpc_call)
    tf.assert_contains(rpc_call, "notarization")
    tf.assert_contains(rpc_call, "header")
    #tf.assert_contains(rpc_call, "protocolversion")
    wait()

    # getpeerinfo call     -- needs it's own assertion and expected results WIP
    #rpc_call = tf.nspv_getpeerinfo(url, userpass)
    #tf.assert_success(rpc_call)
    #wait()

    # hdrsproof call
    # Response should be successful for case 2 and fail for others
    # Response should contain actual headers
    prevheight = [False, 1457769, 'notnum']
    nextheight = [False, 1457791, 'notnum']
    rpc_call = tf.nspv_hdrsproof(url, userpass, prevheight[0], nextheight[0])
    tf.assert_error(rpc_call)
    rpc_call = tf.nspv_hdrsproof(url, userpass, prevheight[1], nextheight[1])
    tf.assert_success(rpc_call)
    tf.assert_contains(rpc_call, "prevht")
    tf.assert_contains(rpc_call, "nextht")
    tf.assert_contains(rpc_call, "headers")
    rpc_call = tf.nspv_hdrsproof(url, userpass, prevheight[2], nextheight[2])
    tf.assert_error(rpc_call)
    wait()

    # notarization call
    # Response should be successful for case 2
    # Successful response should contain prev and next notarizations data
    height = [False, 1457780, 'notnum']
    rpc_call = tf.nspv_notarizations(url, userpass, height[0])
    tf.assert_error(rpc_call)
    rpc_call = tf.nspv_notarizations(url, userpass, height[1])
    tf.assert_success(rpc_call)
    tf.assert_contains(rpc_call, "prev")
    tf.assert_contains(rpc_call, "next")
    rpc_call = tf.nspv_notarizations(url, userpass, height[2])
    tf.assert_error(rpc_call)
    wait()

    # mempool call
    # Response should contain txids
    rpc_call = tf.nspv_mempool(url, userpass)
    tf.assert_success(rpc_call)
    tf.assert_contains(rpc_call, "txids")

    # getnewaddress call
    # Get a new address, save it for latter calls
    rpc_call = tf.nspv_getnewaddress(url, userpass)
    tf.assert_contains(rpc_call, "wifprefix")
    tf.assert_contains(rpc_call, "wif")
    tf.assert_contains(rpc_call, "address")
    tf.assert_contains(rpc_call, "pubkey")
    rep = tf.type_convert(rpc_call)
    wif = rep.get('wif')
    addr = rep.get('address')
    pkey = rep.get('pubkey')
    wait()

    # login call
    # login with fresh credentials
    # Response should contain address, address should be equal to generated earlier one
    rpc_call = tf.nspv_login(url, userpass, wif)
    tf.assert_success(rpc_call)
    tf.assert_contains(rpc_call, "status")
    tf.assert_contains(rpc_call, "address")
    rep = tf.type_convert(rpc_call)
    address = rep.get('address')
    if address != addr:
        raise Exception("addr missmatch: ", addr, address)
    wait()

    # TODO: different cases for logged in and logged out users

    # listtransactions call
    # Successful response should contain txids and same address ass requested
    address = [False, 'RSjpS8bYqQh395cTaWpjDXq5ZuAM6Kdxmj', addr]
    isCCno = [False, 0, 0]
    isCCyes = [False, 1, 1]
    skipcount = [False, 1, 2]
    # Case 1 - False data, still logged in - should not print txids
    rpc_call = tf.nspv_listtransactions(url, userpass, address[0], isCCno[0], skipcount[0])
    tf.assert_success(rpc_call)
    tf.assert_not_contains(rpc_call, "txids")
    rep = tf.type_convert(rpc_call)
    addr_response = rep.get('address')
    if addr_response != address[2]:
        raise Exception("addr missmatch: ", addr_response, address[1])
    rpc_call = tf.nspv_listtransactions(url, userpass, address[0], isCCyes[0], skipcount[0])
    tf.assert_success(rpc_call)
    tf.assert_not_contains(rpc_call, "txids")
    rep = tf.type_convert(rpc_call)
    addr_response = rep.get('address')
    if addr_response != address[2]:
        raise Exception("addr missmatch: ", addr_response, address[1])
    # Case 2 - known data
    rpc_call = tf.nspv_listtransactions(url, userpass, address[1], isCCno[1], skipcount[1])
    tf.assert_success(rpc_call)
    tf.assert_contains(rpc_call, "txids")
    rep = tf.type_convert(rpc_call)
    addr_response = rep.get('address')
    if addr_response != address[1]:
        raise Exception("addr missmatch: ", addr_response, address[1])
    # TODO: Remove extra isCCyes checks
    rpc_call = tf.nspv_listtransactions(url, userpass, address[1], isCCyes[1], skipcount[1])
    tf.assert_success(rpc_call)
    tf.assert_contains(rpc_call, "txids")
    rep = tf.type_convert(rpc_call)
    addr_response = rep.get('address')
    if addr_response != address[1]:
        raise Exception("addr missmatch: ", addr_response, address[1])
    # Case 3 - fresh generated data
    rpc_call = tf.nspv_listtransactions(url, userpass, address[2], isCCno[2], skipcount[2])
    tf.assert_success(rpc_call)
    tf.assert_contains(rpc_call, "txids")
    rep = tf.type_convert(rpc_call)
    addr_response = rep.get('address')
    if addr_response != address[2]:
        raise Exception("addr missmatch: ", addr_response, address[2])
    rpc_call = tf.nspv_listtransactions(url, userpass, address[2], isCCyes[2], skipcount[2])
    tf.assert_success(rpc_call)
    tf.assert_contains(rpc_call, "txids")
    rep = tf.type_convert(rpc_call)
    addr_response = rep.get('address')
    if addr_response != address[1]:
        raise Exception("addr missmatch: ", addr_response, address[2])
    wait()

    # litunspent call
    # Successful response should contain utxos and same address as requested
    address = [False, 'RSjpS8bYqQh395cTaWpjDXq5ZuAM6Kdxmj', addr]
    isCCno = [False, 0, 0]
    isCCyes = [False, 1, 1]
    skipcount = [False, 2, 2]
    # Case 1 - False data
    rpc_call = tf.nspv_listunspent(url, userpass, address[0], isCCno[0], skipcount[0])
    tf.assert_error(rpc_call)
    rpc_call = tf.nspv_listunspent(url, userpass, address[0], isCCyes[0], skipcount[0])
    tf.assert_error(rpc_call)
    # Case 2 - known data
    rpc_call = tf.nspv_listunspent(url, userpass, address[1], isCCno[1], skipcount[1])
    tf.assert_success(rpc_call)
    tf.assert_contains(rpc_call, "utxos")
    rep = tf.type_convert(rpc_call)
    addr_response = rep.get('address')
    if addr_response != address[1]:
        raise Exception("addr missmatch: ", addr_response, address[1])
    rpc_call = tf.nspv_listunspent(url, userpass, address[1], isCCyes[1], skipcount[1])
    tf.assert_success(rpc_call)
    tf.assert_contains(rpc_call, "utxos")
    rep = tf.type_convert(rpc_call)
    addr_response = rep.get('address')
    if addr_response != address[1]:
        raise Exception("addr missmatch: ", addr_response, address[1])
    # Case 3 - fresh generated data
    rpc_call = tf.nspv_listunspent(url, userpass, address[2], isCCno[2], skipcount[2])
    tf.assert_success(rpc_call)
    tf.assert_contains(rpc_call, "utxos")
    rep = tf.type_convert(rpc_call)
    addr_response = rep.get('address')
    if addr_response != address[2]:
        raise Exception("addr missmatch: ", addr_response, address[2])
    rpc_call = tf.nspv_listunspent(url, userpass, address[2], isCCyes[2], skipcount[2])
    tf.assert_success(rpc_call)
    tf.assert_contains(rpc_call, "utxos")
    rep = tf.type_convert(rpc_call)
    addr_response = rep.get('address')
    if addr_response != address[1]:
        raise Exception("addr missmatch: ", addr_response, address[2])
    wait()

    # spend call
    # Successful response should contain tx and transaction hex
    amount = [False, 0.001]
    address = [False, 'RSjpS8bYqQh395cTaWpjDXq5ZuAM6Kdxmj']
    # Case 1 - false data
    rpc_call = tf.nspv_spend(url, userpass, address[0], amount[0])
    tf.assert_error(rpc_call)
    rpc_call = tf.nspv_spend(url, userpass, address[1], amount[0])
    tf.assert_error(rpc_call)
    # Case 2 - known data
    rpc_call = tf.nspv_spend(url, userpass, address[1], amount[1])
    tf.assert_success(rpc_call)
    tf.assert_contains(rpc_call, "tx")
    tf.assert_contains(rpc_call, "hex")
    # save hex for future broadcast
    rep = tf.type_convert(rpc_call)
    hex_res = rep.get("hex")
    wait()

    # broadcast call
    # Successful broadcasst should have equal hex broadcasted and expected
    hex = [False, hex_res]
    rpc_call = tf.nspv_broadcast(url, userpass, hex[0])
    tf.assert_error(rpc_call)
    rpc_call = tf.nspv_broadcast(url, userpass, hex[1])
    tf.assert_success(rpc_call)
    rep = tf.type_convert(rpc_call)
    broadcast_res = rep.get("broadcast")
    expected = rep.get("expected")
    if broadcast_res == expected:
        pass
    else:
        raise Exception("Unxepected braodcast: ", broadcast_res, expected)
    wait()

    # spentinfo call
    # Successful response sould contain same txid and same vout
    r_txids = [False, "224c0b2bd80983f44a638d6ae14aab39acc898771ebe5101dd567b13cd5fff78"]
    r_vouts = [False, 1]
    rpc_call = tf.nspv_spentinfo(url, userpass, r_txids[0], r_vouts[0])
    tf.assert_error(rpc_call)
    rpc_call = tf.nspv_spentinfo(url, userpass, r_txids[1], r_vouts[1])
    tf.assert_success(rpc_call)
    rep = tf.type_convert(rpc_call)
    txid_resp = rep.get("txid")
    if r_txids[1] != txid_resp:
        raise Exception("Unexpected txid: ", r_txids[1], txid_resp)
    vout_resp = rep.get("vout")
    if r_vouts[1] != vout_resp:
        raise Exception("Unxepected vout: ", r_vouts[1], vout_resp)
    wait()

    # logout call
    rpc_call = tf.nspv_logout(url, userpass)
    tf.assert_success(rpc_call)


if __name__ == "__main__":
    main()
