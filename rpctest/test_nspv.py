#!/usr/bin/env python3
import itertools
import time
import test_framework.nspvlib as tf

def main():
    url = "http://127.0.0.1:7771"
    userpass = "userpass"

    #  params list format [no value (false), good value, bad value]
    wif = [False, 'UrJUbSqsb1chYxmQvScdnNhVc2tEJEBDUPMcxCCtgoUYuvyvLKvB', 'thiswontwork']
    height = [False, 777, 'notnum']
    prevheight = [False, 765, 'notnum']
    nextheight = [False, 785, 'notnum']
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
    rpc_call = tf.nspv.help(url, userpass)
    tf.assert_success(rpc_call)

    # getinfo call
    rpc_call = tf.nspv_getinfo(url, userpass)
    tf.assert_success(rpc_call)

    # getpeerinfo call
    rpc_call = tf.nspv_getpeerinfo(url, userpass)
    tf.assert_noterror(rpc_call)

    # hdrsproof call
    rpc_call = tf.nspv_hdrsproof(url, userpass, prevheight[1], nextheight[1])
    tf.assert_error(rpc_call)
    rpc_call = tf.nspv_hdrsproof(url, userpass, prevheight[2], nextheight[2])
    tf.assert_success(rpc_call)
    rpc_call = tf.nspv_hdrsproof(url, userpass, prevheight[3], nextheight[3])
    tf.assert_error(rpc_call)

    # notarization call
    rpc_call = tf.nspv_notarizations(url, userpass, height[1])
    tf.assert_error(rpc_call)
    rpc_call = tf.nspv_notarizations(url, userpass, height[2])
    tf.assert_success(rpc_call)
    rpc_call = tf.nspv_notarizations(url, userpass, height[3])
    tf.assert_error(rpc_call)

    # getnewaddress call
    rpc_call = tf.nspv_getnewaddress()
    tf.asert_success(rpc_call)
    rep = tf.type_convert(rpc_call)
    wif = rep.


if __name__ == "__main__":
    main()
