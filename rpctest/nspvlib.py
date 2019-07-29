#!/usr/bin/env python3
import requests
import json

# params list format [no value (false), good value, bad value]
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


nspv_methods = {'broadcast':[rawhex],
                'getnewaddress':[],
                'getpeerinfo':[],
                'hdrsproof':[prevheight,nextheight],
                'help':[],
                'listtransactions1':[address,isCCno,skipcount],
                'listtransactions2':[address,isCCyes,skipcount],
                'listunspent1':[address,isCCno,skipcount],
                'listunspent2':[address,isCCyes,skipcount],
                'login':[wif], 'logout':[], 'mempool':[],
                'notarizations':[height],
                'spend':[address,amount],
                'spentinfo':[txid,vout],
                'txproof':[txid,height],
                'stop':[]}


def nspv_broadcast(node_ip, user_pass, rawhex):
  params = {'userpass': user_pass,
            'method': 'broadcast'}
  if rawhex is not False:
    params.update({'hex':rawhex})
  r = requests.post(node_ip, json=params)
  return r

def nspv_getinfo(node_ip, user_pass, height=False):
  params = {'userpass': user_pass,
            'method': 'getinfo'}
  if height is not False:
    params.update({'height':height})
  r = requests.post(node_ip, json=params)
  print(r.json())
  return r

def nspv_getnewaddress(node_ip, user_pass):
  params = {'userpass': user_pass,
            'method': 'getnewaddress'}
  r = requests.post(node_ip, json=params)
  return r

def nspv_getpeerinfo(node_ip, user_pass):
  params = {'userpass': user_pass,
            'method': 'getpeerinfo'}
  r = requests.post(node_ip, json=params)
  return r

def nspv_hdrsproof(node_ip, user_pass, prevheight, nextheight):
  params = {'userpass': user_pass,
            'method': 'hdrsproof'}
  if prevheight is not False:
    params.update({'prevheight':prevheight})
  if nextheight is not False:
    params.update({'nextheight':nextheight})
  r = requests.post(node_ip, json=params)
  return r

def nspv_help(node_ip, user_pass):
  params = {'userpass': user_pass,
            'method': 'help'}
  r = requests.post(node_ip, json=params)
  return r

def nspv_listtransactions(node_ip, user_pass, address=False, isCC=False, skipcount=False, txfilter=False):
  params = {'userpass': user_pass,
            'method': 'listtransactions'}
  if address is not False:
    params.update({'address': address})
  if isCC is not False:
    params.update({'isCC': isCC})
  if skipcount is not False:
    params.update({'skipcount': skipcount})
  if txfilter is not False:
    params.update({'filter': txfilter})
  r = requests.post(node_ip, json=params)
  return r

def nspv_listunspent(node_ip, user_pass, address=False, isCC=False, skipcount=False, txfilter=False):
  params = {'userpass': user_pass,
            'method': 'listunspent'}
  if address is not False:
    params.update({'address': address})
  if isCC is not False:
    params.update({'isCC': isCC})
  if skipcount is not False:
    params.update({'skipcount': skipcount})
  if txfilter is not False:
    params.update({'filter': txfilter})
  r = requests.post(node_ip, json=params)
  return r

def nspv_login(node_ip, user_pass, wif=False):
  params = {'userpass': user_pass,
            'method': 'login'}
  if wif is not False:
    params.update({'wif': wif})
  r = requests.post(node_ip, json=params)
  print(r.json())
  return r

def nspv_logout(node_ip, user_pass):
  params = {'userpass': user_pass,
            'method': 'logout'}
  r = requests.post(node_ip, json=params)
  return r

def nspv_mempool(node_ip, user_pass):
  params = {'userpass': user_pass,
            'method': 'mempool'}
  r = requests.post(node_ip, json=params)
  return r

def nspv_notarizations(node_ip, user_pass, height):
  params = {'userpass': user_pass,
            'method': 'notarizations'}
  if height is not False:
    params.update({'height': height})
  r = requests.post(node_ip, json=params)
  return r

def nspv_spend(node_ip, user_pass, address, amount):
  params = {'userpass': user_pass,
            'method': 'spend'}
  if address is not False:
    params.update({'address': address})
  if amount is not False:
    params.update({'amount': amount})
  r = requests.post(node_ip, json=params)
  time.sleep(1)
  return r

def nspv_spentinfo(node_ip, user_pass, txid, vout):
  params = {'userpass': user_pass,
            'method': 'spend'}
  if txid is not False:
    params.update({'txid': txid})
  if vout is not False:
    params.update({'vout': vout})
  r = requests.post(node_ip, json=params)
  time.sleep(1)
  return r

def nspv_stop(node_ip, user_pass):
  params = {'userpass': user_pass,
            'method': 'stop'}
  r = requests.post(node_ip, json=params)
  return r

def nspv_txproof(node_ip, user_pass, txid, height):
  params = {'userpass': user_pass,
              'method': 'txproof'}
  if txid is not False:
    params.update({'txid': txid})
  if height is not False:
    params.update({'height': height})
  r = requests.post(node_ip, json=params)
  return r

