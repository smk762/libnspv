
/******************************************************************************
 * Copyright © 2014-2019 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/

#ifndef KOMODO_NSPVWALLET_H
#define KOMODO_NSPVWALLET_H

int32_t NSPV_validatehdrs(btc_spv_client *client,struct NSPV_ntzsproofresp *ptr)
{
    int32_t i,height,txidht; btc_tx *tx; bits256 blockhash,txid,desttxid;
    if ( (ptr->common.nextht-ptr->common.prevht+1) != ptr->common.numhdrs )
    {
        fprintf(stderr,"next.%d prev.%d -> %d vs %d\n",ptr->common.nextht,ptr->common.prevht,ptr->common.nextht-ptr->common.prevht+1,ptr->common.numhdrs);
        return(-2);
    }
    else if ( (tx= NSPV_txextract(ptr->nextntz,ptr->nexttxlen)) == 0 )
        return(-3);
    else if ( bits256_cmp(NSPV_tx_hash(tx),ptr->nexttxid) != 0 )
    {
        btc_tx_free(tx);
        return(-4);
    }
    else if ( NSPV_notarizationextract(client,1,&height,&blockhash,&desttxid,tx) < 0 )
    {
        btc_tx_free(tx);
        return(-5);
    }
    else if ( height != ptr->common.nextht )
    {
        btc_tx_free(tx);
        return(-6);
    }
    else if ( bits256_cmp(NSPV_hdrhash(&ptr->common.hdrs[ptr->common.numhdrs-1]),blockhash) != 0 )
    {
        btc_tx_free(tx);
        return(-7);
    }
    btc_tx_free(tx);
    for (i=ptr->common.numhdrs-1; i>0; i--)
    {
        blockhash = NSPV_hdrhash(&ptr->common.hdrs[i-1]);
        if ( bits256_cmp(blockhash,ptr->common.hdrs[i].hashPrevBlock) != 0 )
            return(-i-13);
    }
    sleep(1); // need this to get past the once per second rate limiter per message
    if ( (tx= NSPV_txextract(ptr->prevntz,ptr->prevtxlen)) == 0 )
        return(-8);
    else if ( bits256_cmp(NSPV_tx_hash(tx),ptr->prevtxid) )
    {
        btc_tx_free(tx);
        return(-9);
    }
    else if ( NSPV_notarizationextract(client,1,&height,&blockhash,&desttxid,tx) < 0 )
    {
        btc_tx_free(tx);
        return(-10);
    }
    else if ( height != ptr->common.prevht )
    {
        btc_tx_free(tx);
        return(-11);
    }
    else if ( bits256_cmp(NSPV_hdrhash(&ptr->common.hdrs[0]),blockhash) != 0 )
    {
        btc_tx_free(tx);
        return(-12);
    }
    btc_tx_free(tx);
    return(0);
}

btc_tx *NSPV_gettransaction(btc_spv_client *client,int32_t *retvalp,int32_t isKMD,int32_t skipvalidation,int32_t vout,bits256 txid,int32_t height,int64_t extradata,uint32_t tiptime,int64_t *rewardsump)
{
    struct NSPV_txproof *ptr; btc_tx_vout *vout; btc_tx *tx = 0; char str[65],str2[65]; int32_t i,offset; int64_t rewards = 0; uint32_t nLockTime; cstr *proof = 0; bits256 proofroot = zeroid;
    *retvalp = -1;
    if ( (ptr= NSPV_txproof_find(txid)) == 0 )
    {
        NSPV_txproof(vout,txid,height);
        ptr = &NSPV_txproofresult;
    }
    if ( ptr->txid != txid )
    {
        fprintf(stderr,"txproof error %s != %s\n",bits256_str(str,ptr->txid),bits256_str(str2,txid));
        return(0);
    }
    else if ( (tx= NSPV_txextract(ptr->tx,ptr->txlen)) == 0 )
        return(0);
    else if ( bits256_cmp(NSPV_tx_hash(tx),txid) != 0 )
    {
        *retvalp = -2001;
        return(tx);
    }
    else if ( skipvalidation == 0 && ptr->unspentvalue <= 0 )
    {
        *retvalp = -2002;
        return(tx);
    }
    else if ( isKMD != 0 && tiptime != 0 )
    {
        if ( (vout= btc_tx_vout(tx,vout)) != 0 )
        {
            rewards = komodo_interestnew(height!=0?height:1000000,vout->value,tx->locktime,tiptime);
            (*rewardsump) += rewards;
        }
        if ( rewards != extradata )
            fprintf(stderr,"extradata %.8f vs rewards %.8f\n",dstr(extradata),dstr(rewards));
    }
    if ( skipvalidation == 0 )
    {
        if ( ptr->txprooflen > 0 )
        {
            proof = cstr_new_sz(ptr->txprooflen);
            memcpy(proof->str,ptr->txproof,ptr->txprooflen);
        }
        NSPV_notarizations(height); // gets the prev and next notarizations
        if ( NSPV_inforesult.notarization.height >= height && (NSPV_ntzsresult.prevntz.height == 0 || NSPV_ntzsresult.prevntz.height >= NSPV_ntzsresult.nextntz.height) )
        {
            fprintf(stderr,"issue manual bracket\n");
            NSPV_notarizations(height-1);
            NSPV_notarizations(height+1);
            NSPV_notarizations(height); // gets the prev and next notarizations
        }
        if ( NSPV_ntzsresult.prevntz.height != 0 && NSPV_ntzsresult.prevntz.height <= NSPV_ntzsresult.nextntz.height )
        {
            fprintf(stderr,">>>>> gettx ht.%d prev.%d next.%d\n",height,NSPV_ntzsresult.prevntz.height, NSPV_ntzsresult.nextntz.height);
            offset = (height - NSPV_ntzsresult.prevntz.height);
            if ( offset >= 0 && height <= NSPV_ntzsresult.nextntz.height )
            {
                fprintf(stderr,"call NSPV_txidhdrsproof %s %s\n",bits256_str(str,NSPV_ntzsresult.prevntz.txid),bits256_str(str2,NSPV_ntzsresult.nextntz.txid));
                NSPV_txidhdrsproof(NSPV_ntzsresult.prevntz.txid,NSPV_ntzsresult.nextntz.txid);
                usleep(10000);
                if ( (retval= NSPV_validatehdrs(client,&NSPV_ntzsproofresult)) == 0 )
                {
                    fprintf(stderr,"calculate merkleproofroot with proof len.%d\n",proof->len);
                    /*std::vector<uint256> txids; uint256 proofroot;
                    proofroot = BitcoinGetProofMerkleRoot(proof,txids);*/
                    if ( proofroot != NSPV_ntzsproofresult.common.hdrs[offset].hashMerkleRoot )
                    {
                        fprintf(stderr,"prooflen.%d proofroot.%s vs %s\n",(int32_t)proof.size(),bits256_str(str,proofroot),bits256_str(str2,NSPV_ntzsproofresult.common.hdrs[offset].hashMerkleRoot));
                        retval = -2003;
                    } else *retvalp = 0;
                }
            } else *retvalp = -2005;
        } else *retvalp = -2004;
    }
    return(tx);
}

int32_t NSPV_vinselect(int32_t *aboveip,int64_t *abovep,int32_t *belowip,int64_t *belowp,struct NSPV_utxoresp utxos[],int32_t numunspents,int64_t value)
{
    int32_t i,abovei,belowi; int64_t above,below,gap,atx_value;
    abovei = belowi = -1;
    for (above=below=i=0; i<numunspents; i++)
    {
        if ( (atx_value= utxos[i].satoshis) <= 0 )
            continue;
        if ( atx_value == value )
        {
            *aboveip = *belowip = i;
            *abovep = *belowp = 0;
            return(i);
        }
        else if ( atx_value > value )
        {
            gap = (atx_value - value);
            if ( above == 0 || gap < above )
            {
                above = gap;
                abovei = i;
            }
        }
        else
        {
            gap = (value - atx_value);
            if ( below == 0 || gap < below )
            {
                below = gap;
                belowi = i;
            }
        }
        //printf("value %.8f gap %.8f abovei.%d %.8f belowi.%d %.8f\n",dstr(value),dstr(gap),abovei,dstr(above),belowi,dstr(below));
    }
    *aboveip = abovei;
    *abovep = above;
    *belowip = belowi;
    *belowp = below;
    //printf("above.%d below.%d\n",abovei,belowi);
    if ( abovei >= 0 && belowi >= 0 )
    {
        if ( above < (below >> 1) )
            return(abovei);
        else return(belowi);
    }
    else if ( abovei >= 0 )
        return(abovei);
    else return(belowi);
}

int64_t NSPV_addinputs(struct NSPV_utxoresp *used,btc_tx *mtx,int64_t total,int32_t maxinputs,struct NSPV_utxoresp *ptr,int32_t num)
{
    int32_t abovei,belowi,ind,vout,i,n = 0; int64_t threshold,above,below; int64_t remains,totalinputs = 0; struct NSPV_utxoresp utxos[NSPV_MAXVINS],*up;
    memset(utxos,0,sizeof(utxos));
    if ( maxinputs > NSPV_MAXVINS )
        maxinputs = NSPV_MAXVINS;
    if ( maxinputs > 0 )
        threshold = total/maxinputs;
    else threshold = total;
    for (i=0; i<num; i++)
    {
        if ( num < NSPV_MAXVINS || ptr[i].satoshis > threshold )
            utxos[n++] = ptr[i];
    }
    remains = total;
    //fprintf(stderr,"threshold %.8f n.%d for total %.8f\n",(double)threshold/COIN,n,(double)total/COIN);
    for (i=0; i<maxinputs && n>0; i++)
    {
        below = above = 0;
        abovei = belowi = -1;
        if ( NSPV_vinselect(&abovei,&above,&belowi,&below,utxos,n,remains) < 0 )
        {
            fprintf(stderr,"error finding unspent i.%d of %d, %.8f vs %.8f\n",i,n,(double)remains/COIN,(double)total/COIN);
            return(0);
        }
        if ( belowi < 0 || abovei >= 0 )
            ind = abovei;
        else ind = belowi;
        if ( ind < 0 )
        {
            fprintf(stderr,"error finding unspent i.%d of %d, %.8f vs %.8f, abovei.%d belowi.%d ind.%d\n",i,n,(double)remains/COIN,(double)total/COIN,abovei,belowi,ind);
            return(0);
        }
        //fprintf(stderr,"i.%d ind.%d abovei.%d belowi.%d n.%d\n",i,ind,abovei,belowi,n);
        up = &utxos[ind];
        mtx.vin.push_back(CTxIn(up->txid,up->vout,CScript()));
        used[i] = *up;
        totalinputs += up->satoshis;
        remains -= up->satoshis;
        utxos[ind] = utxos[--n];
        memset(&utxos[n],0,sizeof(utxos[n]));
        //fprintf(stderr,"totalinputs %.8f vs total %.8f i.%d vs max.%d\n",(double)totalinputs/COIN,(double)total/COIN,i,maxinputs);
        if ( totalinputs >= total || (i+1) >= maxinputs )
            break;
    }
    //fprintf(stderr,"totalinputs %.8f vs total %.8f\n",(double)totalinputs/COIN,(double)total/COIN);
    if ( totalinputs >= total )
        return(totalinputs);
    return(0);
}

bool NSPV_SignTx(btc_tx *mtx,int32_t vini,int64_t utxovalue,cstring *scriptPubKey,uint32_t nTime)
{
    if ( nTime != 0 && mtx->version == 1 )
    {
        fprintf(stderr,"use legacy sig validation\n");
        branchid = 0;
    }
    /*CTransaction txNewConst(mtx); SignatureData sigdata; CBasicKeyStore keystore; int64_t branchid = NSPV_BRANCHID;
    keystore.AddKey(NSPV_key);
    if ( ProduceSignature(TransactionSignatureCreator(&keystore,&txNewConst,vini,utxovalue,SIGHASH_ALL),scriptPubKey,sigdata,branchid) != 0 )
    {
        UpdateTransaction(mtx,vini,sigdata);
        //fprintf(stderr,"SIG_TXHASH %s vini.%d %.8f\n",bits256_str(str,SIG_TXHASH),vini,(double)utxovalue/COIN);
        return(true);
    }  //else fprintf(stderr,"sigerr SIG_TXHASH %s vini.%d %.8f\n",bits256_str(str,SIG_TXHASH),vini,(double)utxovalue/COIN);
    return(false);*/
    fprintf(stderr,"create signature txversion.%d\n",mtx->version);
    return(true);
}

cstring *NSPV_signtx(btc_spv_client *client,int32_t isKMD,int64_t *rewardsump,int64_t *interestsump,cJSON *retcodes,btc_tx *mtx,uint64_t txfee,struct NSPV_utxoresp used[])
{
    btc_tx *vintx; btc_tx_vin *vin; btc_tx_out *vout; cstring *hex = 0; char str[65]; bits256 prevhash; int64_t interest=0,change,totaloutputs=0,totalinputs=0; int32_t i,utxovout,n,validation;
    *rewardsump = *interestsump = 0;
    if ( mtx == 0 )
        return(0);
    if ( mtx->vout != 0 )
    {
        n = mtx->vout->len;
        for (i=0; i<n; i++)
        {
            if ( (vout= btc_tx_vout(mtx,i)) != 0 )
                totaloutputs += vout->value;
        }
    }
    if ( mtx->vin != 0 )
    {
        n = mtx->vin->len;
        for (i=0; i<n; i++)
        {
            totalinputs += used[i].satoshis;
            interest += used[i].extradata;
        }
    }
    *interestsump = interest;
    if ( (totalinputs+interest) >= totaloutputs+2*txfee )
    {
        change = (totalinputs+interest) - (totaloutputs+txfee);
        btc_tx_add_p2pk(mtx,change,NSPV_pubkey->pubkey);
    }
    for (i=0; i<n; i++)
    {
        if ( (vin= btc_tx_vin(mtx,i)) == 0 )
        {
            fprintf(stderr,"mtx has no vin.%d\n",i);
            return(0);
        }
        utxovout = vin->prevout.n;
        prevhash = btc_uint256_to_bits256(vin->prevout.hash);
        if ( i > 0 )
            sleep(1);
        vintx = NSPV_gettransaction(client,&validation,isKMD,0,utxovout,prevhash,used[i].height,used[i].extradata,NSPV_tiptime,rewardsump);
        jaddinum(retcodes,validation);
        if ( vintx != 0 && validation != -1 && (vout= btc_tx_vout(vintx,utxovout)) != 0 ) // other validation retcodes are degraded security
        {
            if ( vout->value != used[i].satoshis )
            {
                fprintf(stderr,"vintx mismatch %.8f != %.8f\n",(double)vout->value/COIN,(double)used[i].satoshis/COIN);
                return(0);
            }
            else if ( utxovout != used[i].vout )
            {
                fprintf(stderr,"vintx vout mismatch %d != %d\n",utxovout,used[i].vout);
                return(0);
            }
            else if ( NSPV_SignTx(mtx,i,vout->value,vout->script_pubKey,0) == 0 )
            {
                fprintf(stderr,"signing error for vini.%d\n",i);
                return(0);
            }
        } else fprintf(stderr,"couldnt find txid.%s/v%d or it was spent\n",bits256_str(str,prevhash),utxovout); // of course much better handling is needed
    }
    fprintf(stderr,"sign %d inputs %.8f + interest %.8f -> %d outputs %.8f change %.8f\n",(int32_t)mtx->vin->len,(double)totalinputs/COIN,(double)interest/COIN,(int32_t)mtx->vout->len,(double)totaloutputs/COIN,(double)change/COIN);
    return(btc_tx_to_cstr(mtx));
}

cJSON *NSPV_spend(btc_spv_client *client,char *srcaddr,char *destaddr,int64_t satoshis)
{
    cJSON *result = cJSON_CreateObject(),*retcodes = cJSON_CreateArray(); uint8_t *ptr,rmd160[128]; int32_t len,isKMD = 0; int64_t txfee = 10000; cstring *scriptPubKey=0,*hex=0; btc_tx *mtx=0,*tx=0; struct NSPV_utxoresp used[NSPV_MAXVINS]; int64_t rewardsum=0,interestsum=0;
    if ( NSPV_logintime == 0 || time(NULL) > NSPV_logintime+NSPV_AUTOLOGOUT )
    {
        jaddstr(result,"result","error");
        jaddstr(result,"error","wif expired");
        return(result);
    }
    if ( strcmp(srcaddr,NSPV_address) != 0 )
    {
        jaddstr(result,"result","error");
        jaddstr(result,"error","invalid address");
        jaddstr(result,"mismatched",srcaddr);
        return(result);
    }
    if ( NSPV_inforesult.height == 0 )
    {
        jaddstr(result,"result","error");
        jaddstr(result,"error","couldnt getinfo");
        return(result);
    }
    if ( NSPV_utxosresult.CCflag != 0 || strcmp(NSPV_utxosresult.coinaddr,srcaddr) != 0 || NSPV_utxosresult.nodeheight < NSPV_inforesult.height )
        NSPV_addressutxos(srcaddr,0,0);
    if ( NSPV_utxosresult.CCflag != 0 || strcmp(NSPV_utxosresult.coinaddr,srcaddr) != 0 || NSPV_utxosresult.nodeheight < NSPV_inforesult.height )
    {
        jaddstr(result,"result","error");
        jaddstr(result,"address",NSPV_utxosresult.coinaddr);
        jaddstr(result,"srcaddr",srcaddr);
        jaddnum(result,"nodeheight",NSPV_utxosresult.nodeheight);
        jaddnum(result,"infoheight",NSPV_inforesult.height);
        jaddnum(result,"CCflag",NSPV_utxosresult.CCflag);
        jaddstr(result,"error","couldnt get addressutxos");
        return(result);
    }
    if ( NSPV_utxosresult.total < satoshis+txfee )
    {
        jaddstr(result,"result","error");
        jaddstr(result,"error","not enough funds");
        jaddnum(result,"balance",(double)NSPV_utxosresult.total/COIN);
        jaddnum(result,"amount",(double)satoshis/COIN);
        return(result);
    }
    if ( btc_base58_decode_check(destaddr,rmd160,sizeof(rmd160)) != 25 )
    {
        if ( (len= is_hexstr(destaddr,0)) > 0 ) // all hex string
        {
            len >>= 1;
            scriptPubkey = cstr_new_sz(len);
            decode_hex((uint8_t *)scriptPubkey->str,len,destaddr);
            scriptPubkey->len = len;
        }
        else
        {
            jaddstr(result,"result","error");
            jaddstr(result,"error","invalid destaddr");
            jaddstr(result,"destaddr",destaddr);
            return(result);
        }
    }
    else
    {
        scriptPubkey = cstr_new_sz(25);
        btc_script_build_p2pkh(scriptPubkey,rmd160);
    }
    printf("%s numutxos.%d balance %.8f\n",NSPV_utxosresult.coinaddr,NSPV_utxosresult.numutxos,(double)NSPV_utxosresult.total/COIN);
    mtx = btc_tx_new(client->chainparams->komodo != 0 ? SAPLING_TX_VERSION : 1);
    isKMD = (strcmp(client->chainparams->name,"KMD") == 0);
    if ( isKMD != 0 )
        mtx->locktime = (uint32_t)time(NULL) - 777;
    memset(used,0,sizeof(used));
    if ( NSPV_addinputs(used,mtx,satoshis+txfee,64,NSPV_utxosresult.utxos,NSPV_utxosresult.numutxos) > 0 )
    {
        btc_tx_add_txout(mtx,satoshis,scriptPubKey);
        if ( NSPV_logintime == 0 || time(NULL) > NSPV_logintime+NSPV_AUTOLOGOUT )
        {
            jaddstr(result,"result","error");
            jaddstr(result,"error","wif expired");
            btc_tx_free(mtx);
            return(result);
        }
        hex = NSPV_signtx(client,isKMD,rewardsum,interestsum,retcodes,mtx,txfee,used);
        if ( isKMD != 0 )
        {
            char numstr[64];
            sprintf(numstr,"%.8f",(double)interestsum/COIN);
            jaddstr(result,"rewards",numstr);
            sprintf(numstr,"%.8f",(double)rewardsum/COIN);
            jaddstr(result,"validated",numstr);
        }
        if ( hex != 0 && hex->len > 0 )
        {
            if ( (tx= btc_tx_decodehex(hex) != 0 )
            {
                jadd(result,"tx",btc_tx_to_json(tx));
                jaddstr(result,"result","success");
                jaddstr(result,"hex",hex->str);
                jadd(result,"retcodes",retcodes);
            }
            else
            {
                jaddstr(result,"result","error");
                jaddstr(result,"error","couldnt decode");
                jaddstr(result,"hex",hex->str);
            }
        }
        else
        {
            jaddstr(result,"result","error");
            jadd(result,"retcodes",retcodes);
            jaddstr(result,"error","signing error");
        }
        btc_tx_free(mtx);
        btc_tx_free(tx);
        cstr_free(hex,1);
        return(result);
    }
    else
    {
        jaddstr(result,"result","error");
        jaddstr(result,"error","couldnt create tx");
        btc_tx_free(mtx);
        cstr_free(scriptPubKey,1);
        return(result);
    }
}

#ifdef SUPPORT_CC
int64_t NSPV_AddNormalinputs(CMutableTransaction &mtx,CPubKey mypk,int64_t total,int32_t maxinputs,struct NSPV_CCmtxinfo *ptr)
{
    char coinaddr[64]; int32_t CCflag = 0;
    if ( ptr != 0 )
    {
        mtx.fOverwintered = true;
        mtx.nExpiryHeight = 0;
        mtx.nVersionGroupId = SAPLING_VERSION_GROUP_ID;
        mtx.nVersion = SAPLING_TX_VERSION;
        Getscriptaddress(coinaddr,CScript() << ParseHex(HexStr(mypk)) << OP_CHECKSIG);
        if ( strcmp(ptr->U.coinaddr,coinaddr) != 0 )
        {
            NSPV_addressutxos(coinaddr,CCflag,0);
            NSPV_utxosresp_purge(&ptr->U);
            NSPV_utxosresp_copy(&ptr->U,&NSPV_utxosresult);
        }
        fprintf(stderr,"%s numutxos.%d\n",ptr->U.coinaddr,ptr->U.numutxos);
        memset(ptr->used,0,sizeof(ptr->used));
        return(NSPV_addinputs(ptr->used,mtx,total,maxinputs,ptr->U.utxos,ptr->U.numutxos));
    } else return(0);
}

void NSPV_utxos2CCunspents(struct NSPV_utxosresp *ptr,std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > &outputs)
{
    CAddressUnspentKey key; CAddressUnspentValue value; int32_t i,type; uint160 hashBytes; std::string addrstr(ptr->coinaddr);
    if ( ptr->utxos != NULL && ptr->numutxos > 0 )
    {
        CBitcoinAddress address(addrstr);
        if ( address.GetIndexKey(hashBytes, type, ptr->CCflag) == 0 )
        {
            fprintf(stderr,"couldnt get indexkey\n");
            return;
        }
        for (i = 0; i < ptr->numutxos; i ++)
        {
            key.type = type;
            key.hashBytes = hashBytes;
            key.txhash = ptr->utxos[i].txid;
            key.index = ptr->utxos[i].vout;
            value.satoshis = ptr->utxos[i].satoshis;
            value.blockHeight = ptr->utxos[i].height;
            outputs.push_back(std::make_pair(key, value));
        }
    }
}

void NSPV_txids2CCtxids(struct NSPV_txidsresp *ptr,std::vector<std::pair<CAddressIndexKey, CAmount> > &txids)
{
    CAddressIndexKey key; int64_t value; int32_t i,type; uint160 hashBytes; std::string addrstr(ptr->coinaddr);
    if ( ptr->txids != NULL && ptr->numtxids > 0 )
    {
        CBitcoinAddress address(addrstr);
        if ( address.GetIndexKey(hashBytes, type, ptr->CCflag) == 0 )
        {
            fprintf(stderr,"couldnt get indexkey\n");
            return;
        }
        for (i = 0; i < ptr->numtxids; i ++)
        {
            key.type = type;
            key.hashBytes = hashBytes;
            key.txhash = ptr->txids[i].txid;
            key.index = ptr->txids[i].vout;
            key.blockHeight = ptr->txids[i].height;
            value = ptr->txids[i].satoshis;
            txids.push_back(std::make_pair(key, value));
        }
    }
}

void NSPV_CCunspents(std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > &outputs,char *coinaddr,bool ccflag)
{
    NSPV_addressutxos(coinaddr,ccflag,0);
    NSPV_utxos2CCunspents(&NSPV_utxosresult,outputs);
}

void NSPV_CCtxids(std::vector<std::pair<CAddressIndexKey, CAmount> > &txids,char *coinaddr,bool ccflag)
{
    NSPV_addresstxids(coinaddr,ccflag,0);
    NSPV_txids2CCtxids(&NSPV_txidsresult,txids);
}
#endif

#endif // KOMODO_NSPVWALLET_H
