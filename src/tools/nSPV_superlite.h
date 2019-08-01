
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

#ifndef KOMODO_NSPVSUPERLITE_H
#define KOMODO_NSPVSUPERLITE_H

#include <btc/block.h>
#include <btc/blockchain.h>
#include <btc/headersdb.h>
#include <btc/headersdb_file.h>
#include <btc/net.h>
#include <btc/netspv.h>
#include <btc/protocol.h>
#include <btc/serialize.h>
#include <btc/tx.h>
#include <btc/utils.h>
#include <btc/base58.h>

cJSON *NSPV_spend(btc_spv_client *client,char *srcaddr,char *destaddr,int64_t satoshis);
cJSON *NSPV_txproof(btc_spv_client *client,int32_t vout,bits256 txid,int32_t height);
void expand_ipbits(char *ipaddr,uint64_t ipbits);
btc_tx *NSPV_gettransaction(btc_spv_client *client,int32_t *retvalp,int32_t isKMD,int32_t skipvalidation,int32_t v,bits256 txid,int32_t height,int64_t extradata,uint32_t tiptime,int64_t *rewardsump);

uint32_t NSPV_logintime,NSPV_lastinfo,NSPV_tiptime;
char NSPV_lastpeer[64],NSPV_address[64],NSPV_wifstr[64],NSPV_pubkeystr[67],NSPV_symbol[64];
btc_spv_client *NSPV_client;
const btc_chainparams *NSPV_chain;

btc_key NSPV_key;
btc_pubkey NSPV_pubkey;
struct NSPV_inforesp NSPV_inforesult;
struct NSPV_utxosresp NSPV_utxosresult;
struct NSPV_txidsresp NSPV_txidsresult;
struct NSPV_mempoolresp NSPV_mempoolresult;
struct NSPV_spentinfo NSPV_spentresult;
struct NSPV_ntzsresp NSPV_ntzsresult;
struct NSPV_ntzsproofresp NSPV_ntzsproofresult;
struct NSPV_txproof NSPV_txproofresult;
struct NSPV_broadcastresp NSPV_broadcastresult;

struct NSPV_ntzsresp NSPV_ntzsresp_cache[NSPV_MAXVINS];
struct NSPV_ntzsproofresp NSPV_ntzsproofresp_cache[NSPV_MAXVINS * 2];
struct NSPV_txproof NSPV_txproof_cache[NSPV_MAXVINS * 4];

// validation 
struct NSPV_ntz NSPV_lastntz;
struct NSPV_header NSPV_blockheaders[128]; // limitation here is that 100 block history is maximum. no nota for 100 blocks and we cant sync back to the notarizatio, we can wait for the next one. 
int32_t NSPV_num_headers = 0;
int32_t NSPV_hdrheight_counter;
int32_t IS_IN_SYNC = 0;

struct NSPV_ntzsresp *NSPV_ntzsresp_find(int32_t reqheight)
{
    uint32_t i;
    for (i=0; i<sizeof(NSPV_ntzsresp_cache)/sizeof(*NSPV_ntzsresp_cache); i++)
        if ( NSPV_ntzsresp_cache[i].reqheight == reqheight )
            return(&NSPV_ntzsresp_cache[i]);
    return(0);
}

struct NSPV_ntzsresp *NSPV_ntzsresp_add(struct NSPV_ntzsresp *ptr)
{
    uint32_t i;
    for (i=0; i<sizeof(NSPV_ntzsresp_cache)/sizeof(*NSPV_ntzsresp_cache); i++)
        if ( NSPV_ntzsresp_cache[i].reqheight == 0 )
            break;
    if ( i == sizeof(NSPV_ntzsresp_cache)/sizeof(*NSPV_ntzsresp_cache) )
        i = (rand() % (sizeof(NSPV_ntzsresp_cache)/sizeof(*NSPV_ntzsresp_cache)));
    NSPV_ntzsresp_purge(&NSPV_ntzsresp_cache[i]);
    NSPV_ntzsresp_copy(&NSPV_ntzsresp_cache[i],ptr);
    fprintf(stderr,"ADD CACHE ntzsresp req.%d\n",ptr->reqheight);
    return(&NSPV_ntzsresp_cache[i]);
}

struct NSPV_txproof *NSPV_txproof_find(bits256 txid,int32_t height)
{
    uint32_t i; struct NSPV_txproof *backup = 0;
    for (i=0; i<sizeof(NSPV_txproof_cache)/sizeof(*NSPV_txproof_cache); i++)
        if ( memcmp(&NSPV_txproof_cache[i].txid,&txid,sizeof(txid)) == 0 && (height == 0 || NSPV_txproof_cache[i].height == height) )
        {
            if ( NSPV_txproof_cache[i].txprooflen != 0 )
                return(&NSPV_txproof_cache[i]);
            else backup = &NSPV_txproof_cache[i];
        }
    return(backup);
}

struct NSPV_txproof *NSPV_txproof_add(struct NSPV_txproof *ptr)
{
    uint32_t i; char str[65];
    for (i=0; i<sizeof(NSPV_txproof_cache)/sizeof(*NSPV_txproof_cache); i++)
        if ( memcmp(&NSPV_txproof_cache[i].txid,&ptr->txid,sizeof(ptr->txid)) == 0 )
        {
            if ( NSPV_txproof_cache[i].txprooflen == 0 && ptr->txprooflen != 0 )
            {
                NSPV_txproof_purge(&NSPV_txproof_cache[i]);
                NSPV_txproof_copy(&NSPV_txproof_cache[i],ptr);
                return(&NSPV_txproof_cache[i]);
            }
            else if ( NSPV_txproof_cache[i].txprooflen != 0 || ptr->txprooflen == 0 )
                return(&NSPV_txproof_cache[i]);
        }
    for (i=0; i<sizeof(NSPV_txproof_cache)/sizeof(*NSPV_txproof_cache); i++)
        if ( NSPV_txproof_cache[i].txlen == 0 )
            break;
    if ( i == sizeof(NSPV_txproof_cache)/sizeof(*NSPV_txproof_cache) )
        i = (rand() % (sizeof(NSPV_txproof_cache)/sizeof(*NSPV_txproof_cache)));
    NSPV_txproof_purge(&NSPV_txproof_cache[i]);
    NSPV_txproof_copy(&NSPV_txproof_cache[i],ptr);
    fprintf(stderr,"ADD CACHE txproof %s\n",bits256_str(str,ptr->txid));
    return(&NSPV_txproof_cache[i]);
}

struct NSPV_ntzsproofresp *NSPV_ntzsproof_find(bits256 prevtxid,bits256 nexttxid)
{
    uint32_t i;
    for (i=0; i<sizeof(NSPV_ntzsproofresp_cache)/sizeof(*NSPV_ntzsproofresp_cache); i++)
        if ( memcmp(&NSPV_ntzsproofresp_cache[i].prevtxid,&prevtxid,sizeof(prevtxid)) == 0 && memcmp(&NSPV_ntzsproofresp_cache[i].nexttxid,&nexttxid,sizeof(nexttxid)) == 0 )
            return(&NSPV_ntzsproofresp_cache[i]);
    return(0);
}

struct NSPV_ntzsproofresp *NSPV_ntzsproof_add(struct NSPV_ntzsproofresp *ptr)
{
    uint32_t i;
    for (i=0; i<sizeof(NSPV_ntzsproofresp_cache)/sizeof(*NSPV_ntzsproofresp_cache); i++)
        if ( NSPV_ntzsproofresp_cache[i].common.hdrs == 0 )
            break;
    if ( i == sizeof(NSPV_ntzsproofresp_cache)/sizeof(*NSPV_ntzsproofresp_cache) )
        i = (rand() % (sizeof(NSPV_ntzsproofresp_cache)/sizeof(*NSPV_ntzsproofresp_cache)));
    NSPV_ntzsproofresp_purge(&NSPV_ntzsproofresp_cache[i]);
    NSPV_ntzsproofresp_copy(&NSPV_ntzsproofresp_cache[i],ptr);
    return(&NSPV_ntzsproofresp_cache[i]);
}

void NSPV_logout()
{
    if ( NSPV_logintime != 0 )
        fprintf(stderr,"scrub wif and privkey from NSPV memory\n");
    memset(NSPV_ntzsproofresp_cache,0,sizeof(NSPV_ntzsproofresp_cache));
    memset(NSPV_txproof_cache,0,sizeof(NSPV_txproof_cache));
    memset(NSPV_ntzsresp_cache,0,sizeof(NSPV_ntzsresp_cache));
    memset(NSPV_wifstr,0,sizeof(NSPV_wifstr));
    memset(&NSPV_key,0,sizeof(NSPV_key));
    NSPV_logintime = 0;
}

btc_node *NSPV_req(btc_spv_client *client,btc_node *node,uint8_t *msg,int32_t len,uint64_t mask,int32_t ind)
{
    int32_t i,n,flag = 0; btc_node *nodes[64]; uint32_t timestamp = (uint32_t)time(NULL);
    if ( node == 0 )
    {
        memset(nodes,0,sizeof(nodes));
        n = 0;
        for (i=0; i<(int32_t)client->nodegroup->nodes->len; i++)
        {
            btc_node *ptr = vector_idx(client->nodegroup->nodes,i);
            if ( ptr->prevtimes[ind] > timestamp )
                ptr->prevtimes[ind] = 0;
            if ( (ptr->state & NODE_CONNECTED) == NODE_CONNECTED )
            {
                if ( (ptr->nServices & mask) == mask && timestamp > ptr->prevtimes[ind] )
                {
                    flag = 1;
                    nodes[n++] = ptr;
                    if ( n == sizeof(nodes)/sizeof(*nodes) )
                        break;
                }
            }
        }
        if ( n > 0 )
            node = nodes[rand() % n];
    } else flag = 1;
    if ( node != 0 )
    {
        if ( len >= 0xfd )
        {
            //fprintf(stderr,"len.%d overflow for 1 byte varint\n",len);
            msg[0] = 0xfd;
            msg[1] = (len - 3) & 0xff;
            msg[2] = ((len - 1) >> 8) & 0xff;
        } else msg[0] = len - 1;
        cstring *request = btc_p2p_message_new(node->nodegroup->chainparams->netmagic,"getnSPV",msg,len);
        btc_node_send(node,request);
        cstr_free(request, true);
        //fprintf(stderr,"pushmessage [%d] len.%d\n",msg[1],len);
        node->prevtimes[ind] = timestamp;
        return(node);
    } else fprintf(stderr,"no nodes\n");
    return(0);
}

int32_t NSPV_periodic(btc_node *node) // called periodically
{
    uint8_t msg[512]; int32_t i,len = 1; uint32_t timestamp = (uint32_t)time(NULL);
    btc_spv_client *client = (btc_spv_client*)node->nodegroup->ctx;
    if ( NSPV_logintime != 0 && timestamp > NSPV_logintime+NSPV_AUTOLOGOUT )
        NSPV_logout();
    if ( node->prevtimes[NSPV_INFO>>1] > timestamp )
        node->prevtimes[NSPV_INFO>>1] = 0;
    if ( node->gotaddrs == 0 )
    {
        // void CAddrMan::GetAddr_(std::vector<CAddress>& vAddr) to use nSPV flag
        cstring *request = btc_p2p_message_new(node->nodegroup->chainparams->netmagic,"getaddr",NULL,0);
        btc_node_send(node,request);
        cstr_free(request, true);
        //fprintf(stderr,"request addrs\n");
    }
    if ( timestamp > NSPV_lastinfo + client->chainparams->blocktime/2 && timestamp > node->prevtimes[NSPV_INFO>>1] + 2*client->chainparams->blocktime/3 )
    {
        int32_t reqht, hdrheight;
        if ( NSPV_lastntz.height == 0 || IS_IN_SYNC == 1 || (NSPV_inforesult.height-NSPV_lastntz.height-NSPV_num_headers < 5 && rand() % 100 < 10) )
            reqht = 0;
        else 
            reqht = NSPV_hdrheight_counter;
        msg[len++] = NSPV_INFO;
        len += iguana_rwnum(1,&msg[len],sizeof(reqht),&reqht);
        //fprintf(stderr,"[%i] getinfo for block %i\n",node->nodeid, reqht);
        NSPV_hdrheight_counter++;
        if ( NSPV_hdrheight_counter > NSPV_inforesult.height+1 )
            NSPV_hdrheight_counter = NSPV_lastntz.height;
        if ( NSPV_inforesult.height-NSPV_lastntz.height-NSPV_hdrheight_counter > 101 )
            NSPV_hdrheight_counter = NSPV_inforesult.height-101;
        
        return(NSPV_req(client,node,msg,len,NODE_NSPV,NSPV_INFO>>1) != 0);
    }
    return(0);
}

int32_t havehdr(bits256 blockhash)
{
    for (int32_t i = 0; i < NSPV_num_headers; i++) 
        if ( bits256_cmp(NSPV_blockheaders[i].blockhash, blockhash) == 0 )
            return(i);
    return(-1);
}

int32_t validate_headers(bits256 fromblockhash)
{
    int32_t index, bestindex = 0, counted = 0; char str[65];
    bits256 lastblock = fromblockhash;
    while ( counted <= NSPV_num_headers )
    {
        if ( (index= havehdr(lastblock)) != -1 )
        {
            lastblock = NSPV_blockheaders[index].hashPrevBlock;
            bestindex = index;
            counted++;
        }
        else break;
    }
    return ( bits256_cmp(NSPV_blockheaders[bestindex].blockhash, NSPV_lastntz.blockhash) == 0 );
}

int32_t check_headers()
{
    return(NSPV_num_headers >= NSPV_inforesult.height-NSPV_lastntz.height-1);
}

void reset_headers(int32_t new_ntz_height)
{
    struct NSPV_header old_blockheaders[128];
    for (int32_t i = 0; i < NSPV_num_headers; i++) 
        old_blockheaders[i] = NSPV_blockheaders[i];
    int32_t old_num_headers = NSPV_num_headers;
    memset(NSPV_blockheaders,0,sizeof(*NSPV_blockheaders));
    NSPV_num_headers = 0;
    for (int32_t i = 0; i < old_num_headers; i++) 
    {
        if ( old_blockheaders[i].height >= new_ntz_height )
        {
            NSPV_blockheaders[NSPV_num_headers] = old_blockheaders[i];
            NSPV_num_headers++;
        }
    }
}

int32_t validate_notarization(bits256 notarization, uint32_t timestamp)
{
    int32_t height; bits256 blockhash,desttxid;
    if ( NSPV_txproofresult.txlen == 0 )
        return(0);
    btc_tx *tx = NSPV_txextract(NSPV_txproofresult.tx,NSPV_txproofresult.txlen); 
    if ( tx == NULL ) 
        return(0);
    if ( bits256_cmp(NSPV_tx_hash(tx),NSPV_inforesult.notarization.txid) != 0 )
        return(0);
    if ( NSPV_notarizationextract(NSPV_client,1,&height,&blockhash,&desttxid,tx, timestamp) == 0 )
    {
        btc_tx_free(tx);
        return(1);
    }
    return(0);
}

void komodo_nSPVresp(btc_node *from,uint8_t *response,int32_t len) 
{
    struct NSPV_inforesp I; char str[65],str2[65]; uint32_t timestamp = (uint32_t)time(NULL);
    const btc_chainparams *chain = from->nodegroup->chainparams;
    sprintf(NSPV_lastpeer,"nodeid.%d",from->nodeid);
    if ( len > 0 )
    {
        switch ( response[0] )
        {
            case NSPV_INFORESP:
                I = NSPV_inforesult;
                NSPV_inforesp_purge(&NSPV_inforesult);
                NSPV_rwinforesp(0,&response[1],&NSPV_inforesult,len);
                //fprintf(stderr,"got info version.%d response %u from.%d size.%d hdrheight.%d \n",NSPV_inforesult.version,timestamp,from->nodeid,len,NSPV_inforesult.hdrheight); // update current height and ntrz status
                bits256 hdrhash = NSPV_hdrhash(&(NSPV_inforesult.H));
                if ( NSPV_inforesult.height < I.height )
                {
                    fprintf(stderr,"got old info response %u size.%d height.%d\n",timestamp,len,NSPV_inforesult.height);
                    NSPV_inforesp_purge(&NSPV_inforesult);
                    NSPV_inforesult = I;
                }
                else
                {
                    if ( NSPV_inforesult.height > I.height )
                        fprintf(stderr, "[%i] last ntz.%i currentht.%i hdrheight.%i est headers until sync.%i\n",from->nodeid, NSPV_lastntz.height, NSPV_inforesult.height, NSPV_inforesult.hdrheight,  NSPV_inforesult.height-NSPV_lastntz.height-NSPV_num_headers);
                    // fetch the notarization tx to validate it when it arives. 
                    if ( NSPV_lastntz.height < NSPV_inforesult.notarization.height )
                    {
                        static int32_t counter = 0;
                        if ( counter < 1 )
                            NSPV_txproof(NSPV_client, 0, NSPV_inforesult.notarization.txid, -1);
                        counter++;
                        if ( counter > 5 ) 
                            counter = 0;
                    }
                    // insert block header into array 
                    if ( NSPV_inforesult.hdrheight >= NSPV_lastntz.height && havehdr(hdrhash) == -1 )
                    {
                        // empty half the array to prevent trying to over fill it. 
                        if ( NSPV_num_headers == 128 )
                        {
                            fprintf(stderr, "array of headers is full, emptying blocks before height.%i\n", I.height-64);
                            reset_headers(I.height-64);
                        }
                        //fprintf(stderr, "added  block.%i\n",  NSPV_inforesult.hdrheight);
                        NSPV_blockheaders[NSPV_num_headers].height = NSPV_inforesult.hdrheight;
                        NSPV_blockheaders[NSPV_num_headers].blockhash = hdrhash;
                        NSPV_blockheaders[NSPV_num_headers].hashPrevBlock = NSPV_inforesult.H.hashPrevBlock;
                        NSPV_num_headers++;
                    }
                    // if we have enough headers and they validate back to the last notarization update the tiptime/synced chain status
                    if ( check_headers() != 0 && validate_headers(NSPV_inforesult.blockhash) != 0 )
                    {
                        //fprintf(stderr, "[%i]: synced at height.%i \n",from->nodeid, NSPV_inforesult.height);
                        NSPV_lastinfo = timestamp - chain->blocktime/4;
                        NSPV_tiptime = NSPV_inforesult.H.nTime;
                        from->synced = 1;
                        IS_IN_SYNC = 1;
                    } 
                    else if ( IS_IN_SYNC == 1 )
                    {
                        // this is for reorgs, we dont update the chain tip if it cannot be linked back to last nota.
                        // we do keep the block in the array though incase it becomes main chain later.
                        NSPV_inforesp_purge(&NSPV_inforesult);
                        NSPV_inforesult = I;
                        from->synced = 0;
                        // set in sync false, so we can try and fetch more previous blocks to get back in sync. 
                        IS_IN_SYNC = 0;
                    }
                    else IS_IN_SYNC = 0;
                    if ( IS_IN_SYNC == 1 )
                    {
                        // check nodes are sending real headers not garbage.
                        if ( validate_headers(hdrhash) == 0 )
                        {
                            from->banscore += 1;
                            fprintf(stderr, "[%i] sent invalid header banscore.%i\n",from->nodeid, from->banscore);
                        }
                    }
                }
                break;
            case NSPV_UTXOSRESP:
                NSPV_utxosresp_purge(&NSPV_utxosresult);
                NSPV_rwutxosresp(0,&response[1],&NSPV_utxosresult);
                fprintf(stderr,"got utxos response %u size.%d\n",timestamp,len);
                break;
            case NSPV_TXIDSRESP:
                NSPV_txidsresp_purge(&NSPV_txidsresult);
                NSPV_rwtxidsresp(0,&response[1],&NSPV_txidsresult);
                fprintf(stderr,"got txids response %u size.%d %s CC.%d num.%d\n",timestamp,len,NSPV_txidsresult.coinaddr,NSPV_txidsresult.CCflag,NSPV_txidsresult.numtxids);
                break;
            case NSPV_MEMPOOLRESP:
                NSPV_mempoolresp_purge(&NSPV_mempoolresult);
                NSPV_rwmempoolresp(0,&response[1],&NSPV_mempoolresult);
                fprintf(stderr,"got mempool response %u size.%d (%s) CC.%d num.%d memfunc.%d %s/v%d\n",timestamp,len,NSPV_mempoolresult.coinaddr,NSPV_mempoolresult.CCflag,NSPV_mempoolresult.numtxids,NSPV_mempoolresult.memfunc,bits256_str(str,NSPV_mempoolresult.txid),NSPV_mempoolresult.vout);
                break;
            case NSPV_NTZSRESP:
                NSPV_ntzsresp_purge(&NSPV_ntzsresult);
                NSPV_rwntzsresp(0,&response[1],&NSPV_ntzsresult);
                if ( NSPV_ntzsresp_find(NSPV_ntzsresult.reqheight) == 0 )
                    NSPV_ntzsresp_add(&NSPV_ntzsresult);
                fprintf(stderr,"got ntzs response %u size.%d %s prev.%d, %s next.%d\n",timestamp,len,bits256_str(str,NSPV_ntzsresult.prevntz.txid),NSPV_ntzsresult.prevntz.height,bits256_str(str2,NSPV_ntzsresult.nextntz.txid),NSPV_ntzsresult.nextntz.height);
                break;
            case NSPV_NTZSPROOFRESP:
                NSPV_ntzsproofresp_purge(&NSPV_ntzsproofresult);
                NSPV_rwntzsproofresp(0,&response[1],&NSPV_ntzsproofresult);
                if ( NSPV_ntzsproof_find(NSPV_ntzsproofresult.prevtxid,NSPV_ntzsproofresult.nexttxid) == 0 )
                    NSPV_ntzsproof_add(&NSPV_ntzsproofresult);
                fprintf(stderr,"got ntzproof response %u size.%d prev.%d next.%d\n",timestamp,len,NSPV_ntzsproofresult.common.prevht,NSPV_ntzsproofresult.common.nextht);
                break;
            case NSPV_TXPROOFRESP:
                NSPV_txproof_purge(&NSPV_txproofresult);
                NSPV_rwtxproof(0,&response[1],&NSPV_txproofresult);
                // validate the notarization transaction that was fetched. 
                if ( bits256_cmp(NSPV_txproofresult.txid, NSPV_inforesult.notarization.txid) == 0 ) 
                {
                    if ( validate_notarization(NSPV_inforesult.notarization.txid, NSPV_inforesult.notarization.timestamp) != 0 )
                    {
                        NSPV_lastntz = NSPV_inforesult.notarization;
                        NSPV_hdrheight_counter = NSPV_lastntz.height;
                        reset_headers(NSPV_lastntz.height);
                        fprintf(stderr, "new notarization at height.%i\n", NSPV_lastntz.height);
                    } 
                }
                else if ( NSPV_txproof_find(NSPV_txproofresult.txid,NSPV_txproofresult.height) == 0 )
                    NSPV_txproof_add(&NSPV_txproofresult);
                fprintf(stderr,"got txproof response %u size.%d %s ht.%d\n",timestamp,len,bits256_str(str,NSPV_txproofresult.txid),NSPV_txproofresult.height);
                break;
            case NSPV_SPENTINFORESP:
                NSPV_spentinfo_purge(&NSPV_spentresult);
                NSPV_rwspentinfo(0,&response[1],&NSPV_spentresult);
                fprintf(stderr,"got spentinfo response %u size.%d\n",timestamp,len);
                break;
            case NSPV_BROADCASTRESP:
                NSPV_broadcast_purge(&NSPV_broadcastresult);
                NSPV_rwbroadcastresp(0,&response[1],&NSPV_broadcastresult);
                fprintf(stderr,"got broadcast response %u size.%d %s retcode.%d\n",timestamp,len,bits256_str(str,NSPV_broadcastresult.txid),NSPV_broadcastresult.retcode);
                break;
            default: fprintf(stderr,"unexpected response %02x size.%d at %u\n",response[0],len,timestamp);
                break;
        }
    }
}

cJSON *NSPV_getinfo_req(btc_spv_client *client,int32_t reqht)
{
    uint8_t msg[512]; int32_t i,iter,len = 1; struct NSPV_inforesp I;
    NSPV_inforesp_purge(&NSPV_inforesult);
    msg[len++] = NSPV_INFO;
    len += iguana_rwnum(1,&msg[len],sizeof(reqht),&reqht);
    for (iter=0; iter<3; iter++)
    if ( NSPV_req(client,0,msg,len,NODE_NSPV,msg[1]>>1) != 0 )
    {
        for (i=0; i<NSPV_POLLITERS; i++)
        {
            usleep(NSPV_POLLMICROS);
            if ( NSPV_inforesult.height != 0 )
                return(NSPV_getinfo_json(&NSPV_inforesult));
        }
    } else sleep(1);
    memset(&I,0,sizeof(I));
    return(NSPV_getinfo_json(&NSPV_inforesult));
}

cJSON *NSPV_getpeerinfo(btc_spv_client *client)
{
    cJSON *result = cJSON_CreateArray();
    
    size_t j;
    for ( j = 0; j < client->nodegroup->nodes->len; j++) {
        btc_node* node = vector_idx(client->nodegroup->nodes, j);
        if ( (node->state & NODE_CONNECTED) == NODE_CONNECTED )
        {
            char ipaddr[64]; cJSON *node_json = cJSON_CreateObject();
            expand_ipbits(ipaddr, (uint64_t)((struct sockaddr_in*)&node->addr)->sin_addr.s_addr );
            jaddnum(node_json,"nodeid",(int64_t)node->nodeid);
            jaddstr(node_json,"ipaddress",ipaddr);
            jaddnum(node_json,"port", (int64_t)node->nodegroup->chainparams->default_port);
            jaddnum(node_json,"lastping",(int64_t)node->lastping);
            jaddnum(node_json,"time_started_con",(int64_t)node->time_started_con);
            jaddnum(node_json,"time_last_request",(int64_t)node->time_last_request);
            jaddnum(node_json,"services",(int64_t)node->services);
            jaddnum(node_json,"missbehavescore",(int64_t)node->banscore);
            jaddnum(node_json,"bestknownheight",(int64_t)node->bestknownheight);
            if ( node->synced == 0 )
                jaddstr(node_json,"in_sync", "not_synced");
            else if ( IS_IN_SYNC == 1 )
                jaddstr(node_json,"in_sync", "synced");
            jaddi(result,node_json);     
        }
    }
    return(result);
}

cJSON *NSPV_gettransaction2(btc_spv_client *client,bits256 txid,int32_t v,int32_t height)
{
    int32_t retval = 0, isKMD, skipvalidation = 0; int64_t extradata = 0; int64_t rewardsum = 0; 
    cJSON *result = cJSON_CreateObject();
    isKMD = (strcmp(client->chainparams->name,"KMD") == 0);
    if ( height < 1 )
        height = NSPV_inforesult.height;
    v = 0;
    btc_tx* tx = NSPV_gettransaction(client,&retval,isKMD,skipvalidation,v,txid,height,extradata,NSPV_tiptime,&rewardsum);
    cstring *txhex = btc_tx_to_cstr(tx);
    jaddstr(result, "hex", txhex->str);
    jaddnum(result, "retcode", (int64_t)retval);
    if (rewardsum > 0 )
        jaddnum(result, "rewards", (int64_t)rewardsum);
    return(result);
}

uint32_t NSPV_blocktime(btc_spv_client *client,int32_t hdrheight)
{
    uint32_t timestamp; struct NSPV_inforesp old = NSPV_inforesult;
    if ( hdrheight > 0 )
    {
        NSPV_getinfo_req(client,hdrheight);
        if ( NSPV_inforesult.hdrheight == hdrheight )
        {
            timestamp = NSPV_inforesult.H.nTime;
            NSPV_inforesult = old;
            //fprintf(stderr,"NSPV_blocktime ht.%d -> t%u\n",hdrheight,timestamp);
            return(timestamp);
        }
    }
    NSPV_inforesult = old;
    return(0);
}

cJSON *NSPV_addressutxos(btc_spv_client *client,char *coinaddr,int32_t CCflag,int32_t skipcount,int32_t filter)
{
    cJSON *result = cJSON_CreateObject(); uint8_t msg[512]; int32_t i,iter,slen,len = 1; size_t sz;
    //fprintf(stderr,"utxos %s NSPV addr %s\n",coinaddr,NSPV_address.c_str());
    //if ( NSPV_utxosresult.nodeheight >= NSPV_inforesult.height && strcmp(coinaddr,NSPV_utxosresult.coinaddr) == 0 && CCflag == NSPV_utxosresult.CCflag && skipcount == NSPV_utxosresult.skipcount && filter == NSPV_utxosresult.filter )
    //    return(NSPV_utxosresp_json(&NSPV_utxosresult));
    if ( skipcount < 0 )
        skipcount = 0;
    NSPV_utxosresp_purge(&NSPV_utxosresult);
    if ( (sz= btc_base58_decode_check(coinaddr,msg,sizeof(msg))) != 25 )
    //if ( bitcoin_base58decode(msg,coinaddr) != 25 )
    {
        jaddstr(result,"result","error");
        jaddstr(result,"error","invalid address");
        jaddnum(result,"addrlen",(int64_t)sz);
        jaddstr(result,"lastpeer",NSPV_lastpeer);
        return(result);
    }
    slen = (int32_t)strlen(coinaddr);
    msg[len++] = NSPV_UTXOS;
    msg[len++] = slen;
    memcpy(&msg[len],coinaddr,slen), len += slen;
    msg[len++] = (CCflag != 0);
    len += iguana_rwnum(1,&msg[len],sizeof(skipcount),&skipcount);
    len += iguana_rwnum(1,&msg[len],sizeof(filter),&filter);
    for (iter=0; iter<3; iter++)
    if ( NSPV_req(client,0,msg,len,NODE_ADDRINDEX,msg[1]>>1) != 0 )
    {
        for (i=0; i<NSPV_POLLITERS; i++)
        {
            usleep(NSPV_POLLMICROS);
            if ( (NSPV_inforesult.height == 0 || NSPV_utxosresult.nodeheight >= NSPV_inforesult.height) && strcmp(coinaddr,NSPV_utxosresult.coinaddr) == 0 && CCflag == NSPV_utxosresult.CCflag )
                return(NSPV_utxosresp_json(&NSPV_utxosresult));
        }
    } else sleep(1);
    jaddstr(result,"result","error");
    jaddstr(result,"error","timeout");
    jaddstr(result,"lastpeer",NSPV_lastpeer);
    return(result);
}

cJSON *NSPV_addresstxids(btc_spv_client *client,char *coinaddr,int32_t CCflag,int32_t skipcount,int32_t filter)
{
    cJSON *result = cJSON_CreateObject(); size_t sz; uint8_t msg[512]; int32_t i,iter,slen,len = 1;
    if ( NSPV_txidsresult.nodeheight >= NSPV_inforesult.height && strcmp(coinaddr,NSPV_txidsresult.coinaddr) == 0 && CCflag == NSPV_txidsresult.CCflag && skipcount == NSPV_txidsresult.skipcount )
        return(NSPV_txidsresp_json(&NSPV_txidsresult));
    if ( skipcount < 0 )
        skipcount = 0;
    NSPV_txidsresp_purge(&NSPV_txidsresult);
    if ( (sz= btc_base58_decode_check(coinaddr,msg,sizeof(msg))) != 25 )
    //if ( btc_base58_decode((void *)msg,&sz,coinaddr) == 0 || sz != 25 )
    //if ( bitcoin_base58decode(msg,coinaddr) != 25 )
    {
        jaddstr(result,"result","error");
        jaddstr(result,"error","invalid address");
        jaddnum(result,"addrlen",(int64_t)sz);
        jaddstr(result,"lastpeer",NSPV_lastpeer);
        return(result);
    }
    slen = (int32_t)strlen(coinaddr);
    msg[len++] = NSPV_TXIDS;
    msg[len++] = slen;
    memcpy(&msg[len],coinaddr,slen), len += slen;
    msg[len++] = (CCflag != 0);
    len += iguana_rwnum(1,&msg[len],sizeof(skipcount),&skipcount);
    len += iguana_rwnum(1,&msg[len],sizeof(filter),&filter);
    //fprintf(stderr,"skipcount.%d\n",skipcount);
    for (iter=0; iter<3; iter++)
    if ( NSPV_req(client,0,msg,len,NODE_ADDRINDEX,msg[1]>>1) != 0 )
    {
        for (i=0; i<NSPV_POLLITERS; i++)
        {
            usleep(NSPV_POLLMICROS);
            if ( (NSPV_inforesult.height == 0 || NSPV_txidsresult.nodeheight >= NSPV_inforesult.height) && strcmp(coinaddr,NSPV_txidsresult.coinaddr) == 0 && CCflag == NSPV_txidsresult.CCflag )
                return(NSPV_txidsresp_json(&NSPV_txidsresult));
        }
    } else sleep(1);
    jaddstr(result,"result","error");
    jaddstr(result,"error","timeout");
    jaddstr(result,"lastpeer",NSPV_lastpeer);
    return(result);
}

cJSON *NSPV_mempooltxids(btc_spv_client *client,char *coinaddr,int32_t CCflag,uint8_t memfunc,bits256 txid,int32_t vout)
{
    cJSON *result = cJSON_CreateObject(); size_t sz; uint8_t msg[512]; char str[65],zeroes[64]; int32_t i,iter,slen,len = 1;
    NSPV_mempoolresp_purge(&NSPV_mempoolresult);
    memset(zeroes,0,sizeof(zeroes));
    if ( coinaddr == 0 )
        coinaddr = zeroes;
    if ( coinaddr[0] != 0 && (sz= btc_base58_decode_check(coinaddr,msg,sizeof(msg))) != 25 )
    {
        jaddstr(result,"result","error");
        jaddstr(result,"error","invalid address");
        jaddnum(result,"addrlen",(int64_t)sz);
        jaddstr(result,"lastpeer",NSPV_lastpeer);
        return(result);
    }
    msg[len++] = NSPV_MEMPOOL;
    msg[len++] = (CCflag != 0);
    len += iguana_rwnum(1,&msg[len],sizeof(memfunc),&memfunc);
    len += iguana_rwnum(1,&msg[len],sizeof(vout),&vout);
    len += iguana_rwbignum(1,&msg[len],sizeof(txid),(uint8_t *)&txid);
    slen = (int32_t)strlen(coinaddr);
    msg[len++] = slen;
    memcpy(&msg[len],coinaddr,slen), len += slen;
    fprintf(stderr,"(%s) func.%d CC.%d %s/v%d len.%d\n",coinaddr,memfunc,CCflag,bits256_str(str,txid),vout,len);
    for (iter=0; iter<3; iter++)
    if ( NSPV_req(client,0,msg,len,NODE_NSPV,msg[1]>>1) != 0 )
    {
        for (i=0; i<NSPV_POLLITERS; i++)
        {
            usleep(NSPV_POLLMICROS);
            if ( NSPV_mempoolresult.nodeheight >= NSPV_inforesult.height && strcmp(coinaddr,NSPV_mempoolresult.coinaddr) == 0 && CCflag == NSPV_mempoolresult.CCflag && memcmp(&txid,&NSPV_mempoolresult.txid,sizeof(txid)) == 0 && vout == NSPV_mempoolresult.vout && memfunc == NSPV_mempoolresult.memfunc )
                return(NSPV_mempoolresp_json(&NSPV_mempoolresult));
        }
    } else sleep(1);
    jaddstr(result,"result","error");
    jaddstr(result,"error","timeout");
    jaddstr(result,"lastpeer",NSPV_lastpeer);
    return(result);
}

int32_t NSPV_coinaddr_inmempool(btc_spv_client *client,char const *logcategory,char *coinaddr,uint8_t CCflag)
{
    NSPV_mempooltxids(client,coinaddr,CCflag,NSPV_MEMPOOL_ADDRESS,zeroid,-1);
    if ( NSPV_mempoolresult.txids != 0 && NSPV_mempoolresult.numtxids >= 1 && strcmp(NSPV_mempoolresult.coinaddr,coinaddr) == 0 && NSPV_mempoolresult.CCflag == CCflag )
    {
        fprintf(stderr,"found (%s) vout in mempool\n",coinaddr);
        if ( logcategory != 0 )
        {
            // add to logfile
        }
        return(true);
    } else return(false);
}

bool NSPV_spentinmempool(btc_spv_client *client,bits256 *spenttxidp,int32_t *spentvinip,bits256 txid,int32_t vout)
{
    NSPV_mempooltxids(client,(char *)"",0,NSPV_MEMPOOL_ISSPENT,txid,vout);
    if ( NSPV_mempoolresult.txids != 0 && NSPV_mempoolresult.numtxids == 1 && memcmp(&NSPV_mempoolresult.txid,&txid,sizeof(txid)) == 0 )
    {
        *spenttxidp = NSPV_mempoolresult.txids[0];
        *spentvinip = NSPV_mempoolresult.vindex;
        return(true);
    }
    *spentvinip = -1;
    memset(spenttxidp,0,sizeof(*spenttxidp));
    return(false);
}

bool NSPV_inmempool(btc_spv_client *client,bits256 txid)
{
    NSPV_mempooltxids(client,(char *)"",0,NSPV_MEMPOOL_INMEMPOOL,txid,0);
    if ( NSPV_mempoolresult.txids != 0 && NSPV_mempoolresult.numtxids == 1 && memcmp(&NSPV_mempoolresult.txids[0],&txid,sizeof(txid)) == 0 )
        return(true);
    else return(false);
}

bool NSPV_evalcode_inmempool(btc_spv_client *client,uint8_t evalcode,uint8_t memfunc)
{
    int32_t vout;
    vout = ((uint32_t)memfunc << 8) | evalcode;
    NSPV_mempooltxids(client,(char *)"",1,NSPV_MEMPOOL_CCEVALCODE,zeroid,vout);
    if ( NSPV_mempoolresult.txids != 0 && NSPV_mempoolresult.numtxids >= 1 && NSPV_mempoolresult.vout == vout )
        return(true);
    else return(false);
}

cJSON *NSPV_notarizations(btc_spv_client *client,int32_t reqheight)
{
    uint8_t msg[512]; int32_t i,iter,len = 1; struct NSPV_ntzsresp N,*ptr;
    if ( (ptr= NSPV_ntzsresp_find(reqheight)) != 0 )
    {
        fprintf(stderr,"FROM CACHE NSPV_notarizations.%d\n",reqheight);
        NSPV_ntzsresp_purge(&NSPV_ntzsresult);
        NSPV_ntzsresp_copy(&NSPV_ntzsresult,ptr);
        return(NSPV_ntzsresp_json(ptr));
    }
    msg[len++] = NSPV_NTZS;
    len += iguana_rwnum(1,&msg[len],sizeof(reqheight),&reqheight);
    for (iter=0; iter<3; iter++)
    if ( NSPV_req(client,0,msg,len,NODE_NSPV,msg[1]>>1) != 0 )
    {
        for (i=0; i<NSPV_POLLITERS; i++)
        {
            usleep(NSPV_POLLMICROS);
            if ( NSPV_ntzsresult.reqheight == reqheight )
                return(NSPV_ntzsresp_json(&NSPV_ntzsresult));
        }
    } else sleep(1);
    memset(&N,0,sizeof(N));
    return(NSPV_ntzsresp_json(&N));
}

cJSON *NSPV_txidhdrsproof(btc_spv_client *client,bits256 prevtxid,bits256 nexttxid)
{
    uint8_t msg[512]; int32_t i,iter,len = 1; struct NSPV_ntzsproofresp P,*ptr;
    if ( (ptr= NSPV_ntzsproof_find(prevtxid,nexttxid)) != 0 )
    {
        NSPV_ntzsproofresp_purge(&NSPV_ntzsproofresult);
        NSPV_ntzsproofresp_copy(&NSPV_ntzsproofresult,ptr);
        return(NSPV_ntzsproof_json(ptr));
    }
    NSPV_ntzsproofresp_purge(&NSPV_ntzsproofresult);
    msg[len++] = NSPV_NTZSPROOF;
    len += iguana_rwbignum(1,&msg[len],sizeof(prevtxid),(uint8_t *)&prevtxid);
    len += iguana_rwbignum(1,&msg[len],sizeof(nexttxid),(uint8_t *)&nexttxid);
    for (iter=0; iter<3; iter++)
    if ( NSPV_req(client,0,msg,len,NODE_NSPV,msg[1]>>1) != 0 )
    {
        for (i=0; i<NSPV_POLLITERS; i++)
        {
            usleep(NSPV_POLLMICROS);
            if ( memcmp(&NSPV_ntzsproofresult.prevtxid,&prevtxid,sizeof(prevtxid)) == 0 && memcmp(&NSPV_ntzsproofresult.nexttxid,&nexttxid,sizeof(nexttxid)) == 0 )
                return(NSPV_ntzsproof_json(&NSPV_ntzsproofresult));
        }
    } else sleep(1);
    fprintf(stderr,"timeout hdrsproof\n");
    memset(&P,0,sizeof(P));
    return(NSPV_ntzsproof_json(&P));
}

cJSON *NSPV_hdrsproof(btc_spv_client *client,int32_t prevht,int32_t nextht)
{
    bits256 prevtxid,nexttxid;
    NSPV_notarizations(client,prevht);
    prevtxid = NSPV_ntzsresult.prevntz.txid;
    NSPV_notarizations(client,nextht);
    nexttxid = NSPV_ntzsresult.nextntz.txid;
    return(NSPV_txidhdrsproof(client,prevtxid,nexttxid));
}

cJSON *NSPV_txproof(btc_spv_client *client,int32_t vout,bits256 txid,int32_t height)
{
    uint8_t msg[512]; char str[65]; int32_t i,iter,len = 1; struct NSPV_txproof P,*ptr;
    if ( height > 0 && (ptr= NSPV_txproof_find(txid,height)) != 0 )
    {
        fprintf(stderr,"FROM CACHE NSPV_txproof %s\n",bits256_str(str,txid));
        NSPV_txproof_purge(&NSPV_txproofresult);
        NSPV_txproof_copy(&NSPV_txproofresult,ptr);
        return(NSPV_txproof_json(ptr));
    }
    NSPV_txproof_purge(&NSPV_txproofresult);
    msg[len++] = NSPV_TXPROOF;
    len += iguana_rwnum(1,&msg[len],sizeof(height),&height);
    len += iguana_rwnum(1,&msg[len],sizeof(vout),&vout);
    len += iguana_rwbignum(1,&msg[len],sizeof(txid),(uint8_t *)&txid);
    //fprintf(stderr,"req txproof %s/v%d at height.%d\n",bits256_str(str,txid),vout,height);
    if ( height == -1 )
    {
        NSPV_req(client,0,msg,len,NODE_NSPV,msg[1]>>1);
        return(0);
    }
    for (iter=0; iter<3; iter++)
    if ( NSPV_req(client,0,msg,len,NODE_NSPV,msg[1]>>1) != 0 )
    {
        for (i=0; i<NSPV_POLLITERS; i++)
        {
            usleep(NSPV_POLLMICROS);
            if ( memcmp(&NSPV_txproofresult.txid,&txid,sizeof(txid)) == 0 )
                return(NSPV_txproof_json(&NSPV_txproofresult));
        }
    } else sleep(1);
    fprintf(stderr,"txproof timeout\n");
    memset(&P,0,sizeof(P));
    return(NSPV_txproof_json(&P));
}

cJSON *NSPV_spentinfo(btc_spv_client *client,bits256 txid,int32_t vout)
{
    uint8_t msg[512]; int32_t i,iter,len = 1; struct NSPV_spentinfo I;
    NSPV_spentinfo_purge(&NSPV_spentresult);
    msg[len++] = NSPV_SPENTINFO;
    len += iguana_rwnum(1,&msg[len],sizeof(vout),&vout);
    len += iguana_rwbignum(1,&msg[len],sizeof(txid),(uint8_t *)&txid);
    for (iter=0; iter<3; iter++)
    if ( NSPV_req(client,0,msg,len,NODE_SPENTINDEX,msg[1]>>1) != 0 )
    {
        for (i=0; i<NSPV_POLLITERS; i++)
        {
            usleep(NSPV_POLLMICROS);
            if ( memcmp(&NSPV_spentresult.txid,&txid,sizeof(txid)) == 0 && NSPV_spentresult.vout == vout )
                return(NSPV_spentinfo_json(&NSPV_spentresult));
        }
    } else sleep(1);
    memset(&I,0,sizeof(I));
    return(NSPV_spentinfo_json(&I));
}

cJSON *NSPV_broadcast(btc_spv_client *client,char *hex)
{
    uint8_t *msg,*data; bits256 txid; int32_t i,n,iter,len = 3; struct NSPV_broadcastresp B;
    NSPV_broadcast_purge(&NSPV_broadcastresult);
    n = (int32_t)strlen(hex) >> 1;
    data = (uint8_t *)malloc(n);
    decode_hex(data,n,hex);
    txid = bits256_doublesha256(data,n);
    msg = (uint8_t *)malloc(3 + sizeof(txid) + sizeof(n) + n);
    msg[0] = msg[1] = msg[2] = 0;
    msg[len++] = NSPV_BROADCAST;
    len += iguana_rwbignum(1,&msg[len],sizeof(txid),(uint8_t *)&txid);
    len += iguana_rwnum(1,&msg[len],sizeof(n),&n);
    memcpy(&msg[len],data,n), len += n;
    free(data);
    for (iter=0; iter<3; iter++)
    if ( NSPV_req(client,0,msg,len,NODE_NSPV,NSPV_BROADCAST>>1) != 0 )
    {
        for (i=0; i<NSPV_POLLITERS; i++)
        {
            usleep(NSPV_POLLMICROS);
            if ( memcmp(&NSPV_broadcastresult.txid,&txid,sizeof(txid)) == 0 )
            {
                free(msg);
                return(NSPV_broadcast_json(&NSPV_broadcastresult,txid));
            }
        }
    } else sleep(1);
    free(msg);
    memset(&B,0,sizeof(B));
    B.retcode = -2;
    return(NSPV_broadcast_json(&B,txid));
}

cJSON *NSPV_login(const btc_chainparams *chain,char *wifstr)
{
    cJSON *result = cJSON_CreateObject(); char coinaddr[64]; uint8_t data[128]; int32_t valid = 0; size_t sz=0,sz2;
    NSPV_logout();
    if ( strlen(wifstr) < 64 && (sz= btc_base58_decode_check(wifstr,data,sizeof(data))) > 0 && ((sz == 38 && data[sz-5] == 1) || (sz == 37 && data[sz-5] != 1)) )
        valid = 1;
    if ( valid == 0 || data[0] != chain->b58prefix_secret_address )
    {
        jaddstr(result,"result","error");
        jaddstr(result,"error","invalid wif");
        jaddnum(result,"len",(int64_t)sz);
        jaddnum(result,"wifprefix",(int64_t)data[0]);
        jaddnum(result,"expected",(int64_t)chain->b58prefix_secret_address);
        return(result);
    }
    memset(NSPV_wifstr,0,sizeof(NSPV_wifstr));
    NSPV_logintime = (uint32_t)time(NULL);
    if ( strcmp(NSPV_wifstr,wifstr) != 0 )
    {
        strncpy(NSPV_wifstr,wifstr,sizeof(NSPV_wifstr)-1);
        if ( btc_privkey_decode_wif(NSPV_wifstr,chain,&NSPV_key) == 0 )
            jaddstr(result,"wiferror","couldnt decode wif");
    }
    jaddstr(result,"result","success");
    jaddstr(result,"status","wif will expire in 777 seconds");
    btc_pubkey_from_key(&NSPV_key,&NSPV_pubkey);
    sz2 = sizeof(NSPV_pubkeystr);
    btc_pubkey_get_hex(&NSPV_pubkey,NSPV_pubkeystr,&sz2);
    btc_pubkey_getaddr_p2pkh(&NSPV_pubkey,chain,NSPV_address);
    jaddstr(result,"address",NSPV_address);
    jaddstr(result,"pubkey",NSPV_pubkeystr);
    jaddnum(result,"wifprefix",(int64_t)data[0]);
    jaddnum(result,"compressed",(int64_t)(data[sz-5] == 1));
    memset(data,0,sizeof(data));
    return(result);
}

cJSON *NSPV_getnewaddress(const btc_chainparams *chain)
{
    cJSON *result = cJSON_CreateObject(); size_t sz; btc_key key; btc_pubkey pubkey; char address[64],pubkeystr[67],wifstr[100];
    btc_random_bytes(key.privkey,32,0);
    btc_pubkey_from_key(&key,&pubkey);
    sz = sizeof(pubkeystr);
    btc_pubkey_get_hex(&pubkey,pubkeystr,&sz);
    btc_pubkey_getaddr_p2pkh(&pubkey,chain,address);
    sz = sizeof(wifstr);
    btc_privkey_encode_wif(&key,chain,wifstr,&sz);
    jaddstr(result,"wif",wifstr);
    jaddstr(result,"address",address);
    jaddstr(result,"pubkey",pubkeystr);
    jaddnum(result,"wifprefix",chain->b58prefix_secret_address);
    jaddnum(result,"compressed",1);
    return(result);
}

#define NSPV_STR 1
#define NSPV_INT 2
#define NSPV_UINT 3
#define NSPV_HASH 4
#define NSPV_FLOAT 5

struct NSPV_arginfo { char field[63]; uint8_t type; };

struct NSPV_methodarg
{
    char method[64];
    struct NSPV_arginfo args[8];
};

struct NSPV_methodarg NSPV_methods[] =
{
    { "stop", { "", 0 } },
    { "help", { "", 0 } },
    { "logout", { "", 0 } },
    { "getnewaddress", { "", 0 } },
    { "getpeerinfo", { "", 0 } },
    { "login", { { "wif", NSPV_STR } } },
    { "broadcast", { { "hex", NSPV_STR } } },
    { "listunspent", { { "address", NSPV_STR }, { "isCC", NSPV_UINT }, { "skipcount", NSPV_UINT }, { "filter", NSPV_UINT } } },
    { "listtransactions", { { "address", NSPV_STR }, { "isCC", NSPV_UINT }, { "skipcount", NSPV_UINT }, { "filter", NSPV_UINT } } },
    { "notarizations", { { "height", NSPV_UINT } } },
    { "hdrsproof", { { "prevheight", NSPV_UINT }, { "nextheight", NSPV_UINT } } },
    { "getinfo", { { "hdrheight", NSPV_UINT } } },
    { "txproof", { { "txid", NSPV_HASH }, { "vout", NSPV_UINT }, { "height", NSPV_UINT } } },
    { "spentinfo", { { "txid", NSPV_HASH }, { "vout", NSPV_UINT } } },
    { "spend", { { "address", NSPV_STR }, { "amount", NSPV_FLOAT } } },
    { "mempool", { { "address", NSPV_STR }, { "isCC", NSPV_UINT }, { "memfunc", NSPV_UINT }, { "txid", NSPV_HASH }, { "vout", NSPV_UINT }, { "evalcode", NSPV_UINT }, { "CCfunc", NSPV_UINT }, } },
    { "faucetget", { "", 0 } },
    { "gettransaction", { { "txid", NSPV_HASH }, { "vout", NSPV_UINT }, { "height", NSPV_UINT } } },
};

cJSON *NSPV_helpitem(struct NSPV_methodarg *ptr)
{
    int32_t i; char *str; cJSON *item = cJSON_CreateObject(),*obj,*array = cJSON_CreateArray();
    jaddstr(item,"method",ptr->method);
    for (i=0; i<(int32_t)(sizeof(ptr->args)/sizeof(*ptr->args)); i++)
    {
        if ( ptr->args[i].field[0] == 0 )
            break;
        obj = cJSON_CreateObject();
        switch ( ptr->args[i].type )
        {
            case NSPV_STR:
                jaddstr(obj,ptr->args[i].field,"string");
                break;
            case NSPV_INT:
                jaddstr(obj,ptr->args[i].field,"int32_t");
                break;
            case NSPV_UINT:
                jaddstr(obj,ptr->args[i].field,"uint32_t");
                break;
            case NSPV_HASH:
                jaddstr(obj,ptr->args[i].field,"hash");
                break;
            case NSPV_FLOAT:
                jaddstr(obj,ptr->args[i].field,"float");
                break;
        }
        jaddi(array,obj);
    }
    jadd(item,"fields",array);
    return(item);
}

cJSON *NSPV_help()
{
    int32_t i; cJSON *retjson = cJSON_CreateObject(),*array = cJSON_CreateArray();
    jaddstr(retjson,"result","success");
    for (i=0; i<(int32_t)(sizeof(NSPV_methods)/sizeof(*NSPV_methods)); i++)
        jaddi(array,NSPV_helpitem(&NSPV_methods[i]));
    jadd(retjson,"methods",array);
    jaddnum(retjson,"num",sizeof(NSPV_methods)/sizeof(*NSPV_methods));
    return(retjson);
}

void NSPV_argjson_addfields(char *method,cJSON *argjson,cJSON *params)
{
    int32_t i,j,n,m;
    for (i=0; i<(int32_t)(sizeof(NSPV_methods)/sizeof(*NSPV_methods)); i++)
    {
        if ( strcmp(method,NSPV_methods[i].method) == 0 )
        {
            for (j=0; j<(int32_t)(sizeof(NSPV_methods[i].args)/sizeof(*NSPV_methods[i].args)); j++)
                if ( NSPV_methods[i].args[j].field[0] == 0 )
                    break;
            n = j;
            m = cJSON_GetArraySize(params);
            for (j=0; j<n; j++)
            {
                switch ( NSPV_methods[i].args[j].type )
                {
                    case NSPV_STR:
                        if ( j >= m )
                            jaddstr(argjson,NSPV_methods[i].args[j].field,"");
                        else jaddstr(argjson,NSPV_methods[i].args[j].field,jstri(params,j));
                        break;
                    case NSPV_INT:
                        if ( j >= m )
                            jaddnum(argjson,NSPV_methods[i].args[j].field,0);
                        else jaddnum(argjson,NSPV_methods[i].args[j].field,jinti(params,j));
                        break;
                   case NSPV_UINT:
                        if ( j >= m )
                            jaddnum(argjson,NSPV_methods[i].args[j].field,0);
                        else jaddnum(argjson,NSPV_methods[i].args[j].field,juinti(params,j));
                        break;
                    case NSPV_HASH:
                        if ( j >= m )
                            jaddbits256(argjson,NSPV_methods[i].args[j].field,zeroid);
                        else jaddbits256(argjson,NSPV_methods[i].args[j].field,jbits256i(params,j));
                        break;
                    case NSPV_FLOAT:
                        if ( j >= m )
                            jaddnum(argjson,NSPV_methods[i].args[j].field,0);
                        else jaddnum(argjson,NSPV_methods[i].args[j].field,jdoublei(params,j));
                        break;
                }
            }
        }
    }
    fprintf(stderr,"new argjson.(%s)\n",jprint(argjson,0));
}

cJSON *_NSPV_JSON(cJSON *argjson)
{
    char *method; bits256 txid; int64_t satoshis; char *symbol,*coinaddr,*wifstr,*hex; int32_t vout,prevheight,nextheight,skipcount,height,hdrheight,numargs; uint8_t CCflag,memfunc; cJSON *params;
    if ( (method= jstr(argjson,"method")) == 0 )
        return(cJSON_Parse("{\"error\":\"no method\"}"));
    else if ( (symbol= jstr(argjson,"coin")) != 0 && strcmp(symbol,NSPV_symbol) != 0 )
        return(cJSON_Parse("{\"error\":\"wrong coin\"}"));
    else if ( strcmp("stop",method) == 0 )
    {
        NSPV_STOP_RECEIVED = (uint32_t)time(NULL);
        btc_node_group_shutdown(NSPV_client->nodegroup);
        fprintf(stderr,"shutdown started\n");
        return(cJSON_Parse("{\"result\":\"success\"}"));
    }
    else if ( strcmp("help",method) == 0 )
        return(NSPV_help());
    if ( (params= jarray(&numargs,argjson,"params")) != 0 )
        NSPV_argjson_addfields(method,argjson,params);
    txid = jbits256(argjson,"txid");
    vout = jint(argjson,"vout");
    height = jint(argjson,"height");
    hdrheight = jint(argjson,"hdrheight");
    CCflag = jint(argjson,"isCC");
    memfunc = jint(argjson,"memfunc");
    skipcount = jint(argjson,"skipcount");
    prevheight = jint(argjson,"prevheight");
    nextheight = jint(argjson,"nextheight");
    hex = jstr(argjson,"hex");
    wifstr = jstr(argjson,"wif");
    coinaddr = jstr(argjson,"address");
    satoshis = jdouble(argjson,"amount")*COIN + 0.0000000049;
    if ( strcmp(method,"getinfo") == 0 )
        return(NSPV_getinfo_req(NSPV_client,hdrheight));
    else if ( strcmp(method, "getpeerinfo") == 0 )
        return(NSPV_getpeerinfo(NSPV_client));
    else if ( strcmp(method, "gettransaction") == 0 )
    {
        if ( vout < 0 || memcmp(&zeroid,&txid,sizeof(txid)) == 0 )
            return(cJSON_Parse("{\"error\":\"invalid utxo\"}"));
        return(NSPV_gettransaction2(NSPV_client, txid, vout, height));
    }
    else if ( strcmp(method,"logout") == 0 )
    {
        NSPV_logout();
        return(cJSON_Parse("{\"result\":\"success\"}"));
    }
    else if ( strcmp(method,"login") == 0 )
    {
        if ( wifstr == 0 )
            return(cJSON_Parse("{\"error\":\"no wif\"}"));
        else return(NSPV_login(NSPV_chain,wifstr));
    }
    else if ( strcmp(method,"getnewaddress") == 0 )
        return(NSPV_getnewaddress(NSPV_chain));
    else if ( strcmp(method,"broadcast") == 0 )
    {
        if ( hex == 0 )
            return(cJSON_Parse("{\"error\":\"no hex\"}"));
        else return(NSPV_broadcast(NSPV_client,hex));
    }
    else if ( strcmp(method,"listunspent") == 0 )
    {
        if ( coinaddr == 0 )
            coinaddr = NSPV_address;
        return(NSPV_addressutxos(NSPV_client,coinaddr,CCflag,skipcount,0));
    }
    else if ( strcmp(method,"listtransactions") == 0 )
    {
        if ( coinaddr == 0 )
            coinaddr = NSPV_address;
        return(NSPV_addresstxids(NSPV_client,coinaddr,CCflag,skipcount,0));
    }
    else if ( strcmp(method,"notarizations") == 0 )
    {
        if ( height == 0 )
            return(cJSON_Parse("{\"error\":\"no height\"}"));
        else return(NSPV_notarizations(NSPV_client,height));
    }
    else if ( strcmp(method,"hdrsproof") == 0 )
    {
        if ( prevheight > nextheight || nextheight == 0 || (nextheight-prevheight) > 1440 )
            return(cJSON_Parse("{\"error\":\"invalid height range\"}"));
        else return(NSPV_hdrsproof(NSPV_client,prevheight,nextheight));
    }
    else if ( strcmp(method,"txproof") == 0 )
    {
        if ( vout < 0 || memcmp(&zeroid,&txid,sizeof(txid)) == 0 )
            return(cJSON_Parse("{\"error\":\"invalid utxo\"}"));
        else return(NSPV_txproof(NSPV_client,vout,txid,height));
    }
    else if ( strcmp(method,"spentinfo") == 0 )
    {
        if ( vout < 0 || memcmp(&zeroid,&txid,sizeof(txid)) == 0 )
            return(cJSON_Parse("{\"error\":\"invalid utxo\"}"));
        else return(NSPV_spentinfo(NSPV_client,txid,vout));
    }
    else if ( strcmp(method,"spend") == 0 )
    {
        if ( satoshis < 1000 || coinaddr == 0 )
            return(cJSON_Parse("{\"error\":\"invalid address or amount too small\"}"));
        else return(NSPV_spend(NSPV_client,NSPV_address,coinaddr,satoshis));
    }
    else if ( strcmp(method,"mempool") == 0 )
    {
        if ( memfunc == NSPV_MEMPOOL_CCEVALCODE )
        {
            uint8_t e,f;
            e = juint(argjson,"evalcode");
            f = juint(argjson,"CCfunc");
            vout = ((uint16_t)f << 8) | e;
        }
        return(NSPV_mempooltxids(NSPV_client,coinaddr,CCflag,memfunc,txid,vout));
    }
    else if ( strcmp(method,"faucetget") == 0 )
        return(NSPV_CC_faucetget());
    else return(cJSON_Parse("{\"error\":\"invalid method\"}"));
}

char *NSPV_JSON(cJSON *argjson,char *remoteaddr,uint16_t port) // from rpc port
{
    char *retstr; cJSON *retjson;
    if ( strcmp(remoteaddr,"127.0.0.1") != 0 || port == 0 )
        fprintf(stderr,"remoteaddr %s:%u\n",remoteaddr,port);
    if ( (retjson= _NSPV_JSON(argjson)) != 0 )
        retstr = jprint(retjson,1);
    else retstr = clonestr("{\"error\":\"unparseable retjson\"}");
    return(retstr);
}

#endif // KOMODO_NSPVSUPERLITE_H
