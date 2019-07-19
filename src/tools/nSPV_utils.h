
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

#ifndef NSPV_UTILS_H
#define NSPV_UTILS_H

void vcalc_sha256(char deprecated[(256 >> 3) * 2 + 1],uint8_t hash[256 >> 3],uint8_t *src,int32_t len)
{
    struct sha256_vstate md;
    sha256_vinit(&md);
    sha256_vprocess(&md,src,len);
    sha256_vdone(&md,hash);
}

bits256 bits256_doublesha256(char *deprecated,uint8_t *data,int32_t datalen)
{
    bits256 hash,hash2; int32_t i;
    vcalc_sha256(0,hash.bytes,data,datalen);
    vcalc_sha256(0,hash2.bytes,hash.bytes,sizeof(hash));
    for (i=0; i<sizeof(hash); i++)
        hash.bytes[i] = hash2.bytes[sizeof(hash) - 1 - i];
    return(hash);
}

uint256 NSPV_doublesha256(uint8_t *data,int32_t datalen)
{
    bits256 _hash; uint256 hash; int32_t i;
    _hash = bits256_doublesha256(0,data,datalen);
    for (i=0; i<32; i++)
        ((uint8_t *)&hash)[i] = _hash.bytes[31 - i];
    return(hash);
}

uint256 NSPV_hdrhash(struct NSPV_equihdr *hdr)
{
    CBlockHeader block;
    block.nVersion = hdr->nVersion;
    block.hashPrevBlock = hdr->hashPrevBlock;
    block.hashMerkleRoot = hdr->hashMerkleRoot;
    block.hashFinalSaplingRoot = hdr->hashFinalSaplingRoot;
    block.nTime = hdr->nTime;
    block.nBits = hdr->nBits;
    block.nNonce = hdr->nNonce;
    block.nSolution.resize(sizeof(hdr->nSolution));
    memcpy(&block.nSolution[0],hdr->nSolution,sizeof(hdr->nSolution));
    return(block.GetHash());
}

int32_t NSPV_txextract(CTransaction &tx,uint8_t *data,int32_t datalen)
{
    std::vector<uint8_t> rawdata;
    if ( datalen < MAX_TX_SIZE_AFTER_SAPLING )
    {
        rawdata.resize(datalen);
        memcpy(&rawdata[0],data,datalen);
        if ( DecodeHexTx(tx,HexStr(rawdata)) != 0 )
            return(0);
    }
    return(-1);
}

bool NSPV_SignTx(CMutableTransaction &mtx,int32_t vini,int64_t utxovalue,const CScript scriptPubKey,uint32_t nTime);

int32_t NSPV_fastnotariescount(CTransaction tx,uint8_t elected[64][33],uint32_t nTime)
{
    CPubKey pubkeys[64]; uint8_t sig[512]; CScript scriptPubKeys[64]; CMutableTransaction mtx(tx); int32_t vini,j,siglen,retval; uint64_t mask = 0; char *str; std::vector<std::vector<unsigned char>> vData;
    for (j=0; j<64; j++)
    {
        pubkeys[j] = buf2pk(elected[j]);
        scriptPubKeys[j] = (CScript() << ParseHex(HexStr(pubkeys[j])) << OP_CHECKSIG);
        //fprintf(stderr,"%d %s\n",j,HexStr(pubkeys[j]).c_str());
    }
    fprintf(stderr,"txid %s\n",tx.GetHash().GetHex().c_str());
    //for (vini=0; vini<tx.vin.size(); vini++)
    //    mtx.vin[vini].scriptSig.resize(0);
    for (vini=0; vini<tx.vin.size(); vini++)
    {
        CScript::const_iterator pc = tx.vin[vini].scriptSig.begin();
        if ( tx.vin[vini].scriptSig.GetPushedData(pc,vData) != 0 )
        {
            vData[0].pop_back();
            for (j=0; j<64; j++)
            {
                if ( ((1LL << j) & mask) != 0 )
                    continue;
                char coinaddr[64]; Getscriptaddress(coinaddr,scriptPubKeys[j]);
                NSPV_SignTx(mtx,vini,10000,scriptPubKeys[j],nTime); // sets SIG_TXHASH
                if ( (retval= pubkeys[j].Verify(SIG_TXHASH,vData[0])) != 0 )
                {
                    fprintf(stderr,"(vini.%d %s.%d) ",vini,coinaddr,retval);
                    mask |= (1LL << j);
                    break;
                }
            }
            fprintf(stderr," verified %llx\n",(long long)mask);
        }
    }
    return(bitweight(mask));
}

/*
 NSPV_notariescount is the slowest process during full validation as it requires looking up 13 transactions.
 one way that would be 10000x faster would be to bruteforce validate the signatures in each vin, against all 64 pubkeys! for a valid tx, that is on average 13*32 secp256k1/sapling verify operations, which is much faster than even a single network request.
 Unfortunately, due to the complexity of calculating the hash to sign for a tx, this bruteforcing would require determining what type of signature method and having sapling vs legacy methods of calculating the txhash.
 It could be that the fullnode side could calculate this and send it back to the superlite side as any hash that would validate 13 different ways has to be the valid txhash.
 However, since the vouts being spent by the notaries are highly constrained p2pk vouts, the txhash can be deduced if a specific notary pubkey is indeed the signer
 */
int32_t NSPV_notariescount(CTransaction tx,uint8_t elected[64][33])
{
    uint8_t *script; CTransaction vintx; int64_t rewardsum = 0; int32_t i,j,utxovout,scriptlen,numsigs = 0;
    for (i=0; i<tx.vin.size(); i++)
    {
        utxovout = tx.vin[i].prevout.n;
        if ( NSPV_gettransaction(1,utxovout,tx.vin[i].prevout.hash,0,vintx,-1,0,rewardsum) != 0 )
        {
            fprintf(stderr,"error getting %s/v%d\n",tx.vin[i].prevout.hash.GetHex().c_str(),utxovout);
            return(numsigs);
        }
        if ( utxovout < vintx.vout.size() )
        {
            script = (uint8_t *)&vintx.vout[utxovout].scriptPubKey[0];
            if ( (scriptlen= vintx.vout[utxovout].scriptPubKey.size()) == 35 )
            {
                for (j=0; j<64; j++)
                    if ( memcmp(&script[1],elected[j],33) == 0 )
                    {
                        numsigs++;
                        break;
                    }
            } else fprintf(stderr,"invalid scriptlen.%d\n",scriptlen);
        } else fprintf(stderr,"invalid utxovout.%d vs %d\n",utxovout,(int32_t)vintx.vout.size());
    }
    return(numsigs);
}

uint256 NSPV_opretextract(int32_t *heightp,uint256 *blockhashp,char *symbol,std::vector<uint8_t> opret,uint256 txid)
{
    uint256 desttxid; int32_t i;
    iguana_rwnum(0,&opret[32],sizeof(*heightp),heightp);
    for (i=0; i<32; i++)
        ((uint8_t *)blockhashp)[i] = opret[i];
    for (i=0; i<32; i++)
        ((uint8_t *)&desttxid)[i] = opret[4 + 32 + i];
    if ( 0 && *heightp != 2690 )
        fprintf(stderr," ntzht.%d %s <- txid.%s size.%d\n",*heightp,(*blockhashp).GetHex().c_str(),(txid).GetHex().c_str(),(int32_t)opret.size());
    return(desttxid);
}

int32_t NSPV_notarizationextract(int32_t verifyntz,int32_t *ntzheightp,uint256 *blockhashp,uint256 *desttxidp,CTransaction tx)
{
    int32_t numsigs=0; uint8_t elected[64][33]; char *symbol; std::vector<uint8_t> opret; uint32_t nTime;
    if ( tx.vout.size() >= 2 )
    {
        symbol = (ASSETCHAINS_SYMBOL[0] == 0) ? (char *)"KMD" : ASSETCHAINS_SYMBOL;
        GetOpReturnData(tx.vout[1].scriptPubKey,opret);
        if ( opret.size() >= 32*2+4 )
        {
            //sleep(1); // needed to avoid no pnodes error
            *desttxidp = NSPV_opretextract(ntzheightp,blockhashp,symbol,opret,tx.GetHash());
            nTime = NSPV_blocktime(*ntzheightp);
            komodo_notaries(elected,*ntzheightp,nTime);
            if ( verifyntz != 0 && (numsigs= NSPV_fastnotariescount(tx,elected,nTime)) < 12 )
            {
                fprintf(stderr,"numsigs.%d error\n",numsigs);
                return(-3);
            }
            return(0);
        }
        else
        {
            fprintf(stderr,"opretsize.%d error\n",(int32_t)opret.size());
            return(-2);
        }
    } else return(-1);
}
#endif // NSPV_UTILS_H
