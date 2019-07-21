
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

#define MAX_TX_SIZE_BEFORE_SAPLING 100000
#define MAX_TX_SIZE_AFTER_SAPLING (2 * MAX_TX_SIZE_BEFORE_SAPLING)


btc_chainparams kmd_chainparams_main =
{
    "KMD",
    60,
    85,
    "bc", // const char bech32_hrp[5]
    188,
    0x0488ADE4, // uint32_t b58prefix_bip32_privkey
    0x0488B21E, // uint32_t b58prefix_bip32_pubkey
    { 0xf9, 0xee, 0xe4, 0x8d },
    { 0x02, 0x7e, 0x37, 0x58, 0xc3, 0xa6, 0x5b, 0x12, 0xaa, 0x10, 0x46, 0x46, 0x2b, 0x48, 0x6d, 0x0a, 0x63, 0xbf, 0xa1, 0xbe, 0xae, 0x32, 0x78, 0x97, 0xf5, 0x6c, 0x5c, 0xfb, 0x7d, 0xaa, 0xae, 0x71 }, //{0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00},
    7770,7771,
    {{"5.9.253.195, 5.9.253.196, 5.9.253.197, 5.9.253.198, 5.9.253.199, 5.9.253.200, 5.9.253.201, 5.9.253.202, 5.9.253.203"}, 0},
    60,
    170007,
    MAX_TX_SIZE_AFTER_SAPLING,
    1,1,0,
};

btc_chainparams nspv_chainparams_main =
{
    "NSPV",
    60,
    85,
    "bc", // const char bech32_hrp[5]
    188,
    0x0488ADE4, // uint32_t b58prefix_bip32_privkey
    0x0488B21E, // uint32_t b58prefix_bip32_pubkey
    { 0x06, 0x65, 0x02, 0x98 }, //0x98, 0x02, 0x65, 0x06 },
    { 0x02, 0x7e, 0x37, 0x58, 0xc3, 0xa6, 0x5b, 0x12, 0xaa, 0x10, 0x46, 0x46, 0x2b, 0x48, 0x6d, 0x0a, 0x63, 0xbf, 0xa1, 0xbe, 0xae, 0x32, 0x78, 0x97, 0xf5, 0x6c, 0x5c, 0xfb, 0x7d, 0xaa, 0xae, 0x71 }, //{0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00},
    20266,20267,
    {{"5.9.102.210, 5.9.253.195, 5.9.253.196, 5.9.253.197, 5.9.253.198, 5.9.253.199, 5.9.253.200, 5.9.253.201, 5.9.253.202, 5.9.253.203"}, 0},
    60,
    170007,
    MAX_TX_SIZE_AFTER_SAPLING,
    1,1,0,
};

btc_chainparams iln_chainparams_main =
{
    "ILN",
    60,
    85,
    "bc", // const char bech32_hrp[5]
    188,
    0x0488ADE4, // uint32_t b58prefix_bip32_privkey
    0x0488B21E, // uint32_t b58prefix_bip32_pubkey
    { 0xfe, 0xb4, 0xcb, 0x23 }, //23cbb4fe },
    { 0x02, 0x7e, 0x37, 0x58, 0xc3, 0xa6, 0x5b, 0x12, 0xaa, 0x10, 0x46, 0x46, 0x2b, 0x48, 0x6d, 0x0a, 0x63, 0xbf, 0xa1, 0xbe, 0xae, 0x32, 0x78, 0x97, 0xf5, 0x6c, 0x5c, 0xfb, 0x7d, 0xaa, 0xae, 0x71 },
    12985,12986,
    {{"5.9.102.210, 5.9.253.195, 5.9.253.196, 5.9.253.197, 5.9.253.198, 5.9.253.199, 5.9.253.200, 5.9.253.201, 5.9.253.202, 5.9.253.203"}, 0},
    60,
    170007,
    MAX_TX_SIZE_AFTER_SAPLING,
    1,1,0,
};

char *bits256_str(char *buf,bits256 hash)
{
    int32_t i;
    for (i=0; i<32; i++)
        sprintf(&buf[i<<1],"%02x",hash.bytes[i]);
    buf[i<<1] = 0;
    return(buf);
}

bits256 bits256_doublesha256(uint8_t *data,int32_t datalen)
{
    bits256 hash,hash2; int32_t i;
    sha256_Raw(data,datalen,hash.bytes);
    sha256_Raw(hash.bytes,sizeof(hash),hash2.bytes);
    for (i=0; i<(int32_t)sizeof(hash); i++)
        hash.bytes[i] = hash2.bytes[sizeof(hash) - 1 - i];
    return(hash);
}
               
bits256 NSPV_hdrhash(struct NSPV_equihdr *hdr)
{
    bits256 hash;
    // serialize using iguana_hdrs method
    /*CBlockHeader block;
     block.nVersion = hdr->nVersion;
     block.hashPrevBlock = hdr->hashPrevBlock;
     block.hashMerkleRoot = hdr->hashMerkleRoot;
     block.hashFinalSaplingRoot = hdr->hashFinalSaplingRoot;
     block.nTime = hdr->nTime;
     block.nBits = hdr->nBits;
     block.nNonce = hdr->nNonce;
     block.nSolution.resize(sizeof(hdr->nSolution));
     memcpy(&block.nSolution[0],hdr->nSolution,sizeof(hdr->nSolution));
     return(block.GetHash());*/
    return(hash);
}

void touppercase(char *str)
{
    int32_t i;
    if ( str == 0 || str[0] == 0 )
        return;
    for (i=0; str[i]!=0; i++)
        str[i] = toupper(((int32_t)str[i]));
}

void tolowercase(char *str)
{
    int32_t i;
    if ( str == 0 || str[0] == 0 )
        return;
    for (i=0; str[i]!=0; i++)
        str[i] = tolower(((int32_t)str[i]));
}

char *uppercase_str(char *buf,char *str)
{
    if ( str != 0 )
    {
        strcpy(buf,str);
        touppercase(buf);
    } else buf[0] = 0;
    return(buf);
}

char *lowercase_str(char *buf,char *str)
{
    if ( str != 0 )
    {
        strcpy(buf,str);
        tolowercase(buf);
    } else buf[0] = 0;
    return(buf);
}

int32_t strsearch(char *strs[],int32_t num,char *name)
{
    int32_t i; char strA[32],refstr[32];
    strcpy(refstr,name), touppercase(refstr);
    for (i=0; i<num; i++)
    {
        strcpy(strA,strs[i]), touppercase(strA);
        if ( strcmp(strA,refstr) == 0 )
            return(i);
    }
    return(-1);
}

int32_t is_decimalstr(char *str)
{
    int32_t i;
    if ( str == 0 || str[0] == 0 )
        return(0);
    for (i=0; str[i]!=0; i++)
        if ( str[i] < '0' || str[i] > '9' )
            return(0);
    return(i);
}

int32_t unstringbits(char *buf,uint64_t bits)
{
    int32_t i;
    for (i=0; i<8; i++,bits>>=8)
        if ( (buf[i]= (char)(bits & 0xff)) == 0 )
            break;
    buf[i] = 0;
    return(i);
}

uint64_t stringbits(char *str)
{
    uint64_t bits = 0;
    if ( str == 0 )
        return(0);
    int32_t i,n = (int32_t)strlen(str);
    if ( n > 8 )
        n = 8;
    for (i=n-1; i>=0; i--)
        bits = (bits << 8) | (str[i] & 0xff);
    //printf("(%s) -> %llx %llu\n",str,(long long)bits,(long long)bits);
    return(bits);
}

char *unstringify(char *str)
{
    int32_t i,j,n;
    if ( str == 0 )
        return(0);
    else if ( str[0] == 0 )
        return(str);
    n = (int32_t)strlen(str);
    if ( str[0] == '"' && str[n-1] == '"' )
        str[n-1] = 0, i = 1;
    else i = 0;
    for (j=0; str[i]!=0; i++)
    {
        if ( str[i] == '\\' && (str[i+1] == 't' || str[i+1] == 'n' || str[i+1] == 'b' || str[i+1] == 'r') )
            i++;
        else if ( str[i] == '\\' && str[i+1] == '"' )
            str[j++] = '"', i++;
        else str[j++] = str[i];
    }
    str[j] = 0;
    return(str);
}

void reverse_hexstr(char *str)
{
    int i,n;
    char *rev;
    n = (int32_t)strlen(str);
    rev = (char *)malloc(n + 1);
    for (i=0; i<n; i+=2)
    {
        rev[n-2-i] = str[i];
        rev[n-1-i] = str[i+1];
    }
    rev[n] = 0;
    strcpy(str,rev);
    free(rev);
}

int32_t _unhex(char c)
{
    if ( c >= '0' && c <= '9' )
        return(c - '0');
    else if ( c >= 'a' && c <= 'f' )
        return(c - 'a' + 10);
    else if ( c >= 'A' && c <= 'F' )
        return(c - 'A' + 10);
    return(-1);
}

int32_t is_hexstr(char *str,int32_t n)
{
    int32_t i;
    if ( str == 0 || str[0] == 0 )
        return(0);
    for (i=0; str[i]!=0; i++)
    {
        if ( n > 0 && i >= n )
            break;
        if ( _unhex(str[i]) < 0 )
            break;
    }
    if ( n == 0 )
        return(i);
    return(i == n);
}

int32_t unhex(char c)
{
    int32_t hex;
    if ( (hex= _unhex(c)) < 0 )
    {
        //printf("unhex: illegal hexchar.(%c)\n",c);
    }
    return(hex);
}

unsigned char _decode_hex(char *hex) { return((unhex(hex[0])<<4) | unhex(hex[1])); }

int32_t decode_hex(uint8_t *bytes,int32_t n,char *hex)
{
    int32_t adjust,i = 0;
    //printf("decode.(%s)\n",hex);
    if ( is_hexstr(hex,n) <= 0 )
    {
        memset(bytes,0,n);
        return(n);
    }
    if ( hex[n-1] == '\n' || hex[n-1] == '\r' )
        hex[--n] = 0;
    if ( n == 0 || (hex[n*2+1] == 0 && hex[n*2] != 0) )
    {
        if ( n > 0 )
        {
            bytes[0] = unhex(hex[0]);
            printf("decode_hex n.%d hex[0] (%c) -> %d hex.(%s) [n*2+1: %d] [n*2: %d %c] len.%ld\n",n,hex[0],bytes[0],hex,hex[n*2+1],hex[n*2],hex[n*2],(long)strlen(hex));
        }
        bytes++;
        hex++;
        adjust = 1;
    } else adjust = 0;
    if ( n > 0 )
    {
        for (i=0; i<n; i++)
            bytes[i] = _decode_hex(&hex[i*2]);
    }
    //bytes[i] = 0;
    return(n + adjust);
}

long _stripwhite(char *buf,int accept)
{
    int32_t i,j,c;
    if ( buf == 0 || buf[0] == 0 )
        return(0);
    for (i=j=0; buf[i]!=0; i++)
    {
        buf[j] = c = buf[i];
        if ( c == accept || (c != ' ' && c != '\n' && c != '\r' && c != '\t' && c != '\b') )
            j++;
    }
    buf[j] = 0;
    return(j);
}

char *clonestr(char *str)
{
    char *clone;
    if ( str == 0 || str[0] == 0 )
    {
        printf("warning cloning nullstr.%p\n",str);
#ifdef __APPLE__
        while ( 1 ) sleep(1);
#endif
        str = (char *)"<nullstr>";
    }
    clone = (char *)malloc(strlen(str)+16);
    strcpy(clone,str);
    return(clone);
}

int32_t safecopy(char *dest,char *src,long len)
{
    int32_t i = -1;
    if ( src != 0 && dest != 0 && src != dest )
    {
        if ( dest != 0 )
            memset(dest,0,len);
        for (i=0; i<len&&src[i]!=0; i++)
            dest[i] = src[i];
        if ( i == len )
        {
            printf("safecopy: %s too long %ld\n",src,len);
#ifdef __APPLE__
            //getchar();
#endif
            return(-1);
        }
        dest[i] = 0;
    }
    return(i);
}

char *parse_conf_line(char *line,char *field)
{
    line += strlen(field);
    for (; *line!='='&&*line!=0; line++)
        break;
    if ( *line == 0 )
        return(0);
    if ( *line == '=' )
        line++;
    while ( line[strlen(line)-1] == '\r' || line[strlen(line)-1] == '\n' || line[strlen(line)-1] == ' ' )
        line[strlen(line)-1] = 0;
    //printf("LINE.(%s)\n",line);
    _stripwhite(line,0);
    return(clonestr(line));
}

double OS_milliseconds()
{
    struct timeval tv; double millis;
    gettimeofday(&tv,NULL);
    millis = ((double)tv.tv_sec * 1000. + (double)tv.tv_usec / 1000.);
    //printf("tv_sec.%ld usec.%d %f\n",tv.tv_sec,tv.tv_usec,millis);
    return(millis);
}

char *OS_portable_path(char *str)
{
#ifdef _WIN32
    int32_t i;
    for (i=0; str[i]!=0; i++)
        if ( str[i] == '/' )
            str[i] = '\\';
    return(str);
#else
#ifdef __PNACL
    /*int32_t i,n;
     if ( str[0] == '/' )
     return(str);
     else
     {
     n = (int32_t)strlen(str);
     for (i=n; i>0; i--)
     str[i] = str[i-1];
     str[0] = '/';
     str[n+1] = 0;
     }*/
#endif
    return(str);
#endif
}

void *OS_loadfile(char *fname,char **bufp,long *lenp,long *allocsizep)
{
    FILE *fp;
    long  filesize,buflen = *allocsizep;
    char *buf = *bufp;
    *lenp = 0;
    if ( (fp= fopen(OS_portable_path(fname),"rb")) != 0 )
    {
        fseek(fp,0,SEEK_END);
        filesize = ftell(fp);
        if ( filesize == 0 )
        {
            fclose(fp);
            *lenp = 0;
            //printf("OS_loadfile null size.(%s)\n",fname);
            return(0);
        }
        if ( filesize > buflen-1 )
        {
            *allocsizep = filesize+1;
            *bufp = buf = realloc(buf,(long)*allocsizep);
        }
        rewind(fp);
        if ( buf == 0 )
            printf("Null buf ???\n");
        else
        {
            if ( fread(buf,1,(long)filesize,fp) != (unsigned long)filesize )
                printf("error reading filesize.%ld\n",(long)filesize);
            buf[filesize] = 0;
        }
        fclose(fp);
        *lenp = filesize;
        //printf("loaded.(%s)\n",buf);
    } //else printf("OS_loadfile couldnt load.(%s)\n",fname);
    return(buf);
}

void *OS_filestr(long *allocsizep,char *_fname)
{
    long filesize = 0; char *fname,*buf = 0; void *retptr;
    *allocsizep = 0;
    fname = malloc(strlen(_fname)+1);
    strcpy(fname,_fname);
    retptr = OS_loadfile(fname,&buf,&filesize,allocsizep);
    free(fname);
    return(retptr);
}

void btc_tx_add_txout(btc_tx *mtx,uint64_t satoshis,cstring *scriptPubKey)
{
    btc_tx_out *vout = btc_tx_out_new();
    vout->script_pubkey = scriptPubKey;
    vout->value = satoshis;
    vector_add(mtx->vout,vout);
}

void btc_tx_add_p2pk(btc_tx *mtx,uint64_t satoshis,uint8_t *pubkey33)
{
    btc_tx_out *vout = btc_tx_out_new();
    vout->script_pubkey = cstr_new_sz(35);
    btc_script_append_pushdata(vout->script_pubkey,pubkey33,33);
    btc_script_append_op(vout->script_pubkey,OP_CHECKSIG);
    vout->value = satoshis;
    vector_add(mtx->vout,vout);
}

btc_tx *btc_tx_decodehex(char *hexstr)
{
    uint8_t *data; btc_tx *tx; size_t consumed = 0; int32_t len = (int32_t)strlen(hexstr) >> 1;
    data = btc_malloc(len);
    decode_hex(data,len,hexstr);
    tx = btc_tx_new(SAPLING_TX_VERSION);
    if ( btc_tx_deserialize(data,len,tx,&consumed,false) == 0 || consumed != (size_t)len )
    {
        fprintf(stderr,"btc_tx_decodehex consumed %d != len %d error\n",(int32_t)consumed,len);
        btc_tx_free(tx);
        tx = 0;
    }
    btc_free(data);
    return(tx);
}

char *btc_cstr_to_hex(char *hexstr,int32_t maxlen,cstring *cstr)
{
    int32_t len;
    hexstr[0] = 0;
    if ( cstr != 0 && cstr->str != 0 && (len= cstr->len) <= (maxlen>>1)-1 )
        utils_bin_to_hex((uint8_t *)cstr->str,len,hexstr);
    return(hexstr);
}

bits256 btc_uint256_to_bits256(uint256 hash256)
{
    bits256 hash;
    iguana_rwbignum(1,hash.bytes,sizeof(hash),(uint8_t *)hash256);
    return(hash);
}

uint256 btc_bits256_to_uint256(bits256 hash)
{
    uint256 hash256;
    iguana_rwbignum(0,hash.bytes,sizeof(hash),(uint8_t *)hash256);
    return(hash);
}

cJSON *btc_txvin_to_json(btc_tx_in *vin)
{
    char hexstr[NSPV_MAXSCRIPTSIZE*2+1]; cJSON *item = cJSON_CreateObject();
    jaddbits256(item,"txid",btc_uint256_to_bits256(tx_in->prevout.hash));
    jaddnum(item,"vout",vin->prevout.n);
    jaddstr(item,"scriptSig",btc_cstr2hex(hexstr,sizeof(hexstr),vin->script_sig));
    jaddnum(item,"sequenceid",vin->sequence);
    return(item);
}

cJSON *btc_txvins_to_json(vector *vin)
{
    int32_t i; cJSON *vins = cJSON_CreateArray();
    if ( tx->vin != 0 )
    {
        for (i=0; i<tx->vin->len; i++)
            jaddi(vins,btc_txvin_to_json(vector_idx(tx->vin,i)));
    }
    return(vins);
}

cJSON *btc_txvout_to_json(btc_tx_out *vout)
{
    char hexstr[NSPV_MAXSCRIPTSIZE*2+1]; cJSON *item = cJSON_CreateObject();
    jaddnum(item,"value",dstr(vout->value));
    jaddstr(item,"scriptPubKey",btc_cstr_to_hex(hexstr,sizeof(hexstr),vout->script_pubkey));
    return(item);
}

cJSON *btc_txvouts_to_json(vector *vout)
{
    int32_t i; cJSON *vouts = cJSON_CreateArray();
    if ( tx->vout != 0 )
    {
        for (i=0; i<tx->vout->len; i++)
            jaddi(vouts,btc_txvout_to_json(vector_idx(tx->vout,i)));
    }
    return(vouts);
}

cJSON *btc_tx_to_json(btc_tx *tx)
{
    cJSON *txjson = cJSON_CreateObject();
    jaddnum(tx,"nVersion",tx->version);
    jadd(tx,"vin",btc_txvins_to_json(tx->vin));
    jadd(tx,"vout",btc_txvouts_to_json(tx->vout));
    jaddnum(tx,"nLockTime",tx->locktime);
    if ( tx->version == SAPLING_TX_VERSION )
    {
        jaddnum(tx,"nExpiryHeight",tx->nExpiryHeight);
        jaddnum(tx,"valueBalance",tx->valueBalance);
    }
    return(txjson);
}

btc_tx_in *btc_tx_vin(btc_tx *tx,int32_t vini)
{
    if ( tx != 0 && tx->vin != 0 && vini < tx->vin->len )
        return(vector_idx(tx->vin,vini));
    else return(0);
}

btc_tx_out *btc_tx_vout(btc_tx *tx,int32_t v)
{
    if ( tx != 0 && tx->vout != 0 && v < tx->vout->len )
        return(vector_idx(tx->vout,v));
    else return(0);
}

uint64_t _komodo_interestnew(int32_t txheight,uint64_t nValue,uint32_t nLockTime,uint32_t tiptime)
{
    int32_t minutes; uint64_t interest = 0;
    if ( nLockTime >= NSPV_LOCKTIME_THRESHOLD && tiptime > nLockTime && (minutes= (tiptime - nLockTime) / 60) >= (NSPV_KOMODO_MAXMEMPOOLTIME/60) )
    {
        if ( minutes > 365 * 24 * 60 )
            minutes = 365 * 24 * 60;
        if ( txheight >= 1000000 && minutes > 31 * 24 * 60 )
            minutes = 31 * 24 * 60;
        minutes -= ((NSPV_KOMODO_MAXMEMPOOLTIME/60) - 1);
        interest = ((nValue / 10512000) * minutes);
    }
    return(interest);
}

uint64_t komodo_interestnew(int32_t txheight,uint64_t nValue,uint32_t nLockTime,uint32_t tiptime)
{
    uint64_t interest = 0;
    if ( txheight < NSPV_KOMODO_ENDOFERA && nLockTime >= NSPV_LOCKTIME_THRESHOLD && tiptime != 0 && nLockTime < tiptime && nValue >= 10*COIN )
        interest = _komodo_interestnew(txheight,nValue,nLockTime,tiptime);
    return(interest);
}
#ifdef LATER


int32_t NSPV_txextract(CTransaction &tx,uint8_t *data,int32_t datalen)
{
    std::vector<uint8_t> rawdata;
    if ( datalen < coin->maxtxsize )
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
#endif


#endif // NSPV_UTILS_H
