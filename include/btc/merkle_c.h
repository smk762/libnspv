#ifndef __MERKLE_C_H__
#define __MERKLE_C_H__

typedef struct partial_merkel_tree_ {
    uint32_t hashcount;
    uint256 *hashes;
    cstring *bytes;
    uint32_t txcount;
    uint8_t *bits;
    uint32_t bitscount;
    int fBad;
} partial_merkel_tree;

typedef struct merkle_block_ {
    kmd_block_header header;
    partial_merkel_tree tree;
} merkle_block;


void init_mblock(merkle_block *pmblock);
void free_mblock_data(merkle_block *pmblock);
int GetProofMerkleRoot(uint8_t *proof, int prooflen, merkle_block *pMblock, vector *vmatch, uint256 mroot);


#endif
