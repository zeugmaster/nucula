#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <secp256k1.h>
#include "nutroot.h"
#include "hex.h"
static void key(unsigned v,unsigned char s[32]){memset(s,0,32);s[30]=v>>8;s[31]=v;}
static int pub(secp256k1_context *c,const unsigned char s[32],unsigned char p[33]){
    secp256k1_pubkey pk;size_t len=33;
    return secp256k1_ec_pubkey_create(c,&pk,s)&&secp256k1_ec_pubkey_serialize(c,p,&len,&pk,SECP256K1_EC_COMPRESSED);
}
int main(void){
    secp256k1_context *ctx=secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    unsigned char keys[15*33],sk[32],k33[33],p33[33],leaf[520],root[32],d[32];
    for(int i=0;i<15;i++){key(i+1,sk);if(!pub(ctx,sk,keys+i*33))return 1;}
    key(100,sk);if(!pub(ctx,sk,k33))return 2;
    size_t llen=sizeof(leaf);if(!nutroot_leaf_build(NUTROOT_LEAF_THRESHOLD,8,keys,15,0,NULL,leaf,&llen))return 3;
    if(!nutroot_leaf_hash(leaf,llen,root)||!nutroot_tweak_pubkey(ctx,k33,root,p33))return 4;
    unsigned char kid[8]={2},c[48]={0x80},b[48]={0x80};
    nutroot_input_t in={0};in.amount=8;in.keyset_id=kid;in.keyset_id_len=8;in.secret=p33;in.secret_len=33;in.C=c;in.C_len=48;
    nutroot_output_t out={0};out.amount=8;out.keyset_id=kid;out.keyset_id_len=8;out.B_=b;out.B_len=48;
    nutroot_tx_t tx={0};tx.proof_inputs=&in;tx.n_proof_inputs=1;tx.blinded_outputs=&out;tx.n_blinded_outputs=1;
    if(!nutroot_tx_digest(&tx,d))return 5;
    char lh[1041],kh[67],sigs[8][129];bytes_to_hex(leaf,llen,lh);bytes_to_hex(k33,33,kh);
    for(int i=0;i<8;i++){unsigned char sig[64];key(i+1,sk);if(!nutroot_sign_digest(ctx,sk,d,sig))return 6;bytes_to_hex(sig,64,sigs[i]);}
    puts("case,accepted,schnorr_verifies");
    for(int test=0;test<4;test++){
        char witness[4096];int pos=snprintf(witness,sizeof(witness),"{\"leaf\":\"%s\",\"control\":{\"K\":\"%s\",\"path\":[]},\"signatures\":[",lh,kh);
        int n=test==2?7:8;
        for(int i=0;i<n;i++){int idx=test==1?7-i:i;if(test==3&&i==7)idx=0;pos+=snprintf(witness+pos,sizeof(witness)-pos,"%s\"%s\"",i?",":"",sigs[idx]);}
        snprintf(witness+pos,sizeof(witness)-pos,"]}");in.witness=witness;
        nutroot_stat_sig_verifies=0;int ok=nutroot_verify_transaction(ctx,&tx,2000000000);
        printf("%s,%d,%lu\n",(const char*[]){"ordered8","reversed8","missing8th","duplicate8th"}[test],ok,nutroot_stat_sig_verifies);
        if(ok!=(test<2))return 7;
    }
    secp256k1_context_destroy(ctx);return 0;
}
