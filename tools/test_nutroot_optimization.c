/* Differential malformed/well-formed witnesses, with deterministic fixtures. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cJSON.h>
#include "nutroot.h"
#include "hex.h"
static size_t allocation_limit=(size_t)-1;
static void *limited_malloc(size_t n){return n>allocation_limit?NULL:malloc(n);}
#define malloc limited_malloc
#include "../main/nutroot.c"
#undef malloc
static unsigned rng=0x417828c3;
static unsigned random_word(void) { rng^=rng<<13; rng^=rng>>17; rng^=rng<<5; return rng; }
static void secret(unsigned i,unsigned char sk[32]) {
    for(unsigned j=0;j<32;j++) sk[j]=(unsigned char)(31+j*53+i*7);
    sk[0]&=0x7f; sk[31]|=1;
}
int main(void) {
    secp256k1_context *ctx=secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    unsigned char sk[32],keys[15*33],internal[33],point[33],leaf[520],root[32],digest[32],transaction[32];
    char signatures[15][129];
    for(unsigned i=0;i<16;i++) {
        secp256k1_pubkey pk;size_t len=33;secret(i,sk);
        if(!secp256k1_ec_pubkey_create(ctx,&pk,sk)||!secp256k1_ec_pubkey_serialize(ctx,i==15?internal:keys+33*i,&len,&pk,SECP256K1_EC_COMPRESSED))return 1;
    }
    unsigned char kid[8]={2},c[48]={0x80},b[48]={0x80};
    nutroot_input_t input={.amount=8,.keyset_id=kid,.keyset_id_len=8,.secret=point,.secret_len=33,.C=c,.C_len=48};
    nutroot_output_t output={.amount=8,.keyset_id=kid,.keyset_id_len=8,.B_=b,.B_len=48};
    nutroot_tx_t tx={.proof_inputs=&input,.n_proof_inputs=1,.blinded_outputs=&output,.n_blinded_outputs=1};
    unsigned comparisons=0;
    for(unsigned trial=0;trial<250;trial++) {
        unsigned m=1+random_word()%15,n=1+random_word()%m;
        size_t length=sizeof(leaf);
        if(!nutroot_leaf_build(NUTROOT_LEAF_THRESHOLD,n,keys,m,0,NULL,leaf,&length)||!nutroot_leaf_hash(leaf,length,root)||!nutroot_tweak_pubkey(ctx,internal,root,point)||!nutroot_tx_digest(&tx,transaction)||!nutroot_input_digest(transaction,&input,digest))return 2;
        for(unsigned i=0;i<m;i++) { unsigned char sig[64];secret(i,sk);if(!nutroot_sign_digest(ctx,sk,digest,sig))return 3;bytes_to_hex(sig,64,signatures[i]); }
        char lh[1041],kh[67];bytes_to_hex(leaf,length,lh);bytes_to_hex(internal,33,kh);
        cJSON *w=cJSON_CreateObject(),*ctl=cJSON_AddObjectToObject(w,"control"),*sigs=cJSON_AddArrayToObject(w,"signatures");
        cJSON_AddStringToObject(w,"leaf",lh);cJSON_AddStringToObject(ctl,"K",kh);cJSON_AddArrayToObject(ctl,"path");
        unsigned count=trial%5==0?m:random_word()%(m+2);
        unsigned mask=0;int malformed=0;
        for(unsigned i=0;i<count;i++) {
            unsigned idx=trial%5==0?i%m:random_word()%m;
            unsigned kind=trial%5==0?0:random_word()%16;
            if(kind<11) { cJSON_AddItemToArray(sigs,cJSON_CreateString(signatures[idx]));mask|=1u<<idx; }
            else if(kind==11) { cJSON_AddItemToArray(sigs,cJSON_CreateNumber(42));malformed=1; }
            else if(kind==12) cJSON_AddItemToArray(sigs,cJSON_CreateString("a123"));
            else if(kind==13) { char bad[129];memcpy(bad,signatures[idx],129);bad[17]='z';cJSON_AddItemToArray(sigs,cJSON_CreateString(bad)); }
            else { char bad[129];memcpy(bad,signatures[idx],129);bad[64]=bad[64]=='a'?'b':'a';cJSON_AddItemToArray(sigs,cJSON_CreateString(bad)); }
        }
        input.witness=cJSON_PrintUnformatted(w);cJSON_Delete(w);
        int expected=!malformed&&count<=m&&__builtin_popcount(mask)>=n;
        static const unsigned options[]={0,1,3,7,15,31,63,95};
        for(size_t option=0;option<sizeof(options)/sizeof(options[0]);option++) {
            unsigned opt=options[option];
            nutroot_set_optimizations(opt);
            int got=nutroot_verify_transaction(ctx,&tx,2000000000);
            if(got!=expected) { fprintf(stderr,"mismatch trial=%u opt=%u threshold=%u/%u expected=%d actual=%d witness=%s\n",trial,opt,n,m,expected,got,input.witness);return 4; }
            comparisons++;
        }
        static const size_t limits[]={20000,1000};
        nutroot_set_optimizations(95);
        for(size_t limit=0;limit<sizeof(limits)/sizeof(limits[0]);limit++) {
            allocation_limit=limits[limit];
            if(nutroot_verify_transaction(ctx,&tx,2000000000)!=expected)return 7;
            comparisons++;
        }
        allocation_limit=(size_t)-1;
        free((void *)input.witness);input.witness=NULL;
    }
    unsigned char commitments[64*33],internals[64*33];const unsigned char *roots[64];
    for(unsigned i=0;i<64;i++){memcpy(commitments+33*i,point,33);memcpy(internals+33*i,internal,33);roots[i]=root;}
    static const size_t counts[]={0,1,2,3,10,32,33,64};
    for(size_t j=0;j<sizeof(counts)/sizeof(counts[0]);j++) {
        size_t n=counts[j];
        if(!nutroot_verify_commitments(ctx,n,commitments,internals,roots))return 5;
        if(n){commitments[33*n-1]^=1;if(nutroot_verify_commitments(ctx,n,commitments,internals,roots))return 6;commitments[33*n-1]^=1;}
    }
    puts("PASS: commitment API valid/tampered n=0,1,2,3,10,32,33,64");
    nutroot_input_t many[64];char witnesses[64][160];
    for(size_t i=0;i<64;i++){many[i]=input;many[i].amount=i+1;many[i].witness=witnesses[i];}
    nutroot_tx_t large=tx;large.proof_inputs=many;large.n_proof_inputs=64;
    secret(15,sk);
    if(!nutroot_tweak_seckey(ctx,sk,root)||!nutroot_tx_digest(&large,transaction))return 8;
    for(size_t i=0;i<64;i++) {
        unsigned char signature[64];char hex[129];
        if(!nutroot_input_digest(transaction,&many[i],digest)||!nutroot_sign_digest(ctx,sk,digest,signature))return 9;
        bytes_to_hex(signature,64,hex);snprintf(witnesses[i],sizeof(witnesses[i]),"{\"signatures\":[\"%s\"]}",hex);
    }
    static const size_t limits[]={(size_t)-1,20000,1000};
    static const unsigned modes[]={15,31,95};
    for(size_t l=0;l<3;l++)for(size_t m=0;m<3;m++) {
        allocation_limit=limits[l];nutroot_set_optimizations(modes[m]);
        if(!nutroot_verify_transaction(ctx,&large,2000000000))return 10;
        char saved=witnesses[63][25];witnesses[63][25]=saved=='0'?'1':'0';
        if(nutroot_verify_transaction(ctx,&large,2000000000))return 11;
        witnesses[63][25]=saved;
    }
    puts("PASS: 64 current per-input keypath signatures, full/reduced/no scratch, final-chunk tamper rejection");
    secp256k1_context_destroy(ctx);
    printf("PASS: %u Nutroot threshold comparisons (ordered, shuffled, missing, duplicate, malformed hex and JSON types)\n",comparisons);
}
