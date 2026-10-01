#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_nucula.h>
int main(void) {
    secp256k1_context *ctx=secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    unsigned char signatures[32*64],messages[32*32],keys[32*32];unsigned cases=0;
    for(unsigned i=0;i<32;i++) {
        unsigned char sk[32],aux[32]={0};secp256k1_keypair kp;secp256k1_xonly_pubkey pk;
        for(unsigned j=0;j<32;j++){sk[j]=(unsigned char)(i*23+j*67+47);messages[i*32+j]=(unsigned char)(i*89+j*77);}
        sk[0]&=0x7f;sk[31]|=1;
        if(!secp256k1_keypair_create(ctx,&kp,sk)||!secp256k1_keypair_xonly_pub(ctx,&pk,NULL,&kp)||
           !secp256k1_xonly_pubkey_serialize(ctx,keys+i*32,&pk)||!secp256k1_schnorrsig_sign32(ctx,signatures+i*64,messages+i*32,&kp,aux))return 1;
    }
    for(unsigned mode=0;mode<2;mode++) for(size_t n=1;n<=32;n++) {
        size_t size=secp256k1_nucula_batch_scratch_size(n,mode);void *memory=malloc(size);
        if(!memory)return 2;
        for(unsigned test=0;test<9;test++) {
            unsigned char bads[sizeof(signatures)],badm[sizeof(messages)],badk[sizeof(keys)];
            memcpy(bads,signatures,sizeof(bads));memcpy(badm,messages,sizeof(badm));memcpy(badk,keys,sizeof(badk));
            if(test==1) bads[64*(n-1)+47]^=1;
            if(test==2) badm[32*(n-1)+19]^=1;
            if(test==3) badk[32*(n-1)+19]^=1;
            if(test==4) memset(bads+64*(n-1),0xff,32);
            if(test==5) memset(bads+64*(n-1)+32,0xff,32);
            if(test==6) memset(badk+32*(n-1),0xff,32);
            if(test==7) { /* Opposite perturbations must not cancel in a batch. */
                bads[63]^=1;if(n>1)bads[127]^=1;
            }
            if(test==8&&n>1) { /* Duplicate valid entries remain valid. */
                memcpy(bads+64*(n-1),bads,64);memcpy(badm+32*(n-1),badm,32);memcpy(badk+32*(n-1),badk,32);
            }
            int expected=1;
            for(size_t i=0;i<n;i++) {secp256k1_xonly_pubkey pk;expected&=secp256k1_xonly_pubkey_parse(ctx,&pk,badk+32*i)&&secp256k1_schnorrsig_verify(ctx,bads+64*i,badm+32*i,32,&pk);}
            int got=secp256k1_nucula_verify_batch(ctx,n,bads,badm,badk,memory,size,mode);
            if(got!=expected){fprintf(stderr,"FAIL n=%zu mode=%u test=%u expected=%d got=%d\n",n,mode,test,expected,got);return 3;}cases++;
        }
        if(secp256k1_nucula_verify_batch(ctx,n,signatures,messages,keys,memory,size-1,mode))return 4;
        free(memory);
    }
    secp256k1_context_destroy(ctx);printf("PASS: %u BIP-340 batch/individual comparisons, n=1..32, Strauss/Pippenger, malformed/tampered/duplicate inputs and scratch bounds\n",cases);
}
