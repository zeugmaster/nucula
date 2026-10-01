#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "crypto.h"
#include "hex.h"
#include <secp256k1_nucula.h>
#define CHECK(x) do { if(!(x)){fprintf(stderr,"line %d failed\n",__LINE__);return 1;} } while(0)
static unsigned rng=0x718b30a5;
static void scalar(unsigned char out[32]) {
    for(unsigned j=0;j<32;j++){rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;out[j]=(unsigned char)rng;}
    out[0]&=0x7f;out[31]|=1;
}
static int same(const secp256k1_context *ctx,const secp256k1_pubkey *a,const secp256k1_pubkey *b) {
    unsigned char x[33],y[33];size_t nx=33,ny=33;
    return secp256k1_ec_pubkey_serialize(ctx,x,&nx,a,SECP256K1_EC_COMPRESSED)&&
        secp256k1_ec_pubkey_serialize(ctx,y,&ny,b,SECP256K1_EC_COMPRESSED)&&!memcmp(x,y,33);
}
int main(void) {
    secp256k1_context *ctx=secp256k1_context_create(SECP256K1_CONTEXT_NONE);CHECK(ctx);
    unsigned char ab[33],bb[33],e[32],s[32];secp256k1_pubkey A,B,C,out[2];
    CHECK(hex_to_bytes("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",ab,33));
    CHECK(hex_to_bytes("02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2",bb,33));
    CHECK(secp256k1_ec_pubkey_parse(ctx,&A,ab,33));CHECK(secp256k1_ec_pubkey_parse(ctx,&B,bb,33));C=B;
    CHECK(hex_to_bytes("9818e061ee51d5c8edc3342369a554998ff7b4381c8652d724cdf46429be73d9",e,32));
    CHECK(hex_to_bytes("9818e061ee51d5c8edc3342369a554998ff7b4381c8652d724cdf46429be73da",s,32));
    for(unsigned flags=0;flags<2;flags++) {
        cashu_crypto_configure(flags);CHECK(cashu_verify_dleq(ctx,&A,&B,&C,e,s));
        e[3]^=1;CHECK(!cashu_verify_dleq(ctx,&A,&B,&C,e,s));e[3]^=1;
    }
    for(unsigned i=0;i<256;i++) {
        unsigned char k[32];scalar(k);CHECK(secp256k1_ec_pubkey_create(ctx,&A,k));
        scalar(k);CHECK(secp256k1_ec_pubkey_create(ctx,&B,k));scalar(k);CHECK(secp256k1_ec_pubkey_create(ctx,&C,k));
        scalar(e);scalar(s);CHECK(secp256k1_nucula_dleq_points(ctx,out,&A,&B,&C,e,s)==1);
        secp256k1_pubkey x=A,y,reference;CHECK(secp256k1_ec_pubkey_tweak_mul(ctx,&x,e));
        CHECK(secp256k1_ec_pubkey_negate(ctx,&x));CHECK(secp256k1_ec_pubkey_create(ctx,&y,s));
        const secp256k1_pubkey *points[2]={&x,&y};CHECK(secp256k1_ec_pubkey_combine(ctx,&reference,points,2));CHECK(same(ctx,&reference,&out[0]));
        x=C;y=B;CHECK(secp256k1_ec_pubkey_tweak_mul(ctx,&x,e));CHECK(secp256k1_ec_pubkey_negate(ctx,&x));
        CHECK(secp256k1_ec_pubkey_tweak_mul(ctx,&y,s));CHECK(secp256k1_ec_pubkey_combine(ctx,&reference,points,2));CHECK(same(ctx,&reference,&out[1]));
        reference=A;CHECK(secp256k1_ec_pubkey_tweak_mul(ctx,&reference,s));
        CHECK(secp256k1_nucula_secret_multiply(ctx,&x,&A,s));CHECK(same(ctx,&reference,&x));
        CHECK(secp256k1_nucula_secret_multiply(ctx,&A,&A,s));CHECK(same(ctx,&reference,&A));
    }
    memset(e,0,32);CHECK(!secp256k1_nucula_dleq_points(ctx,out,&A,&B,&C,e,s));
    CHECK(!secp256k1_nucula_secret_multiply(ctx,&out[0],&A,e));memset(e,255,32);
    CHECK(!secp256k1_nucula_dleq_points(ctx,out,&A,&B,&C,e,s));CHECK(!secp256k1_nucula_secret_multiply(ctx,&out[0],&A,e));
    unsigned char points[32*33],keys[32*33],tweaks[32*32];
    for(size_t i=0;i<32;i++) {
        unsigned char k[32];scalar(k);scalar(tweaks+32*i);if(!(i%3))memset(tweaks+32*i,0,32);
        CHECK(secp256k1_ec_pubkey_create(ctx,&A,k));size_t len=33;
        CHECK(secp256k1_ec_pubkey_serialize(ctx,keys+33*i,&len,&A,SECP256K1_EC_COMPRESSED));
        CHECK(secp256k1_ec_pubkey_tweak_add(ctx,&A,tweaks+32*i));len=33;
        CHECK(secp256k1_ec_pubkey_serialize(ctx,points+33*i,&len,&A,SECP256K1_EC_COMPRESSED));
    }
    for(size_t n=1;n<=32;n++) {
        size_t bytes=secp256k1_nucula_tweak_scratch_size(n);void *arena=malloc(bytes);CHECK(arena);
        CHECK(secp256k1_nucula_verify_tweaks(ctx,n,points,keys,tweaks,arena,bytes));
        tweaks[32*n-1]^=1;CHECK(!secp256k1_nucula_verify_tweaks(ctx,n,points,keys,tweaks,arena,bytes));tweaks[32*n-1]^=1;
        CHECK(!secp256k1_nucula_verify_tweaks(ctx,n,points,keys,tweaks,arena,bytes-1));free(arena);
    }
    secp256k1_context_destroy(ctx);
    puts("PASS: NUT-12 valid/tampered vector, 256 full-width DLEQ point comparisons, 512 secret multiply/alias comparisons, invalid scalars, commitment batches n=1..32 with zero tweaks, tamper and scratch bounds");return 0;
}
