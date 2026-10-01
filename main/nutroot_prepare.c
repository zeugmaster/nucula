#include "nutroot_prepare.h"
#include "cashu_suite.h"
#include <string.h>
#include <limits.h>
static void wipe(void *p,size_t n){volatile unsigned char *b=p;while(n--)*b++=0;}
static const unsigned char secp_order[32]={
 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
 0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x41};
static const unsigned char bls_order[32]={
 0x73,0xed,0xa7,0x53,0x29,0x9d,0x7d,0x48,0x33,0x39,0xd8,0x08,0x09,0xa1,0xd8,0x05,
 0x53,0xbd,0xa4,0x02,0xff,0xfe,0x5b,0xfe,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01};
static void be32(unsigned char *p,uint32_t n){for(unsigned i=0;i<4;i++)p[i]=(unsigned char)(n>>(24-8*i));}
static int scalar_valid(const unsigned char s[32],const unsigned char order[32]) {
    unsigned nonzero=0;for(unsigned i=0;i<32;i++)nonzero|=s[i];
    return nonzero && memcmp(s,order,32)<0;
}
void nutroot_kdf_clear(nutroot_kdf_t *kdf){if(kdf){mbedtls_sha256_free(&kdf->prefix);mbedtls_sha256_free(&kdf->outer);wipe(kdf,sizeof(*kdf));}}
int nutroot_kdf_init(nutroot_kdf_t *kdf,const unsigned char *seed,size_t seed_len,
                      const unsigned char *id,size_t id_len) {
    if(!kdf)return 0;
    memset(kdf,0,sizeof(*kdf));
    if((!seed&&seed_len)||(!id&&id_len)||id_len>UINT32_MAX||(id_len&&id[0]!=2))return 0;
    unsigned char block[64]={0},length[4];int ok=1;
    if(seed_len>64)ok=mbedtls_sha256(seed,seed_len,block,0)==0;
    else if(seed_len)memcpy(block,seed,seed_len);
    mbedtls_sha256_init(&kdf->prefix);mbedtls_sha256_init(&kdf->outer);
    for(unsigned i=0;i<64;i++)block[i]^=0x36;
    ok=ok&&mbedtls_sha256_starts(&kdf->prefix,0)==0&&mbedtls_sha256_update(&kdf->prefix,block,64)==0;
    for(unsigned i=0;i<64;i++)block[i]^=0x36^0x5c;
    ok=ok&&mbedtls_sha256_starts(&kdf->outer,0)==0&&mbedtls_sha256_update(&kdf->outer,block,64)==0;
    static const unsigned char domain[]="Cashu_KDF_HMAC_SHA256";
    be32(length,(uint32_t)id_len);
    ok=ok&&mbedtls_sha256_update(&kdf->prefix,domain,sizeof(domain)-1)==0&&
           mbedtls_sha256_update(&kdf->prefix,length,4)==0&&mbedtls_sha256_update(&kdf->prefix,id,id_len)==0;
    wipe(block,sizeof(block));kdf->quote=id_len==0;kdf->valid=ok;
    if(!ok)nutroot_kdf_clear(kdf);
    return ok;
}
int nutroot_kdf_derive(const nutroot_kdf_t *kdf,uint64_t counter,unsigned type,uint32_t index,unsigned char out[32]) {
    if(!kdf||!kdf->valid||!out||type>4||(type==4)!=kdf->quote)return 0;
    unsigned char suffix[17],digest[32];mbedtls_sha256_context inner,outer;
    mbedtls_sha256_init(&inner);mbedtls_sha256_init(&outer);
    for(unsigned i=0;i<8;i++)suffix[i]=(unsigned char)(counter>>(56-8*i));
    suffix[8]=(unsigned char)type;
    if(type==3)be32(suffix+13,index);
    int ok=0;
    /* Bounded failure returns no key; it never substitutes biased reduction. */
    for(uint32_t attempt=0;attempt<256;attempt++) {
        be32(suffix+9,attempt);mbedtls_sha256_clone(&inner,&kdf->prefix);mbedtls_sha256_clone(&outer,&kdf->outer);
        if(mbedtls_sha256_update(&inner,suffix,type==3?17:13)!=0||mbedtls_sha256_finish(&inner,digest)!=0||
           mbedtls_sha256_update(&outer,digest,32)!=0||mbedtls_sha256_finish(&outer,digest)!=0)break;
        if(scalar_valid(digest,type==1?bls_order:secp_order)){memcpy(out,digest,32);ok=1;break;}
    }
    mbedtls_sha256_free(&inner);mbedtls_sha256_free(&outer);wipe(digest,sizeof(digest));wipe(suffix,sizeof(suffix));
    if(!ok)memset(out,0,32);
    return ok;
}
int nutroot_nums_key(const secp256k1_context *ctx,const unsigned char offset[32],unsigned char K[33]) {
    static const unsigned char H[33]={0x02,0x50,0x92,0x9b,0x74,0xc1,0xa0,0x49,0x54,0xb7,0x8b,0x4b,0x60,0x35,0xe9,0x7a,0x5e,0x07,0x8a,0x5a,0x0f,0x28,0xec,0x96,0xd5,0x47,0xbf,0xee,0x9a,0xce,0x80,0x3a,0xc0};
    if(!ctx||!offset||!K||!secp256k1_ec_seckey_verify(ctx,offset))return 0;
    secp256k1_pubkey generator,nums,result;const secp256k1_pubkey *points[2]={&generator,&nums};size_t length=33;
    return secp256k1_ec_pubkey_parse(ctx,&nums,H,33)&&secp256k1_ec_pubkey_create(ctx,&generator,offset)&&
           secp256k1_ec_pubkey_combine(ctx,&result,points,2)&&secp256k1_ec_pubkey_serialize(ctx,K,&length,&result,SECP256K1_EC_COMPRESSED);
}
int nutroot_nums_verify(const secp256k1_context *ctx,const unsigned char offset[32],const unsigned char K[33]) {
    unsigned char expected[33];return K&&nutroot_nums_key(ctx,offset,expected)&&!memcmp(expected,K,33);
}
void nutroot_prepared_clear(nutroot_prepared_output_t *out){if(out)wipe(out,sizeof(*out));}
int nutroot_prepare_bare(const secp256k1_context *ctx,const nutroot_kdf_t *kdf,uint64_t counter,nutroot_prepared_output_t *out) {
    if(!ctx||!out)return 0;
    memset(out,0,sizeof(*out));secp256k1_pubkey key;size_t length=33;
    int ok=nutroot_kdf_derive(kdf,counter,0,0,out->internal_key)&&nutroot_kdf_derive(kdf,counter,1,0,out->r)&&
           secp256k1_ec_pubkey_create(ctx,&key,out->internal_key)&&
           secp256k1_ec_pubkey_serialize(ctx,out->secret,&length,&key,SECP256K1_EC_COMPRESSED);
    length=48;ok=ok&&cashu_suite_bls.blind(NULL,out->secret,33,out->r,32,out->blinded,&length);
    if(!ok){nutroot_prepared_clear(out);return 0;}out->counter=counter;out->ready=1;return 1;
}
