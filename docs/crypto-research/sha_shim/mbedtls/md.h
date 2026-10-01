#pragma once
/* Host-test adapter only; firmware uses ESP-IDF mbedTLS. */
#include <openssl/hmac.h>
#include <limits.h>
typedef EVP_MD mbedtls_md_info_t;
#define MBEDTLS_MD_SHA256 6
static inline const mbedtls_md_info_t *mbedtls_md_info_from_type(int type) {
    return type==MBEDTLS_MD_SHA256 ? EVP_sha256() : NULL;
}
static inline int mbedtls_md_hmac(const mbedtls_md_info_t *md,const unsigned char *key,
 size_t key_len,const unsigned char *input,size_t len,unsigned char output[32]) {
    unsigned n=0;
    return key_len<=INT_MAX && HMAC(md,key,(int)key_len,input,len,output,&n) && n==32 ? 0 : -1;
}
