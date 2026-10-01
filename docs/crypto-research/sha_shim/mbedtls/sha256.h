#pragma once
#include <stddef.h>
#include <openssl/sha.h>
typedef SHA256_CTX mbedtls_sha256_context;
static inline void mbedtls_sha256_init(mbedtls_sha256_context *c) { (void)c; }
static inline void mbedtls_sha256_free(mbedtls_sha256_context *c) { (void)c; }
static inline int mbedtls_sha256_starts(mbedtls_sha256_context *c, int is224) { return is224 ? -1 : SHA256_Init(c)-1; }
static inline int mbedtls_sha256_update(mbedtls_sha256_context *c, const unsigned char *p, size_t n) { return SHA256_Update(c,p,n)-1; }
static inline int mbedtls_sha256_finish(mbedtls_sha256_context *c, unsigned char out[32]) { return SHA256_Final(out,c)-1; }
static inline int mbedtls_sha256(const unsigned char *p, size_t n, unsigned char out[32], int is224) { return is224 ? -1 : (SHA256(p,n,out) ? 0 : -1); }

static inline void mbedtls_sha256_clone(mbedtls_sha256_context *dst, const mbedtls_sha256_context *src) { *dst=*src; }
