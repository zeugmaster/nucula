#pragma once
#include <secp256k1.h>
#ifdef __cplusplus
extern "C" {
#endif
int secp256k1_nucula_secret_multiply(const secp256k1_context *ctx,secp256k1_pubkey *out,const secp256k1_pubkey *point,const unsigned char scalar[32]);
/* Experimental public commitment equations; malloc-aligned caller workspace,
 * n<=32, compressed P/K arrays and canonical 32-byte tweaks (zero allowed). */
size_t secp256k1_nucula_tweak_scratch_size(size_t n);
int secp256k1_nucula_verify_tweaks(const secp256k1_context *ctx,size_t n,const unsigned char *P,const unsigned char *K,const unsigned char *t,void *scratch,size_t bytes);
int secp256k1_nucula_dleq_points(const secp256k1_context *ctx,secp256k1_pubkey out[2],const secp256k1_pubkey *A,const secp256k1_pubkey *B,const secp256k1_pubkey *C,const unsigned char e[32],const unsigned char s[32]);
int secp256k1_nucula_hwfield_chain(unsigned char out[32],size_t count,int square);
int secp256k1_nucula_hwfield_compare(size_t count);
int secp256k1_nucula_sqrt_compare(size_t count);
void secp256k1_nucula_field_chain(unsigned char out[32], size_t count, unsigned operation);

/* Local BIP-340 batch verifier, fixed 32-byte messages. Coefficients are
 * generated with HMAC-SHA256 from a domain-separated hash of ALL inputs,
 * rejection-sampled in 1..n-1; first coefficient is 1. Public-data MSM only.
 * n <= 32; algorithm 0 = bounded Strauss, 1 = bounded Pippenger.
 * Scratch is caller-owned, naturally aligned, and never retained. */
size_t secp256k1_nucula_batch_scratch_size(size_t n, unsigned algorithm);
int secp256k1_nucula_verify_batch(const secp256k1_context *ctx, size_t n,
                                  const unsigned char *signatures64,
                                  const unsigned char *messages32,
                                  const unsigned char *public_keys32,
                                  void *scratch, size_t scratch_size,
                                  unsigned algorithm);
#ifdef __cplusplus
}
#endif
