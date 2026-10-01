#pragma once
#include <stdint.h>
#include <stddef.h>
#include <secp256k1.h>
#include <mbedtls/sha256.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Current NUT-13 v3 framing. Contexts contain seed-derived state and must be
 * cleared. Each context belongs to one keyset (or empty id for quote keys). */
typedef struct {
    mbedtls_sha256_context prefix, outer;
    int valid, quote;
} nutroot_kdf_t;
int nutroot_kdf_init(nutroot_kdf_t *kdf,const unsigned char *seed,size_t seed_len,
                      const unsigned char *keyset_id,size_t keyset_len);
int nutroot_kdf_derive(const nutroot_kdf_t *kdf,uint64_t counter,unsigned type,
                        uint32_t index,unsigned char scalar[32]);
void nutroot_kdf_clear(nutroot_kdf_t *kdf);
int nutroot_nums_key(const secp256k1_context *ctx,const unsigned char offset[32],unsigned char K[33]);
int nutroot_nums_verify(const secp256k1_context *ctx,const unsigned char offset[32],const unsigned char K[33]);
/* Preparation shifts work before the interactive path; it does not reduce
 * total arithmetic. The caller MUST durably allocate a fresh proof counter
 * before preparing an entry. This API never allocates/persists counters and
 * never shares an ephemeral across outputs. Consume an entry only once. */
typedef struct {
    unsigned char internal_key[32], r[32], secret[33], blinded[48];
    uint64_t counter;
    int ready;
} nutroot_prepared_output_t;
int nutroot_prepare_bare(const secp256k1_context *ctx,const nutroot_kdf_t *kdf,
                          uint64_t allocated_counter,nutroot_prepared_output_t *out);
void nutroot_prepared_clear(nutroot_prepared_output_t *out);
#ifdef __cplusplus
}
#endif
