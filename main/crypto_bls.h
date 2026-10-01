#pragma once
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif
enum {
    CASHU_BLS_WORKSPACE = 1u << 0,
    CASHU_BLS_KEY_CACHE = 1u << 1,
    CASHU_BLS_GROUP_KEYS = 1u << 2,
    CASHU_BLS_BUCKET_MSM = 1u << 3,
    CASHU_BLS_WINDOW_MSM = 1u << 4,
    CASHU_BLS_BATCH_AFFINE = 1u << 5,
    CASHU_BLS_PREPARED_GENERATOR = 1u << 6,
    CASHU_BLS_PREPARED_HOT_KEY = 1u << 7,
    CASHU_BLS_GLV_MSM = 1u << 8,
    CASHU_BLS_GROUP_MSM = 1u << 9,
    CASHU_BLS_BATCH_INVERSE = 1u << 10,
    CASHU_BLS_FAIR_YIELD = 1u << 11,
    CASHU_BLS_HASH_CACHE = 1u << 12,
};
/* Diagnostic configuration. Changes and cache access serialize with the BLS
 * peripheral owner. Capacity is bounded to 1..16. Zero flags select reference. */
int cashu_bls_configure(unsigned flags, size_t capacity);
unsigned cashu_bls_options(void);
size_t cashu_bls_capacity(void);
/* Clear validated G2 and deterministic hash-to-G1 caches. No proof-validity
 * result is cached: C validation, weights and the pairing always run. */
void cashu_bls_clear_key_cache(void);
/* Preserve validated mint keys while dropping deterministic Y mappings.
 * Useful for fresh-proof latency measurements and clearing cached messages. */
void cashu_bls_clear_hash_cache(void);
/* Complete mint-response check. Fixed-stride keys=96B, blinded/out=48B,
 * r=32B big-endian. out may alias blinded, but not the other input arrays.
 * Never publishes a successful unverified result. */
int cashu_bls_unblind_verify(size_t n, const unsigned char *keys,
                             const unsigned char *blinded, const unsigned char *rs,
                             const unsigned char *const *secrets, const size_t *lengths,
                             unsigned char *out);
#ifdef __cplusplus
}
#endif
