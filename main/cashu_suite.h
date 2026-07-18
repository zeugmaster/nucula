#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Cashu crypto suite: a byte-oriented vtable abstracting the signature scheme
 * bound to a keyset version. v1 (0x00) and v2 (0x01) keysets both use the
 * secp256k1 BDHKE suite (cashu_suite_secp256k1); a future v3 keyset would bind
 * to a BLS12-381 suite (cashu_suite_bls, see crypto_bls.c).
 *
 * The interface is deliberately free of any secp256k1 types: every curve point
 * is a length-prefixed byte buffer and the context is an opaque void*. That is
 * what lets a different curve (e.g. BLS, 48-byte points) drop in later without
 * touching the wallet, CBOR, or persistence layers. The secp256k1
 * implementation lives in crypto.c as thin adapter shims over the existing
 * cashu_* functions in crypto.h.
 *
 * Point buffers are compressed serializations: token points (Y, B_, C_, C)
 * are suite->point_len bytes, mint public keys are suite->mint_key_len bytes
 * (SEC1 33/33 for secp256k1; 48/96 for BLS12-381 G1/G2). Scalars (r, e, s)
 * are suite->scalar_len (32). Every function returns 1 on success, 0 on
 * failure.
 */
/* Upper bounds on serialized lengths across all suites, for fixed stack
 * buffers in callers. Token points (Y, B_, C_, C): secp256k1 = 33, BLS12-381
 * G1 = 48. Mint public keys (K/A): secp256k1 = 33, BLS12-381 G2 = 96 —
 * the two lengths coincide for secp but differ for BLS, hence the split.
 * Callers size buffers to these and pass the suite's actual point_len /
 * mint_key_len as the length. */
#define CASHU_MAX_POINT_LEN   48
#define CASHU_MAX_MINTKEY_LEN 96

typedef struct cashu_suite cashu_suite_t;

struct cashu_suite {
    unsigned char version_byte; /* keyset version this scheme serves (0x01 = secp v2) */
    const char   *name;         /* human-readable, e.g. "secp256k1" */
    size_t        point_len;    /* serialized token-point length (33 secp / 48 BLS G1) */
    size_t        mint_key_len; /* serialized mint-pubkey length (33 secp / 96 BLS G2) */
    size_t        scalar_len;   /* scalar length in bytes (32) */
    int           can_mint;     /* scheme can sign/mint (0 = stub / not implemented) */
    int           has_dleq;     /* NUT-12 DLEQ applies (verify_dleq* non-NULL) */

    /* B_ = blind(secret): writes the blinded point into B_out. *B_out_len is
     * in/out (buffer capacity in, bytes written out). r is the blinding
     * scalar (r_len bytes). */
    int (*blind)(void *ctx,
                 const unsigned char *secret, size_t secret_len,
                 const unsigned char *r, size_t r_len,
                 unsigned char *B_out, size_t *B_out_len);

    /* C = unblind(C_, r, K): removes the blinding from the mint's signature.
     * K is mint_key_len bytes. */
    int (*unblind)(void *ctx,
                   const unsigned char *C_, size_t C__len,
                   const unsigned char *r, size_t r_len,
                   const unsigned char *K, size_t K_len,
                   unsigned char *C_out, size_t *C_out_len);

    /* NUT-12: Alice verifies the mint's DLEQ over (A, B_, C_) with (e, s).
     * Only meaningful when has_dleq; NULL for schemes without DLEQ. */
    int (*verify_dleq)(void *ctx,
                       const unsigned char *A, size_t A_len,
                       const unsigned char *B_, size_t B__len,
                       const unsigned char *C_, size_t C__len,
                       const unsigned char *e, const unsigned char *s);

    /* NUT-12: Carol verifies the DLEQ on an unblinded Proof, reconstructing
     * B_/C_ from the secret and the blinding factor r. NULL when !has_dleq. */
    int (*verify_dleq_unblinded)(void *ctx,
                                 const unsigned char *A, size_t A_len,
                                 const unsigned char *C, size_t C_len,
                                 const unsigned char *secret, size_t secret_len,
                                 const unsigned char *e, const unsigned char *s,
                                 const unsigned char *r);

    /* Intrinsic offline verification: are the C_i valid mint signatures over
     * secret_i under mint key K_i, needing nothing beyond the published keys?
     * (BLS v3: the pairing check e(C, g2) == e(Y, K), batched over all n via
     * the "Cashu_BLS_Batch_v1" Fiat-Shamir transcript when n > 1.)
     * Ks: n * mint_key_len bytes concatenated; Cs: n * point_len bytes
     * concatenated; secrets/secret_lens: n pointers + lengths. Returns 1 iff
     * ALL n verify. NULL when the scheme has no intrinsic verification (secp:
     * DLEQ needs mint cooperation, so this cannot exist). The wallet branches
     * on capability — has_dleq vs verify_proofs != NULL — never on curve. */
    int (*verify_proofs)(void *ctx, size_t n,
                         const unsigned char *Ks,
                         const unsigned char *Cs,
                         const unsigned char *const *secrets,
                         const size_t *secret_lens);

    /* NUT-13: deterministic secret / blinding-factor derivation. Already
     * byte-oriented in crypto.h, so the secp suite binds these directly.
     * secret_out / r_out are scalar_len bytes. keyset_id is the hex string. */
    int (*derive_secret)(const unsigned char *seed, size_t seed_len,
                         const char *keyset_id, uint32_t counter,
                         unsigned char *secret_out);
    int (*derive_r)(const unsigned char *seed, size_t seed_len,
                    const char *keyset_id, uint32_t counter,
                    unsigned char *r_out);
};

/* The secp256k1 BDHKE suite (NUT-00/11/12/13). Defined in crypto.c. */
extern const cashu_suite_t cashu_suite_secp256k1;

/* BLS12-381 suite (keyset v3), defined in crypto_bls.c over the blst
 * component. Verification is intrinsic (verify_proofs); no NUT-12 DLEQ. */
extern const cashu_suite_t cashu_suite_bls;

/* One-shot SHA-256 (mbedtls wrapper). out must hold 32 bytes. Returns 1/0.
 * Lives here so the keyset-id codec can hash without pulling in secp256k1.h. */
int cashu_sha256(const unsigned char *data, size_t len, unsigned char out[32]);

/* NUT-13 KDF: HMAC_SHA256(seed, "Cashu_KDF_HMAC_SHA256" || keyset_id_bytes ||
 * counter_be64 || type_byte || suffix). suffix may be NULL/0 (v1/v2); the BLS
 * v3 blinding factor passes u32_BE(attempt) for rejection sampling. Declared
 * here (implemented in crypto.c over mbedtls) so crypto_bls.c shares the KDF
 * without pulling in secp256k1 headers. Returns 1/0. */
int cashu_nut13_hmac(const unsigned char *seed, size_t seed_len,
                     const char *keyset_id, uint32_t counter,
                     unsigned char type_byte,
                     const unsigned char *suffix, size_t suffix_len,
                     unsigned char digest[32]);

#ifdef __cplusplus
}
#endif

