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
 * Point buffers are SEC1-style serializations of length suite->pubkey_len
 * (33 for compressed secp256k1). Scalars (r, e, s) are suite->scalar_len (32).
 * Every function returns 1 on success, 0 on failure.
 */
/* Upper bound on a serialized point length across all suites, for fixed stack
 * buffers in callers (secp256k1 = 33, BLS12-381 G1 = 48). Bump if a future
 * suite uses larger points (e.g. G2 = 96). Callers size point buffers to this
 * and pass the suite's actual pubkey_len as the length. */
#define CASHU_MAX_POINT_LEN 48

typedef struct cashu_suite cashu_suite_t;

struct cashu_suite {
    unsigned char version_byte; /* keyset version this scheme serves (0x01 = secp v2) */
    const char   *name;         /* human-readable, e.g. "secp256k1" */
    size_t        pubkey_len;   /* serialized point length (33 secp / 48 BLS G1) */
    size_t        scalar_len;   /* scalar length in bytes (32) */
    int           can_mint;     /* scheme can sign/mint (0 = stub / not implemented) */
    int           has_dleq;     /* NUT-12 DLEQ supported by this scheme */

    /* B_ = blind(secret): writes the blinded point into B_out. *B_out_len is
     * in/out (buffer capacity in, bytes written out). r is the blinding
     * scalar (r_len bytes). */
    int (*blind)(void *ctx,
                 const unsigned char *secret, size_t secret_len,
                 const unsigned char *r, size_t r_len,
                 unsigned char *B_out, size_t *B_out_len);

    /* C = unblind(C_, r, K): removes the blinding from the mint's signature. */
    int (*unblind)(void *ctx,
                   const unsigned char *C_, size_t C__len,
                   const unsigned char *r, size_t r_len,
                   const unsigned char *K, size_t K_len,
                   unsigned char *C_out, size_t *C_out_len);

    /* NUT-12: Alice verifies the mint's DLEQ over (A, B_, C_) with (e, s). */
    int (*verify_dleq)(void *ctx,
                       const unsigned char *A, size_t A_len,
                       const unsigned char *B_, size_t B__len,
                       const unsigned char *C_, size_t C__len,
                       const unsigned char *e, const unsigned char *s);

    /* NUT-12: Carol verifies the DLEQ on an unblinded Proof, reconstructing
     * B_/C_ from the secret and the blinding factor r. */
    int (*verify_dleq_unblinded)(void *ctx,
                                 const unsigned char *A, size_t A_len,
                                 const unsigned char *C, size_t C_len,
                                 const unsigned char *secret, size_t secret_len,
                                 const unsigned char *e, const unsigned char *s,
                                 const unsigned char *r);

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

/* BLS12-381 suite (keyset v3). SCAFFOLD ONLY — defined in crypto_bls.c; all
 * ops are stubs and can_mint is 0 until a future session implements them. */
extern const cashu_suite_t cashu_suite_bls;

/* One-shot SHA-256 (mbedtls wrapper). out must hold 32 bytes. Returns 1/0.
 * Lives here so the keyset-id codec can hash without pulling in secp256k1.h. */
int cashu_sha256(const unsigned char *data, size_t len, unsigned char out[32]);

#ifdef __cplusplus
}
#endif

