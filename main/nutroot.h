#pragma once

#include <stdint.h>
#include <stddef.h>
#include <secp256k1.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Nutroot secrets (v3 keysets, NUT-10 rev. cashubtc/nuts#421): taproot-style
 * commitments in the proof secret. A v3 secret is a 33-byte compressed
 * secp256k1 point P = K + t*G committing to a merkle tree of declarative
 * condition leaves; spends carry a BIP-340 witness over the transaction
 * digest, key-path (one signature by P's key) or script-path (reveal one
 * leaf, its merkle path, and enough signatures to satisfy it).
 *
 * Current rules are pinned to cashubtc/nuts#421, head a3f04b97154b
 * (2026-09-10): per-input signing digests, version-based routing, 512-byte
 * leaf bodies, eight leaves, and disclosure mode 1. Historical transcript
 * entry points exist only for reproducing the original benchmark.
 *
 * Like crypto_bls.c this file is ESP-free (secp256k1 + mbedtls + cJSON +
 * libc only) so a host harness can compile it verbatim; cJSON must be
 * vendored alongside on the host.
 */

#define NUTROOT_POINT_LEN        33
#define NUTROOT_LEAF_VERSION     0x00
#define NUTROOT_LEAF_THRESHOLD   0x01
#define NUTROOT_LEAF_AFTER       0x02
#define NUTROOT_LEAF_HASHLOCK    0x03
/* Normative caps. The leaf body excludes the leading version byte. */
#define NUTROOT_MAX_LEAF_BODY    512
#define NUTROOT_MAX_TREE_DEPTH   3
#define NUTROOT_MAX_WITNESS_LEN  4096
/* Largest `after` time: 2^53 - 1, where IEEE-754 integers stop counting. */
#define NUTROOT_MAX_LEAF_TIME    ((int64_t)0x1FFFFFFFFFFFFF)

/* All functions return 1 on success / valid, 0 on failure (fail closed). */

/* BIP340-style tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg). */
int nutroot_tagged_hash(const char *tag,
                        const unsigned char *msg, size_t len,
                        unsigned char out[32]);

/* ------------------------------------------------------------------ leaves */

/* A parsed declarative leaf (version 0x00). Pointers borrow from the
 * serialized buffer handed to nutroot_leaf_parse. */
typedef struct {
    uint8_t type;                /* NUTROOT_LEAF_* */
    uint8_t n;                   /* threshold, 1..num_keys */
    uint8_t num_keys;
    uint8_t disclosure;          /* 0 absent, 1 publish exercised witness */
    const unsigned char *keys;   /* num_keys * 33 bytes, concatenated */
    int64_t time;                /* after leaves; 0 otherwise */
    const unsigned char *hash;   /* 32 bytes for hashlock leaves; NULL else */
} nutroot_leaf_t;

/* Serialize a leaf: version || type || field TLVs (type 1B, len 2B BE).
 * keys is num_keys*33 bytes; time only for after, hash32 only for hashlock.
 * *out_len is in/out (capacity in, bytes written out). */
int nutroot_leaf_build(uint8_t type, uint8_t n,
                       const unsigned char *keys, uint8_t num_keys,
                       int64_t time, const unsigned char *hash32,
                       unsigned char *out, size_t *out_len);

/* Parse + validate a serialized leaf. Rejects unknown version/type/field,
 * non-ascending TLVs, invalid or duplicate-x keys, n out of range, and
 * fields a type does not define. */
int nutroot_leaf_parse(const secp256k1_context *ctx,
                       const unsigned char *leaf, size_t len,
                       nutroot_leaf_t *out);

/* tagged_hash("Cashu_NutrootLeaf", serialized_leaf). */
int nutroot_leaf_hash(const unsigned char *leaf, size_t len,
                      unsigned char out[32]);

/* ------------------------------------------------------------------ merkle */

/* Fold n leaf hashes to the root: sorted ascending, pairwise sorted-pair
 * branch hashing, odd hash promoted unchanged. hashes (n*32 bytes) is
 * CLOBBERED (sorted and folded in place) so callers of arbitrary n need no
 * separate scratch. n must be 1..2^NUTROOT_MAX_TREE_DEPTH. */
int nutroot_merkle_root(unsigned char *hashes, size_t n,
                        unsigned char root[32]);

/* Merkle path (sibling hashes leaf-to-root) for the leaf at index into the
 * transmitted order. hashes is CLOBBERED. path holds up to
 * NUTROOT_MAX_TREE_DEPTH * 32 bytes. */
int nutroot_merkle_path(unsigned char *hashes, size_t n, size_t index,
                        unsigned char *path, size_t *path_len);

/* Recompute a root from a leaf hash and its path (verification side). */
int nutroot_root_from_path(const unsigned char leaf_hash[32],
                           const unsigned char *path, size_t path_len,
                           unsigned char root[32]);

/* ------------------------------------------------------------------- tweak */

/* t = tagged_hash("Cashu_NutrootTweak", K || root) mod curve order, reduced
 * and never rejected. root == NULL is the empty tweak (hash over K alone). */
int nutroot_tweak_scalar(const unsigned char K33[33],
                         const unsigned char *root /* 32 bytes or NULL */,
                         unsigned char t32[32]);

/* The v3 secret P = K + t*G. A zero tweak yields K itself. */
int nutroot_tweak_pubkey(const secp256k1_context *ctx,
                         const unsigned char K33[33],
                         const unsigned char *root /* 32 bytes or NULL */,
                         unsigned char P33[33]);

/* Verify n public commitments P_i=K_i+t(K_i,root_i)G. Arrays P/K contain
 * n compressed points; roots is n pointers, each 32 bytes or NULL (empty
 * tweak, as in nutroot_tweak_pubkey; this is not an untweaked bare point).
 * Validating the tree/leaf policy remains the caller's responsibility.
 * Bounded batches of at most 32, full-width transcript-derived weights,
 * individual verification on allocation failure; zero count succeeds. */
int nutroot_verify_commitments(const secp256k1_context *ctx,size_t n,
                               const unsigned char *points,const unsigned char *keys,
                               const unsigned char *const *roots);

/* Key-path signing key p' = (k + t) mod n. sk32 is updated in place. */
int nutroot_tweak_seckey(const secp256k1_context *ctx,
                         unsigned char sk32[32],
                         const unsigned char *root /* 32 bytes or NULL */);

/* ------------------------------------------------- transaction transcript */

/* Amounts are minimal big-endian (zero = zero-length). keyset_id is raw
 * bytes (hex ids decode, anything else contributes utf8 bytes — caller's
 * job). secret is the bytes the proof contributes: the 33-byte point for
 * v3, the secret's utf8 bytes for v0-v2 inputs in mixed transactions. */
typedef struct {
    uint64_t amount;
    const unsigned char *keyset_id; size_t keyset_id_len;
    const unsigned char *secret;    size_t secret_len;
    const unsigned char *C;         size_t C_len;
    const char *witness;            /* raw witness JSON; NULL = none */
} nutroot_input_t;

typedef struct {
    uint64_t amount;
    const unsigned char *keyset_id; size_t keyset_id_len;
    const unsigned char *B_;        size_t B_len;
} nutroot_output_t;

typedef struct {
    uint64_t amount;
    const char *quote_id;           /* utf8, non-empty */
} nutroot_quote_t;

/* Mirrors nutshell's TransactionShape: containers 0x01 proof input, 0x02
 * mint quote input, 0x03 blinded output, 0x04 melt quote output; types
 * ascend, request order within a type. */
typedef struct {
    const nutroot_input_t  *proof_inputs;       size_t n_proof_inputs;
    const nutroot_quote_t  *mint_quote_inputs;  size_t n_mint_quote_inputs;
    const nutroot_output_t *blinded_outputs;    size_t n_blinded_outputs;
    const nutroot_quote_t  *melt_quote_outputs; size_t n_melt_quote_outputs;
} nutroot_tx_t;

/* SHA256(TLV transcript), shared by all inputs but never signed directly. */
int nutroot_tx_digest(const nutroot_tx_t *tx, unsigned char digest[32]);
/* tagged_hash("Cashu_TransactionInput", tx_digest || SHA256(input container)). */
int nutroot_input_digest(const unsigned char tx_digest[32],
                         const nutroot_input_t *input, unsigned char digest[32]);
int nutroot_quote_input_digest(const unsigned char tx_digest[32],
                               const nutroot_quote_t *input, unsigned char digest[32]);

/* Verifies proof-input witnesses, selecting v3 by keyset version >= 0x02.
 * The caller must separately validate the transaction, BLS signatures,
 * duplicate proofs, keyset authorization and pre-v3 spending rules. */
int nutroot_verify_transaction(const secp256k1_context *ctx,
                               const nutroot_tx_t *tx, int64_t now);

/* Historical benchmark compatibility only; not current-proposal validation. */
int nutroot_legacy_tx_digest(const nutroot_tx_t *tx, unsigned char digest[32]);
int nutroot_legacy_verify_transaction(const secp256k1_context *ctx,
                                      const nutroot_tx_t *tx, int64_t now);

/* NUT-28 raw x-coordinate ECDH and slot KDF. The ordinary secp ECDH default
 * hashes the shared point and must NOT be substituted for this operation.
 * The caller supplies a fresh ephemeral key for every output, matches derived
 * slots by value and erases the returned shared secret when finished. */
int nutroot_ecdh_x(const secp256k1_context *ctx, const unsigned char sk[32],
                   const unsigned char peer[33], unsigned char shared_x[32]);
int nutroot_p2bk_scalar(const secp256k1_context *ctx, const unsigned char shared_x[32],
                        unsigned slot, unsigned char scalar[32]);

/* BIP-340 sign a 32-byte digest directly, zero aux randomness (matches the
 * shared vectors; cashu_schnorr_sign_secret pre-hashes and cannot be used
 * for witness signatures). */
int nutroot_sign_digest(const secp256k1_context *ctx,
                        const unsigned char priv32[32],
                        const unsigned char digest[32],
                        unsigned char sig64[64]);

/* Cooperative-yield hook called between inputs and every few signature
 * verifies inside nutroot_verify_transaction. NULL (default) disables it;
 * the benchmark installs a FreeRTOS yield only for rows whose single call
 * outlasts the idle task watchdog. */
void nutroot_set_yield_hook(void (*hook)(void));

/* Diagnostic comparison: 0 = historical loop, 1 = decode once + early
 * completion, 3 = also try the corresponding signature first; bit 2 reuses parsed
 * leaf public keys and bit 3 reuses constant tag hashes. Bit 4 enables
 * BIP-340 batch equations; bit 5 selects Pippenger instead of Strauss.
 * Bit 6 avoids tiny batches and shrinks chunks to fit available scratch.
 * Default 95 enables adaptive Strauss batching and allocation fallback. */
void nutroot_set_optimizations(unsigned flags);
unsigned nutroot_optimizations(void);

/* BIP-340 verify calls made inside nutroot_verify_transaction since the
 * caller last reset it. The benchmark reports it per case, mirroring
 * nutshell's schnorr-verify counter. Diagnostic only, not thread-safe. */
extern unsigned long nutroot_stat_sig_verifies;
extern unsigned long nutroot_stat_batch_verifies;

#ifdef __cplusplus
}
#endif
