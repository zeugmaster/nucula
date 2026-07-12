#include "cashu_suite.h"

/*
 * BLS12-381 crypto-suite SCAFFOLD (keyset v3, version byte 0x02).
 *
 * This is a NON-FUNCTIONAL placeholder so the versioned-keyset machinery has a
 * concrete v3 seam to fill in. Every operation returns 0 (failure) and
 * can_mint is 0, so the wallet never selects this suite for minting and any
 * accidental use fails closed. The keyset-id codec for v3 (keyset.cpp) is
 * likewise a stub, so v3 keysets are rejected at load time until implemented.
 *
 * The real implementation (over the blst component) fills in the bodies
 * below and flips can_mint. Per the v3 spec (nuts PR #371): token points
 * are compressed G1 (48 B), mint keys compressed G2 (96 B), blinding is
 * multiplicative (B_ = r*Y, C = r^-1*C_), NUT-12 DLEQ is abolished in favor
 * of the intrinsic pairing check exposed through verify_proofs. Only the
 * function bodies here and the v3 keyset-id codec should need to change —
 * the wallet, CBOR, JSON, and persistence layers are already routed through
 * cashu_suite_t and suite_for_id().
 */

static int bls_blind(void *ctx,
                     const unsigned char *secret, size_t secret_len,
                     const unsigned char *r, size_t r_len,
                     unsigned char *B_out, size_t *B_out_len)
{
    (void)ctx; (void)secret; (void)secret_len; (void)r; (void)r_len;
    (void)B_out; (void)B_out_len;
    return 0; /* TODO(v3): BLS12-381 blinding */
}

static int bls_unblind(void *ctx,
                       const unsigned char *C_, size_t C__len,
                       const unsigned char *r, size_t r_len,
                       const unsigned char *K, size_t K_len,
                       unsigned char *C_out, size_t *C_out_len)
{
    (void)ctx; (void)C_; (void)C__len; (void)r; (void)r_len;
    (void)K; (void)K_len; (void)C_out; (void)C_out_len;
    return 0; /* TODO(v3) */
}

static int bls_verify_proofs(void *ctx, size_t n,
                             const unsigned char *Ks,
                             const unsigned char *Cs,
                             const unsigned char *const *secrets,
                             const size_t *secret_lens)
{
    (void)ctx; (void)n; (void)Ks; (void)Cs; (void)secrets; (void)secret_lens;
    return 0; /* TODO(v3): pairing check, Fiat-Shamir batched for n > 1 */
}

static int bls_derive_secret(const unsigned char *seed, size_t seed_len,
                             const char *keyset_id, uint32_t counter,
                             unsigned char *secret_out)
{
    (void)seed; (void)seed_len; (void)keyset_id; (void)counter; (void)secret_out;
    return 0; /* TODO(v3): NUT-13 over the BLS scalar field */
}

static int bls_derive_r(const unsigned char *seed, size_t seed_len,
                        const char *keyset_id, uint32_t counter,
                        unsigned char *r_out)
{
    (void)seed; (void)seed_len; (void)keyset_id; (void)counter; (void)r_out;
    return 0; /* TODO(v3) */
}

const cashu_suite_t cashu_suite_bls = {
    .version_byte = 0x02,
    .name = "bls12_381",
    .point_len = 48,    /* compressed G1: Y, B_, C_, C */
    .mint_key_len = 96, /* compressed G2: mint keys K  */
    .scalar_len = 32,
    .can_mint = 0,      /* scaffold: not implemented, never selected for minting */
    .has_dleq = 0,      /* NUT-12 does not apply to v3 — pairing verify instead */
    .blind = bls_blind,
    .unblind = bls_unblind,
    .verify_dleq = NULL,
    .verify_dleq_unblinded = NULL,
    .verify_proofs = bls_verify_proofs,
    .derive_secret = bls_derive_secret,
    .derive_r = bls_derive_r,
};
