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
 * A future session implements the BLS math here — pairing-based verification on
 * BLS12-381 — and flips can_mint. Expected shape when implemented:
 *   - pubkey_len = 48 (compressed G1); revisit if the scheme uses G2 (96).
 *   - blind/unblind per the (draft) v3 spec.
 *   - DLEQ is likely superseded by public pairing-based verifiability, so
 *     has_dleq may remain 0; verify_dleq* would then stay unused.
 * Only the function bodies below and the v3 keyset-id codec should need to
 * change — the wallet, CBOR, JSON, and persistence layers are already routed
 * through cashu_suite_t and suite_for_id().
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

static int bls_verify_dleq(void *ctx,
                           const unsigned char *A, size_t A_len,
                           const unsigned char *B_, size_t B__len,
                           const unsigned char *C_, size_t C__len,
                           const unsigned char *e, const unsigned char *s)
{
    (void)ctx; (void)A; (void)A_len; (void)B_; (void)B__len;
    (void)C_; (void)C__len; (void)e; (void)s;
    return 0; /* TODO(v3): pairing-based verification */
}

static int bls_verify_dleq_unblinded(void *ctx,
                                     const unsigned char *A, size_t A_len,
                                     const unsigned char *C, size_t C_len,
                                     const unsigned char *secret, size_t secret_len,
                                     const unsigned char *e, const unsigned char *s,
                                     const unsigned char *r)
{
    (void)ctx; (void)A; (void)A_len; (void)C; (void)C_len;
    (void)secret; (void)secret_len; (void)e; (void)s; (void)r;
    return 0; /* TODO(v3) */
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
    .pubkey_len = 48, /* compressed G1; revisit if v3 uses G2 (96) */
    .scalar_len = 32,
    .can_mint = 0,    /* scaffold: not implemented, never selected for minting */
    .has_dleq = 0,
    .blind = bls_blind,
    .unblind = bls_unblind,
    .verify_dleq = bls_verify_dleq,
    .verify_dleq_unblinded = bls_verify_dleq_unblinded,
    .derive_secret = bls_derive_secret,
    .derive_r = bls_derive_r,
};
