/*
 * Cashu BDHKE / NUT-12 / NUT-13 fast secp256k1 primitives.
 *
 * Includes upstream libsecp256k1's secp256k1.c untouched so we can use its
 * internal group/field/multi-scalar-multiplication routines directly without
 * modifying the git submodule:
 *   - Shamir's trick + GLV endomorphism for R1 = (-e)*A + s*G
 *   - 2-point Strauss wNAF + GLV for R2 = s*B_ + (-e)*C_
 *   - Batch Jacobian->affine inversion (Montgomery's trick) for R1, R2 [, C_]
 *   - Safegcd Jacobi pre-filter before fe_sqrt in hash_to_curve
 *   - Constant-time ecmult_gen / ecmult_const preserved for secret scalar r
 *   - Stack-only HMAC-SHA256 for NUT-13 KDF (zero heap churn)
 */
#include "secp256k1.c"
#include "secp256k1_cashu.h"
#include "sha/sha_core.h"
#include <mbedtls/sha256.h>

static const unsigned char CASHU_H2C_DOMAIN[28] = "Secp256k1_HashToCurve_Cashu_";

static void cashu_hw_sha256_2(const unsigned char *a, size_t a_len,
                              const unsigned char *b, size_t b_len,
                              unsigned char out[32])
{
    /* Fast path for small inputs (secrets, NUT-13 KDF messages): assemble on
     * stack and invoke ESP32-C3 hardware SHA-256 in a single call. */
    if (a_len + b_len <= 160) {
        unsigned char tmp[160];
        memcpy(tmp, a, a_len);
        if (b_len > 0)
            memcpy(tmp + a_len, b, b_len);
        esp_sha(SHA2_256, tmp, a_len + b_len, out);
        return;
    }
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);
    mbedtls_sha256_update(&sha, a, a_len);
    if (b_len > 0)
        mbedtls_sha256_update(&sha, b, b_len);
    mbedtls_sha256_finish(&sha, out);
    mbedtls_sha256_free(&sha);
}

static int cashu_hash_to_curve_ge(secp256k1_ge *out,
                                  const unsigned char *msg,
                                  size_t msg_len)
{
    unsigned char buf[36];
    cashu_hw_sha256_2(CASHU_H2C_DOMAIN, sizeof(CASHU_H2C_DOMAIN), msg, msg_len, buf);

    for (uint32_t counter = 0; counter < 65536; counter++) {
        buf[32] = (unsigned char)(counter & 0xff);
        buf[33] = (unsigned char)((counter >> 8) & 0xff);
        buf[34] = (unsigned char)((counter >> 16) & 0xff);
        buf[35] = (unsigned char)((counter >> 24) & 0xff);

        unsigned char hash[32];
        esp_sha(SHA2_256, buf, sizeof(buf), hash);

        secp256k1_fe x;
        if (!secp256k1_fe_set_b32_limit(&x, hash))
            continue;

        /* rhs = x^3 + 7; reject non-squares via Safegcd Jacobi before fe_sqrt. */
        secp256k1_fe x2, rhs;
        secp256k1_fe_sqr(&x2, &x);
        secp256k1_fe_mul(&rhs, &x2, &x);
        secp256k1_fe_add_int(&rhs, SECP256K1_B);
        if (!secp256k1_fe_is_square_var(&rhs))
            continue;

        secp256k1_fe y;
        if (!secp256k1_fe_sqrt(&y, &rhs))
            continue;
        secp256k1_fe_normalize_var(&y);
        if (secp256k1_fe_is_odd(&y)) {
            secp256k1_fe_negate(&y, &y, 1);
            secp256k1_fe_normalize_var(&y);
        }
        secp256k1_ge_set_xy(out, &x, &y);
        return 1;
    }

    return 0;
}

static void cashu_hash_e_ge(unsigned char out[32],
                            const secp256k1_ge *p0,
                            const secp256k1_ge *p1,
                            const secp256k1_ge *p2,
                            const secp256k1_ge *p3)
{
    static const char digits[16] = "0123456789abcdef";
    const secp256k1_ge *pts[4] = { p0, p1, p2, p3 };
    unsigned char hex[4 * 130];

    for (int k = 0; k < 4; k++) {
        secp256k1_ge pt = *pts[k];
        unsigned char raw[65];
        secp256k1_eckey_pubkey_serialize65(&pt, raw);
        unsigned char *dst = hex + k * 130;
        for (int i = 0; i < 65; i++) {
            dst[i * 2]     = (unsigned char)digits[raw[i] >> 4];
            dst[i * 2 + 1] = (unsigned char)digits[raw[i] & 0x0F];
        }
    }
    esp_sha(SHA2_256, hex, sizeof(hex), out);
}

static int cashu_blind_ge(const secp256k1_context *ctx,
                          secp256k1_ge *B_out,
                          const unsigned char *secret,
                          size_t secret_len,
                          const unsigned char r[32])
{
    secp256k1_ge Y;
    if (!cashu_hash_to_curve_ge(&Y, secret, secret_len))
        return 0;

    secp256k1_scalar sc_r;
    if (!secp256k1_scalar_set_b32_seckey(&sc_r, r)) {
        secp256k1_scalar_clear(&sc_r);
        return 0;
    }

    secp256k1_gej rj;
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &sc_r);
    secp256k1_scalar_clear(&sc_r);

    secp256k1_gej_add_ge(&rj, &rj, &Y);
    if (secp256k1_gej_is_infinity(&rj)) {
        secp256k1_gej_clear(&rj);
        return 0;
    }
    secp256k1_ge_set_gej(B_out, &rj);
    secp256k1_gej_clear(&rj);
    return 1;
}

static int cashu_unblind_ge(secp256k1_ge *C_out,
                            const secp256k1_ge *C_,
                            const unsigned char r[32],
                            const secp256k1_ge *K)
{
    secp256k1_scalar sc_r;
    if (!secp256k1_scalar_set_b32_seckey(&sc_r, r)) {
        secp256k1_scalar_clear(&sc_r);
        return 0;
    }

    /* Matches original secp256k1_ec_pubkey_tweak_mul (GLV wNAF ecmult) while
     * eliminating the intermediate affine inversion and pubkey save/load. */
    secp256k1_gej K_j, rK_j;
    secp256k1_gej_set_ge(&K_j, K);
    secp256k1_ecmult(&rK_j, &K_j, &sc_r, NULL);
    secp256k1_scalar_clear(&sc_r);

    secp256k1_gej_neg(&rK_j, &rK_j);
    secp256k1_gej_add_ge_var(&rK_j, &rK_j, C_, NULL);
    if (secp256k1_gej_is_infinity(&rK_j)) {
        secp256k1_gej_clear(&rK_j);
        return 0;
    }
    secp256k1_ge_set_gej_var(C_out, &rK_j);
    secp256k1_gej_clear(&rK_j);
    return 1;
}

static int cashu_verify_dleq_ge(const secp256k1_ge *A,
                                const secp256k1_ge *B_,
                                const secp256k1_ge *C_,
                                const unsigned char e[32],
                                const unsigned char s[32])
{
    secp256k1_scalar sc_e, sc_s, neg_e;
    int overflow = 0;

    secp256k1_scalar_set_b32(&sc_e, e, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&sc_e))
        return 0;
    secp256k1_scalar_set_b32(&sc_s, s, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&sc_s))
        return 0;
    secp256k1_scalar_negate(&neg_e, &sc_e);

    /* R1 = (-e)*A + s*G */
    secp256k1_gej A_j, R1_j;
    secp256k1_gej_set_ge(&A_j, A);
    secp256k1_ecmult(&R1_j, &A_j, &neg_e, &sc_s);
    if (secp256k1_gej_is_infinity(&R1_j))
        return 0;

    /* R2 = s*B_ + (-e)*C_ in a single 2-point Strauss wNAF + GLV pass */
    secp256k1_gej R2_j;
    {
        secp256k1_fe aux[2 * ECMULT_TABLE_SIZE(WINDOW_A)];
        secp256k1_ge pre_a[2 * ECMULT_TABLE_SIZE(WINDOW_A)];
        struct secp256k1_strauss_point_state ps[2];
        struct secp256k1_strauss_state state;
        secp256k1_gej pts[2];
        secp256k1_scalar scs[2];

        state.aux = aux;
        state.pre_a = pre_a;
        state.ps = ps;
        secp256k1_gej_set_ge(&pts[0], B_);
        secp256k1_gej_set_ge(&pts[1], C_);
        scs[0] = sc_s;
        scs[1] = neg_e;
        secp256k1_ecmult_strauss_wnaf(&state, &R2_j, 2, pts, scs, NULL);
    }
    if (secp256k1_gej_is_infinity(&R2_j))
        return 0;

    /* Single modular inversion for both R1 and R2 */
    secp256k1_gej rj[2] = { R1_j, R2_j };
    secp256k1_ge  rg[2];
    secp256k1_ge_set_all_gej_var(rg, rj, 2);

    unsigned char e_check[32];
    cashu_hash_e_ge(e_check, &rg[0], &rg[1], A, C_);

    return memcmp(e, e_check, 32) == 0 ? 1 : 0;
}

static int cashu_verify_dleq_unblinded_ge(const secp256k1_context *ctx,
                                          const secp256k1_ge *A,
                                          const secp256k1_ge *C,
                                          const unsigned char *secret,
                                          size_t secret_len,
                                          const unsigned char e[32],
                                          const unsigned char s[32],
                                          const unsigned char r[32])
{
    secp256k1_scalar sc_e, sc_s, sc_r, neg_e;
    int overflow = 0;

    secp256k1_scalar_set_b32(&sc_e, e, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&sc_e))
        return 0;
    secp256k1_scalar_set_b32(&sc_s, s, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&sc_s))
        return 0;
    secp256k1_scalar_set_b32(&sc_r, r, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&sc_r))
        return 0;
    secp256k1_scalar_negate(&neg_e, &sc_e);

    secp256k1_ge Y;
    if (!cashu_hash_to_curve_ge(&Y, secret, secret_len))
        return 0;

    /* B_ = Y + r*G (fast 2 KB comb table, stays in Jacobian — no inversion) */
    secp256k1_gej B__j;
    if (secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx)) {
        secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &B__j, &sc_r);
    } else {
        secp256k1_gej zero;
        secp256k1_gej_set_infinity(&zero);
        secp256k1_ecmult(&B__j, &zero, &sc_r, &sc_r);
    }
    secp256k1_gej_add_ge_var(&B__j, &B__j, &Y, NULL);
    if (secp256k1_gej_is_infinity(&B__j))
        return 0;

    /* C_ = C + r*A (stays in Jacobian; inverted alongside R1, R2 at the end) */
    secp256k1_gej A_j, C__j;
    secp256k1_gej_set_ge(&A_j, A);
    secp256k1_ecmult(&C__j, &A_j, &sc_r, NULL);
    secp256k1_gej_add_ge_var(&C__j, &C__j, C, NULL);
    if (secp256k1_gej_is_infinity(&C__j))
        return 0;

    /* R1 = (-e)*A + s*G */
    secp256k1_gej R1_j;
    secp256k1_ecmult(&R1_j, &A_j, &neg_e, &sc_s);
    if (secp256k1_gej_is_infinity(&R1_j))
        return 0;

    /* R2 = s*B_ + (-e)*C_ via 2-point Strauss wNAF directly on Jacobian B_, C_
     * (faster and ~1.1 KB less stack than 3-point+G Strauss). */
    secp256k1_gej R2_j;
    {
        secp256k1_fe aux[2 * ECMULT_TABLE_SIZE(WINDOW_A)];
        secp256k1_ge pre_a[2 * ECMULT_TABLE_SIZE(WINDOW_A)];
        struct secp256k1_strauss_point_state ps[2];
        struct secp256k1_strauss_state state;
        secp256k1_gej pts[2] = { B__j, C__j };
        secp256k1_scalar scs[2] = { sc_s, neg_e };

        state.aux = aux;
        state.pre_a = pre_a;
        state.ps = ps;
        secp256k1_ecmult_strauss_wnaf(&state, &R2_j, 2, pts, scs, NULL);
    }
    if (secp256k1_gej_is_infinity(&R2_j))
        return 0;

    /* Single modular inversion for R1, R2, and C_ */
    secp256k1_gej rj[3] = { R1_j, R2_j, C__j };
    secp256k1_ge  rg[3];
    secp256k1_ge_set_all_gej_var(rg, rj, 3);

    unsigned char e_check[32];
    cashu_hash_e_ge(e_check, &rg[0], &rg[1], A, &rg[2]);

    return memcmp(e, e_check, 32) == 0 ? 1 : 0;
}

/* -------------------------------------------------------------------------
 * Public C API
 * ------------------------------------------------------------------------- */

int secp256k1_cashu_hash_to_curve(const secp256k1_context *ctx,
                                  secp256k1_pubkey *out,
                                  const unsigned char *msg,
                                  size_t msg_len)
{
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(out != NULL);
    ARG_CHECK(msg != NULL || msg_len == 0);
    secp256k1_ge ge;
    if (!cashu_hash_to_curve_ge(&ge, msg, msg_len))
        return 0;
    secp256k1_pubkey_save(out, &ge);
    return 1;
}

int secp256k1_cashu_blind_message(const secp256k1_context *ctx,
                                  secp256k1_pubkey *B_out,
                                  const unsigned char *secret,
                                  size_t secret_len,
                                  const unsigned char r[32])
{
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(B_out != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(secret != NULL || secret_len == 0);
    ARG_CHECK(r != NULL);
    secp256k1_ge B;
    if (!cashu_blind_ge(ctx, &B, secret, secret_len, r))
        return 0;
    secp256k1_pubkey_save(B_out, &B);
    return 1;
}

int secp256k1_cashu_blind_message_ser(const secp256k1_context *ctx,
                                      unsigned char B_out33[33],
                                      const unsigned char *secret,
                                      size_t secret_len,
                                      const unsigned char r[32])
{
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(B_out33 != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(secret != NULL || secret_len == 0);
    ARG_CHECK(r != NULL);
    secp256k1_ge B;
    if (!cashu_blind_ge(ctx, &B, secret, secret_len, r))
        return 0;
    secp256k1_eckey_pubkey_serialize33(&B, B_out33);
    return 1;
}

int secp256k1_cashu_unblind(const secp256k1_context *ctx,
                            secp256k1_pubkey *C_out,
                            const secp256k1_pubkey *C_,
                            const unsigned char r[32],
                            const secp256k1_pubkey *K)
{
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(C_out != NULL && C_ != NULL && r != NULL && K != NULL);
    secp256k1_ge C__ge, K_ge, C_ge;
    if (!secp256k1_pubkey_load(ctx, &C__ge, C_) ||
        !secp256k1_pubkey_load(ctx, &K_ge, K))
        return 0;
    if (!cashu_unblind_ge(&C_ge, &C__ge, r, &K_ge))
        return 0;
    secp256k1_pubkey_save(C_out, &C_ge);
    return 1;
}

int secp256k1_cashu_unblind_ser(const secp256k1_context *ctx,
                                unsigned char C_out33[33],
                                const unsigned char C_33[33],
                                const unsigned char r[32],
                                const unsigned char K33[33])
{
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(C_out33 != NULL && C_33 != NULL && r != NULL && K33 != NULL);
    secp256k1_ge C__ge, K_ge, C_ge;
    if (!secp256k1_eckey_pubkey_parse(&C__ge, C_33, 33) ||
        !secp256k1_eckey_pubkey_parse(&K_ge, K33, 33))
        return 0;
    if (!cashu_unblind_ge(&C_ge, &C__ge, r, &K_ge))
        return 0;
    secp256k1_eckey_pubkey_serialize33(&C_ge, C_out33);
    return 1;
}

int secp256k1_cashu_verify_dleq(const secp256k1_context *ctx,
                                const secp256k1_pubkey *A,
                                const secp256k1_pubkey *B_,
                                const secp256k1_pubkey *C_,
                                const unsigned char e[32],
                                const unsigned char s[32])
{
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(A != NULL && B_ != NULL && C_ != NULL && e != NULL && s != NULL);
    secp256k1_ge A_ge, B_ge, C_ge;
    if (!secp256k1_pubkey_load(ctx, &A_ge, A) ||
        !secp256k1_pubkey_load(ctx, &B_ge, B_) ||
        !secp256k1_pubkey_load(ctx, &C_ge, C_))
        return 0;
    return cashu_verify_dleq_ge(&A_ge, &B_ge, &C_ge, e, s);
}

int secp256k1_cashu_verify_dleq_ser(const secp256k1_context *ctx,
                                    const unsigned char A33[33],
                                    const unsigned char B_33[33],
                                    const unsigned char C_33[33],
                                    const unsigned char e[32],
                                    const unsigned char s[32])
{
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(A33 != NULL && B_33 != NULL && C_33 != NULL && e != NULL && s != NULL);
    secp256k1_ge A_ge, B_ge, C_ge;
    if (!secp256k1_eckey_pubkey_parse(&A_ge, A33, 33) ||
        !secp256k1_eckey_pubkey_parse(&B_ge, B_33, 33) ||
        !secp256k1_eckey_pubkey_parse(&C_ge, C_33, 33))
        return 0;
    return cashu_verify_dleq_ge(&A_ge, &B_ge, &C_ge, e, s);
}

int secp256k1_cashu_verify_dleq_and_unblind_ser(const secp256k1_context *ctx,
                                                const unsigned char K33[33],
                                                const unsigned char B_33[33],
                                                const unsigned char C_33[33],
                                                const unsigned char e[32],
                                                const unsigned char s[32],
                                                const unsigned char r[32],
                                                unsigned char C_out33[33])
{
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(K33 != NULL && B_33 != NULL && C_33 != NULL &&
              e != NULL && s != NULL && r != NULL && C_out33 != NULL);
    secp256k1_ge K_ge, B_ge, C__ge, C_ge;
    if (!secp256k1_eckey_pubkey_parse(&K_ge, K33, 33) ||
        !secp256k1_eckey_pubkey_parse(&B_ge, B_33, 33) ||
        !secp256k1_eckey_pubkey_parse(&C__ge, C_33, 33))
        return 0;
    if (!cashu_verify_dleq_ge(&K_ge, &B_ge, &C__ge, e, s))
        return 0;
    if (!cashu_unblind_ge(&C_ge, &C__ge, r, &K_ge))
        return 0;
    secp256k1_eckey_pubkey_serialize33(&C_ge, C_out33);
    return 1;
}

int secp256k1_cashu_verify_dleq_unblinded(const secp256k1_context *ctx,
                                          const secp256k1_pubkey *A,
                                          const secp256k1_pubkey *C,
                                          const unsigned char *secret,
                                          size_t secret_len,
                                          const unsigned char e[32],
                                          const unsigned char s[32],
                                          const unsigned char r[32])
{
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(A != NULL && C != NULL && (secret != NULL || secret_len == 0) &&
              e != NULL && s != NULL && r != NULL);
    secp256k1_ge A_ge, C_ge;
    if (!secp256k1_pubkey_load(ctx, &A_ge, A) ||
        !secp256k1_pubkey_load(ctx, &C_ge, C))
        return 0;
    return cashu_verify_dleq_unblinded_ge(ctx, &A_ge, &C_ge, secret, secret_len, e, s, r);
}

int secp256k1_cashu_verify_dleq_unblinded_ser(const secp256k1_context *ctx,
                                              const unsigned char A33[33],
                                              const unsigned char C33[33],
                                              const unsigned char *secret,
                                              size_t secret_len,
                                              const unsigned char e[32],
                                              const unsigned char s[32],
                                              const unsigned char r[32])
{
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(A33 != NULL && C33 != NULL && (secret != NULL || secret_len == 0) &&
              e != NULL && s != NULL && r != NULL);
    secp256k1_ge A_ge, C_ge;
    if (!secp256k1_eckey_pubkey_parse(&A_ge, A33, 33) ||
        !secp256k1_eckey_pubkey_parse(&C_ge, C33, 33))
        return 0;
    return cashu_verify_dleq_unblinded_ge(ctx, &A_ge, &C_ge, secret, secret_len, e, s, r);
}

void secp256k1_cashu_hmac_sha256(const unsigned char *key, size_t key_len,
                                 const unsigned char *msg, size_t msg_len,
                                 unsigned char out32[32])
{
    unsigned char kblock[64];
    memset(kblock, 0, sizeof(kblock));
    if (key_len > 64) {
        esp_sha(SHA2_256, key, key_len, kblock);
    } else if (key_len > 0) {
        memcpy(kblock, key, key_len);
    }

    unsigned char ipad[64], opad[96];
    for (int i = 0; i < 64; i++) {
        ipad[i] = kblock[i] ^ 0x36;
        opad[i] = kblock[i] ^ 0x5c;
    }

    unsigned char inner[32];
    cashu_hw_sha256_2(ipad, 64, msg, msg_len, inner);
    memcpy(opad + 64, inner, 32);
    esp_sha(SHA2_256, opad, sizeof(opad), out32);

    secp256k1_memclear_explicit(kblock, sizeof(kblock));
    secp256k1_memclear_explicit(ipad, sizeof(ipad));
    secp256k1_memclear_explicit(opad, sizeof(opad));
    secp256k1_memclear_explicit(inner, sizeof(inner));
}
