#include "crypto.h"
#include <string.h>
#include <mbedtls/sha256.h>

static const char DOMAIN_SEPARATOR[] = "Secp256k1_HashToCurve_Cashu_";
#define DOMAIN_SEPARATOR_LEN 28

static void bytes_to_hex(const unsigned char *bytes, size_t len, char *hex)
{
    static const char lut[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        hex[i * 2]     = lut[(bytes[i] >> 4) & 0x0f];
        hex[i * 2 + 1] = lut[bytes[i] & 0x0f];
    }
    hex[len * 2] = '\0';
}

/*
 * hash_e for DLEQ verification (NUT-12).
 * Concatenates the 130-char hex representations (65-byte uncompressed with 0x04
 * prefix) of each public key, then takes SHA256 of that UTF-8 string.
 */
static int hash_e(const secp256k1_context *ctx,
                  unsigned char out[32],
                  const secp256k1_pubkey *keys,
                  size_t n_keys)
{
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    if (mbedtls_sha256_starts(&sha, 0) != 0)
        goto fail;

    for (size_t i = 0; i < n_keys; i++) {
        unsigned char buf[65];
        size_t len = sizeof(buf);
        if (!secp256k1_ec_pubkey_serialize(ctx, buf, &len,
                                           &keys[i], SECP256K1_EC_UNCOMPRESSED))
            goto fail;
        char hex[131];
        bytes_to_hex(buf, 65, hex);
        if (mbedtls_sha256_update(&sha, (const unsigned char *)hex, 130) != 0)
            goto fail;
    }

    if (mbedtls_sha256_finish(&sha, out) != 0)
        goto fail;

    mbedtls_sha256_free(&sha);
    return 1;

fail:
    mbedtls_sha256_free(&sha);
    return 0;
}

int cashu_hash_to_curve(const secp256k1_context *ctx,
                        secp256k1_pubkey *out,
                        const unsigned char *msg,
                        size_t msg_len)
{
    unsigned char msg_hash[32];
    {
        mbedtls_sha256_context sha;
        mbedtls_sha256_init(&sha);
        mbedtls_sha256_starts(&sha, 0);
        mbedtls_sha256_update(&sha,
                              (const unsigned char *)DOMAIN_SEPARATOR,
                              DOMAIN_SEPARATOR_LEN);
        mbedtls_sha256_update(&sha, msg, msg_len);
        mbedtls_sha256_finish(&sha, msg_hash);
        mbedtls_sha256_free(&sha);
    }

    for (uint32_t counter = 0; counter < 65536; counter++) {
        unsigned char hash[32];
        {
            unsigned char counter_le[4] = {
                (unsigned char)(counter & 0xff),
                (unsigned char)((counter >> 8) & 0xff),
                (unsigned char)((counter >> 16) & 0xff),
                (unsigned char)((counter >> 24) & 0xff),
            };
            mbedtls_sha256_context sha;
            mbedtls_sha256_init(&sha);
            mbedtls_sha256_starts(&sha, 0);
            mbedtls_sha256_update(&sha, msg_hash, 32);
            mbedtls_sha256_update(&sha, counter_le, 4);
            mbedtls_sha256_finish(&sha, hash);
            mbedtls_sha256_free(&sha);
        }

        unsigned char candidate[33];
        candidate[0] = 0x02;
        memcpy(candidate + 1, hash, 32);

        if (secp256k1_ec_pubkey_parse(ctx, out, candidate, 33))
            return 1;
    }

    return 0;
}

int cashu_blind_message(const secp256k1_context *ctx,
                        secp256k1_pubkey *B_out,
                        const unsigned char *secret,
                        size_t secret_len,
                        const unsigned char *r)
{
    secp256k1_pubkey Y;
    if (!cashu_hash_to_curve(ctx, &Y, secret, secret_len))
        return 0;

    secp256k1_pubkey rG;
    if (!secp256k1_ec_pubkey_create(ctx, &rG, r))
        return 0;

    const secp256k1_pubkey *pts[2] = {&Y, &rG};
    if (!secp256k1_ec_pubkey_combine(ctx, B_out, pts, 2))
        return 0;

    return 1;
}

int cashu_unblind(const secp256k1_context *ctx,
                  secp256k1_pubkey *C_out,
                  const secp256k1_pubkey *C_,
                  const unsigned char *r,
                  const secp256k1_pubkey *K)
{
    secp256k1_pubkey rK = *K;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &rK, r))
        return 0;

    secp256k1_ec_pubkey_negate(ctx, &rK);

    const secp256k1_pubkey *pts[2] = {C_, &rK};
    if (!secp256k1_ec_pubkey_combine(ctx, C_out, pts, 2))
        return 0;

    return 1;
}

int cashu_verify_dleq(const secp256k1_context *ctx,
                      const secp256k1_pubkey *A,
                      const secp256k1_pubkey *B_,
                      const secp256k1_pubkey *C_,
                      const unsigned char *e,
                      const unsigned char *s)
{
    /* R1 = s*G - e*A */
    secp256k1_pubkey sG;
    if (!secp256k1_ec_pubkey_create(ctx, &sG, s))
        return 0;

    secp256k1_pubkey eA = *A;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &eA, e))
        return 0;
    secp256k1_ec_pubkey_negate(ctx, &eA);

    secp256k1_pubkey R1;
    {
        const secp256k1_pubkey *pts[2] = {&sG, &eA};
        if (!secp256k1_ec_pubkey_combine(ctx, &R1, pts, 2))
            return 0;
    }

    /* R2 = s*B_ - e*C_ */
    secp256k1_pubkey sB = *B_;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &sB, s))
        return 0;

    secp256k1_pubkey eC = *C_;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &eC, e))
        return 0;
    secp256k1_ec_pubkey_negate(ctx, &eC);

    secp256k1_pubkey R2;
    {
        const secp256k1_pubkey *pts[2] = {&sB, &eC};
        if (!secp256k1_ec_pubkey_combine(ctx, &R2, pts, 2))
            return 0;
    }

    /* e_check = hash(R1, R2, A, C_) */
    secp256k1_pubkey keys[4] = {R1, R2, *A, *C_};
    unsigned char e_check[32];
    if (!hash_e(ctx, e_check, keys, 4))
        return 0;

    return memcmp(e, e_check, 32) == 0 ? 1 : 0;
}

int cashu_verify_dleq_unblinded(const secp256k1_context *ctx,
                                const secp256k1_pubkey *A,
                                const secp256k1_pubkey *C,
                                const unsigned char *secret,
                                size_t secret_len,
                                const unsigned char *e,
                                const unsigned char *s,
                                const unsigned char *r)
{
    /* Y = hash_to_curve(secret) */
    secp256k1_pubkey Y;
    if (!cashu_hash_to_curve(ctx, &Y, secret, secret_len))
        return 0;

    /* C_ = C + r*A */
    secp256k1_pubkey rA = *A;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &rA, r))
        return 0;

    secp256k1_pubkey C_;
    {
        const secp256k1_pubkey *pts[2] = {C, &rA};
        if (!secp256k1_ec_pubkey_combine(ctx, &C_, pts, 2))
            return 0;
    }

    /* B_ = Y + r*G */
    secp256k1_pubkey rG;
    if (!secp256k1_ec_pubkey_create(ctx, &rG, r))
        return 0;

    secp256k1_pubkey B_;
    {
        const secp256k1_pubkey *pts[2] = {&Y, &rG};
        if (!secp256k1_ec_pubkey_combine(ctx, &B_, pts, 2))
            return 0;
    }

    return cashu_verify_dleq(ctx, A, &B_, &C_, e, s);
}

int cashu_pubkey_serialize(const secp256k1_context *ctx,
                           unsigned char out[33],
                           const secp256k1_pubkey *pk)
{
    size_t len = 33;
    return secp256k1_ec_pubkey_serialize(ctx, out, &len,
                                         pk, SECP256K1_EC_COMPRESSED);
}

int cashu_pubkey_parse(const secp256k1_context *ctx,
                       secp256k1_pubkey *out,
                       const unsigned char input[33])
{
    return secp256k1_ec_pubkey_parse(ctx, out, input, 33);
}
