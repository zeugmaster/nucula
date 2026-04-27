#include "crypto.h"
#include "hex.h"
#include <string.h>
#include <mbedtls/sha256.h>
#include <mbedtls/md.h>
#include "secp256k1_extrakeys.h"
#include "secp256k1_schnorrsig.h"

static const char DOMAIN_SEPARATOR[] = "Secp256k1_HashToCurve_Cashu_";
#define DOMAIN_SEPARATOR_LEN 28

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

/* secp256k1 group order N (big-endian) */
static const unsigned char SECP256K1_N[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
    0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
};

/* Compare two 32-byte big-endian values. Returns <0, 0, or >0. */
static int cmp256(const unsigned char a[32], const unsigned char b[32])
{
    return memcmp(a, b, 32);
}

/* Subtract b from a (both 32-byte big-endian), result in out. a must be >= b. */
static void sub256(const unsigned char a[32], const unsigned char b[32],
                   unsigned char out[32])
{
    int borrow = 0;
    for (int i = 31; i >= 0; i--) {
        int diff = (int)a[i] - (int)b[i] - borrow;
        if (diff < 0) {
            diff += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out[i] = (unsigned char)diff;
    }
}

/*
 * Build the NUT-13 HMAC-SHA256 KDF message and compute the digest.
 *
 * message = "Cashu_KDF_HMAC_SHA256" || keyset_id_bytes || counter_be64 || type_byte
 */
static int nut13_hmac(const unsigned char *seed, size_t seed_len,
                      const char *keyset_id, uint32_t counter,
                      unsigned char type_byte, unsigned char digest[32])
{
    /* Decode keyset_id from hex to bytes */
    size_t id_hex_len = strlen(keyset_id);
    if (id_hex_len == 0 || id_hex_len % 2 != 0)
        return 0;
    size_t id_byte_len = id_hex_len / 2;

    /* Stack-allocate message buffer:
     * 20 (domain) + max 33 (keyset id) + 8 (counter) + 1 (type) = 62 max */
    unsigned char msg[128];
    size_t pos = 0;

    static const char domain[] = "Cashu_KDF_HMAC_SHA256";
    size_t domain_len = 21; /* strlen("Cashu_KDF_HMAC_SHA256") */
    memcpy(msg + pos, domain, domain_len);
    pos += domain_len;

    if (pos + id_byte_len > sizeof(msg))
        return 0;
    if (!hex_to_bytes(keyset_id, msg + pos, id_byte_len))
        return 0;
    pos += id_byte_len;

    /* counter as big-endian uint64 */
    msg[pos++] = 0;
    msg[pos++] = 0;
    msg[pos++] = 0;
    msg[pos++] = 0;
    msg[pos++] = (counter >> 24) & 0xFF;
    msg[pos++] = (counter >> 16) & 0xFF;
    msg[pos++] = (counter >> 8) & 0xFF;
    msg[pos++] = counter & 0xFF;

    /* derivation type */
    msg[pos++] = type_byte;

    /* HMAC-SHA256 */
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md_info)
        return 0;

    return mbedtls_md_hmac(md_info, seed, seed_len, msg, pos, digest) == 0 ? 1 : 0;
}

int cashu_derive_secret(const unsigned char *seed, size_t seed_len,
                        const char *keyset_id, uint32_t counter,
                        unsigned char secret_out[32])
{
    return nut13_hmac(seed, seed_len, keyset_id, counter, 0x00, secret_out);
}

int cashu_derive_r(const unsigned char *seed, size_t seed_len,
                   const char *keyset_id, uint32_t counter,
                   unsigned char r_out[32])
{
    unsigned char digest[32];
    if (!nut13_hmac(seed, seed_len, keyset_id, counter, 0x01, digest))
        return 0;

    /* Reduce mod N */
    if (cmp256(digest, SECP256K1_N) >= 0)
        sub256(digest, SECP256K1_N, r_out);
    else
        memcpy(r_out, digest, 32);

    /* Reject r == 0 */
    unsigned char zero[32] = {0};
    if (memcmp(r_out, zero, 32) == 0)
        return 0;

    return 1;
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

int cashu_schnorr_sign_secret(const secp256k1_context *ctx,
                              const unsigned char priv[32],
                              const unsigned char *secret_bytes,
                              size_t secret_len,
                              unsigned char sig64_out[64])
{
    unsigned char msg32[32];
    if (mbedtls_sha256(secret_bytes, secret_len, msg32, 0) != 0)
        return 0;

    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ctx, &kp, priv))
        return 0;

    return secp256k1_schnorrsig_sign32(ctx, sig64_out, msg32, &kp, NULL);
}
