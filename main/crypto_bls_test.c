#if __has_include("sdkconfig.h")
#include "sdkconfig.h"
#endif
#include "crypto_bls_test.h"
#include "cashu_suite.h"
#include "hex.h"
#include <blst.h>
#include <blst_aux.h>
#include <blst_mpi.h>
#include <stdio.h>
#include <string.h>
#include <esp_log.h>
#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#define TAG "bls_test"

/* NUT-00: hash-to-curve DST for the v3 G1 random-oracle suite
 * (RFC 9380 BLS12381G1_XMD:SHA-256_SSWU_RO_ with Cashu domain separation). */
static const unsigned char DST[] = "CASHU_BLS12_381_G1_XMD:SHA-256_SSWU_RO_";
#define DST_LEN (sizeof(DST) - 1)

/* NUT-00: Fiat-Shamir transcript DST for batch verification. */
static const unsigned char BATCH_DST[] = "Cashu_BLS_Batch_v1";
#define BATCH_DST_LEN (sizeof(BATCH_DST) - 1)

/* BLS12-381 Fr order, big-endian. A 32-byte hash is a valid weight/scalar iff
 * 0 < OS2IP(h) < this, compared on the raw bytes: blst_scalar_from_be_bytes
 * REDUCES out-of-range inputs modulo the order (and reports success), so its
 * return value cannot serve as the range check. */
static const unsigned char FR_ORDER_BE[32] = {
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48,
    0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
};

/* --------------------------------------------------------------------------
 * Small wrappers over blst
 * ------------------------------------------------------------------------ */

static int be_lt(const unsigned char a[32], const unsigned char b[32])
{
    for (int i = 0; i < 32; i++) {
        if (a[i] != b[i])
            return a[i] < b[i];
    }
    return 0;
}

static void small_scalar(blst_scalar *s, unsigned char n)
{
    unsigned char be[32] = {0};
    be[31] = n;
    blst_scalar_from_be_bytes(s, be, 32);
}

static void hash_to_g1(blst_p1 *out, const unsigned char *msg, size_t len)
{
    blst_hash_to_g1(out, msg, len, DST, DST_LEN, NULL, 0);
}

/* blst_p1_mult takes the scalar as LITTLE-endian bytes (blst_scalar's
 * internal layout). Feeding big-endian here fails only at runtime, against
 * the conformance vectors — which is exactly why they run at boot. */
static void p1_mul(blst_p1 *out, const blst_p1 *p, const blst_scalar *s)
{
    unsigned char le[32];
    blst_lendian_from_scalar(le, s);
    blst_p1_mult(out, p, le, 256);
}

static void invert_scalar(blst_scalar *out, const blst_scalar *s)
{
    blst_fr fr, inv;
    blst_fr_from_scalar(&fr, s);
    blst_fr_inverse(&inv, &fr);
    blst_scalar_from_fr(out, &inv);
}

/* Full NUT-00 point validation: canonical encoding + on-curve (both enforced
 * by uncompress), identity rejection, and prime-order-subgroup membership
 * (in_g1/in_g2 — rejects cofactor components, the Lim-Lee defense). */
static int validate_g1(blst_p1_affine *out, const unsigned char comp[48])
{
    if (blst_p1_uncompress(out, comp) != BLST_SUCCESS)
        return 0;
    if (blst_p1_affine_is_inf(out))
        return 0;
    if (!blst_p1_affine_in_g1(out))
        return 0;
    return 1;
}

static int validate_g2(blst_p2_affine *out, const unsigned char comp[96])
{
    if (blst_p2_uncompress(out, comp) != BLST_SUCCESS)
        return 0;
    if (blst_p2_affine_is_inf(out))
        return 0;
    if (!blst_p2_affine_in_g2(out))
        return 0;
    return 1;
}

/* Single-proof verification: e(C, g2) == e(Y, K), evaluated as two miller
 * loops and one combined final exponentiation (blst_fp12_finalverify). */
static int pairing_verification(const unsigned char k_comp[96],
                                const unsigned char c_comp[48],
                                const unsigned char *secret, size_t secret_len)
{
    blst_p1_affine c_aff;
    blst_p2_affine k_aff;
    if (!validate_g1(&c_aff, c_comp) || !validate_g2(&k_aff, k_comp))
        return 0;

    blst_p1 Y;
    hash_to_g1(&Y, secret, secret_len);
    blst_p1_affine y_aff;
    blst_p1_to_affine(&y_aff, &Y);

    blst_p2_affine g2_aff;
    blst_p2_to_affine(&g2_aff, blst_p2_generator());

    blst_fp12 ml1, ml2;
    blst_miller_loop(&ml1, &g2_aff, &c_aff); /* e(C, g2) */
    blst_miller_loop(&ml2, &k_aff, &y_aff);  /* e(Y, K)  */
    return blst_fp12_finalverify(&ml1, &ml2) ? 1 : 0;
}

/* NUT-00 batch weights: challenge = SHA256(BATCH_DST || per-proof
 * C(48) || K(96) || u32_BE(len secret) || secret), then per-proof
 * w_i = first SHA256(challenge || u32_BE(i) || u32_BE(ctr)) with
 * 0 < OS2IP < FR_ORDER (rejection sampling). */
#define BATCH_MAX 10

static int derive_batch_weights(const unsigned char *cs /* n*48 */,
                                const unsigned char *ks /* n*96 */,
                                const unsigned char *const *secrets,
                                const size_t *secret_lens,
                                size_t n,
                                blst_scalar *weights_out,
                                unsigned char challenge_out[32])
{
    unsigned char transcript[BATCH_DST_LEN + BATCH_MAX * (48 + 96 + 4 + 64)];
    size_t off = 0;

    memcpy(transcript + off, BATCH_DST, BATCH_DST_LEN);
    off += BATCH_DST_LEN;
    for (size_t i = 0; i < n; i++) {
        if (off + 48 + 96 + 4 + secret_lens[i] > sizeof(transcript))
            return 0;
        memcpy(transcript + off, cs + i * 48, 48);
        off += 48;
        memcpy(transcript + off, ks + i * 96, 96);
        off += 96;
        uint32_t slen = (uint32_t)secret_lens[i];
        transcript[off++] = (unsigned char)(slen >> 24);
        transcript[off++] = (unsigned char)(slen >> 16);
        transcript[off++] = (unsigned char)(slen >> 8);
        transcript[off++] = (unsigned char)(slen);
        memcpy(transcript + off, secrets[i], secret_lens[i]);
        off += secret_lens[i];
    }

    unsigned char challenge[32];
    blst_sha256(challenge, transcript, off);
    if (challenge_out)
        memcpy(challenge_out, challenge, 32);

    for (size_t i = 0; i < n; i++) {
        unsigned char buf[40];
        memcpy(buf, challenge, 32);
        buf[32] = (unsigned char)(i >> 24);
        buf[33] = (unsigned char)(i >> 16);
        buf[34] = (unsigned char)(i >> 8);
        buf[35] = (unsigned char)(i);
        for (uint32_t ctr = 0;; ctr++) {
            buf[36] = (unsigned char)(ctr >> 24);
            buf[37] = (unsigned char)(ctr >> 16);
            buf[38] = (unsigned char)(ctr >> 8);
            buf[39] = (unsigned char)(ctr);
            unsigned char h[32];
            blst_sha256(h, buf, 40);
            int is_zero = 1;
            for (int j = 0; j < 32; j++)
                if (h[j]) { is_zero = 0; break; }
            if (!is_zero && be_lt(h, FR_ORDER_BE)) {
                blst_scalar_from_be_bytes(&weights_out[i], h, 32);
                break;
            }
        }
    }
    return 1;
}

/* NUT-00 batch check, grouped by distinct mint key:
 *   e( sum_i w_i*C_i , g2 ) == prod_k e( sum_{i: K_i=K_k} w_i*Y_i , K_k )
 * One final-verify for the whole equation. */
static int batch_pairing_verification(const unsigned char *ks /* n*96 */,
                                      const unsigned char *cs /* n*48 */,
                                      const unsigned char *const *secrets,
                                      const size_t *secret_lens,
                                      size_t n)
{
    if (n == 0)
        return 1;
    if (n > BATCH_MAX)
        return 0;

    blst_scalar weights[BATCH_MAX];
    if (!derive_batch_weights(cs, ks, secrets, secret_lens, n, weights, NULL))
        return 0;

    /* sum_C = sum w_i * C_i, each C_i fully validated. */
    blst_p1 sum_c;
    for (size_t i = 0; i < n; i++) {
        blst_p1_affine c_aff;
        if (!validate_g1(&c_aff, cs + i * 48))
            return 0;
        blst_p1 c, wc;
        blst_p1_from_affine(&c, &c_aff);
        p1_mul(&wc, &c, &weights[i]);
        if (i == 0)
            sum_c = wc;
        else
            blst_p1_add(&sum_c, &sum_c, &wc);
    }

    /* Group sum(w_i * Y_i) by distinct K (compared on compressed bytes);
     * each distinct K validated once. */
    struct {
        const unsigned char *k_comp;
        blst_p2_affine k_aff;
        blst_p1 sum_ry;
    } groups[BATCH_MAX];
    size_t n_groups = 0;

    for (size_t i = 0; i < n; i++) {
        blst_p1 Y, ry;
        hash_to_g1(&Y, secrets[i], secret_lens[i]);
        p1_mul(&ry, &Y, &weights[i]);

        size_t g;
        for (g = 0; g < n_groups; g++) {
            if (memcmp(groups[g].k_comp, ks + i * 96, 96) == 0) {
                blst_p1_add(&groups[g].sum_ry, &groups[g].sum_ry, &ry);
                break;
            }
        }
        if (g == n_groups) {
            if (!validate_g2(&groups[g].k_aff, ks + i * 96))
                return 0;
            groups[g].k_comp = ks + i * 96;
            groups[g].sum_ry = ry;
            n_groups++;
        }
    }

    /* Left: e(sum_C, g2); right: product of per-key miller loops. */
    blst_p2_affine g2_aff;
    blst_p2_to_affine(&g2_aff, blst_p2_generator());
    blst_p1_affine sum_c_aff;
    blst_p1_to_affine(&sum_c_aff, &sum_c);
    blst_fp12 left;
    blst_miller_loop(&left, &g2_aff, &sum_c_aff);

    blst_fp12 right = *blst_fp12_one();
    for (size_t g = 0; g < n_groups; g++) {
        blst_p1_affine ry_aff;
        blst_p1_to_affine(&ry_aff, &groups[g].sum_ry);
        blst_fp12 ml;
        blst_miller_loop(&ml, &groups[g].k_aff, &ry_aff);
        blst_fp12_mul(&right, &right, &ml);
    }

    return blst_fp12_finalverify(&left, &right) ? 1 : 0;
}

/* --------------------------------------------------------------------------
 * NUT-00 v3 conformance vectors (nuts PR #371, tests/00-tests.md)
 * ------------------------------------------------------------------------ */

static int check_hex(const unsigned char *got, size_t len,
                     const char *expect_hex, const char *what)
{
    char got_hex[2 * 96 + 1];
    bytes_to_hex(got, len, got_hex);
    if (strcmp(got_hex, expect_hex) != 0) {
        ESP_LOGE(TAG, "%s: mismatch\n  got:    %s\n  expect: %s",
                 what, got_hex, expect_hex);
        return 0;
    }
    ESP_LOGI(TAG, "%s: OK", what);
    return 1;
}

/* secret="test_message", r=3, a=2 -> Y, K, B_, C_, C. */
static const char *V3_Y_HEX =
    "860d58e5aeda1376185436ed96412313424cc079e056d1dab595e6db4c2c9685"
    "fec7da052c8db68d88985b75a42388ad";
static const char *V3_K_HEX =
    "aa4edef9c1ed7f729f520e47730a124fd70662a904ba1074728114d1031e1572"
    "c6c886f6b57ec72a6178288c47c33577"
    "1638533957d540a9d2370f17cc7ed5863bc0b995b8825e0ee1ea1e1e4d00dbae"
    "81f14b0bf3611b78c952aacab827a053";
static const char *V3_B_HEX =
    "8e88c5f6a93f653784a66b033a00e52128499e18b095c2a56f080d1c2a937ffc"
    "9ef4600804a48d087bbd1f662f6b068f";
static const char *V3_CBLIND_HEX =
    "8d52d7a6cbe5e99858d5c15c092d11a0c387c78917471211082a6e5afc2a7968"
    "0dfa188fafe5d4a51c5398ce160e7a16";
static const char *V3_C_HEX =
    "b7a4881059133fd91a8753600d9a5e524c65d6224f6fe2d5aef9e59f1507fdad"
    "90b3b4d48ee46da5c8dfaa0b88e28b69";

static int test_bls_round_trip(void)
{
    const unsigned char *secret = (const unsigned char *)"test_message";
    const size_t secret_len = 12;
    int pass = 1;

    /* Y = hash_to_curve_G1(secret) */
    blst_p1 Y;
    hash_to_g1(&Y, secret, secret_len);
    unsigned char y_comp[48];
    blst_p1_compress(y_comp, &Y);
    pass &= check_hex(y_comp, 48, V3_Y_HEX, "hash_to_curve_G1");

    /* K = 2*g2 (the vector's mint key), parsed from hex like a production
     * /v1/keys response rather than derived: blst's G2 scalar mult keeps a
     * ~9 KB window table on the stack (POINTonE2_mult_gls) and the wallet
     * never computes mint keys — only validates received ones. */
    blst_scalar a;
    small_scalar(&a, 2);
    unsigned char k_comp[96];
    hex_to_bytes(V3_K_HEX, k_comp, 96);
    blst_p2_affine k_aff;
    if (!validate_g2(&k_aff, k_comp)) {
        ESP_LOGE(TAG, "mint key K: failed G2 validation");
        pass = 0;
    } else {
        ESP_LOGI(TAG, "mint key K: valid G2 point");
    }

    /* B_ = r*Y, r = 3 (blinding) */
    blst_scalar r;
    small_scalar(&r, 3);
    blst_p1 B_;
    p1_mul(&B_, &Y, &r);
    unsigned char b_comp[48];
    blst_p1_compress(b_comp, &B_);
    pass &= check_hex(b_comp, 48, V3_B_HEX, "blind B_ = r*Y");

    /* C_ = a*B_ (Bob signs) */
    blst_p1 C_;
    p1_mul(&C_, &B_, &a);
    unsigned char cb_comp[48];
    blst_p1_compress(cb_comp, &C_);
    pass &= check_hex(cb_comp, 48, V3_CBLIND_HEX, "sign C_ = a*B_");

    /* C = r^-1 * C_ (unblinding) */
    blst_scalar r_inv;
    invert_scalar(&r_inv, &r);
    blst_p1 C;
    p1_mul(&C, &C_, &r_inv);
    unsigned char c_comp[48];
    blst_p1_compress(c_comp, &C);
    pass &= check_hex(c_comp, 48, V3_C_HEX, "unblind C = r^-1*C_");

    /* e(C, g2) == e(Y, K) */
    if (!pairing_verification(k_comp, c_comp, secret, secret_len)) {
        ESP_LOGE(TAG, "pairing verification: rejected a valid proof");
        pass = 0;
    } else {
        ESP_LOGI(TAG, "pairing verification: OK");
    }

    /* Tampered C must fail (bit flip lands in the x-coordinate; the point
     * either fails to decompress or verifies against the wrong Y). */
    c_comp[47] ^= 0x01;
    if (pairing_verification(k_comp, c_comp, secret, secret_len)) {
        ESP_LOGE(TAG, "pairing verification: accepted a tampered C");
        pass = 0;
    }
    c_comp[47] ^= 0x01;

    /* Tampered secret must fail. */
    if (pairing_verification(k_comp, c_comp, (const unsigned char *)"test_messagf", 12)) {
        ESP_LOGE(TAG, "pairing verification: accepted a tampered secret");
        pass = 0;
    }
    if (pass)
        ESP_LOGI(TAG, "tamper rejection: OK");
    return pass;
}

/* Batch vector: two proofs under K = 2*g2; weight_1 accepts at ctr=4,
 * weight_2 at ctr=0 — exercising both rejection-sampling paths. */
static const char *BATCH_C1_HEX =
    "acebf797506a7031cef3189904715cb22792528f1ea0e6ab25341401d2455394"
    "38ed97122f00e38ee6185cc20b09ba11";
static const char *BATCH_C2_HEX =
    "9776497ad47a00f8a56233fb88f939b0572cf174a4c6d2446c0b1060434e305f"
    "ae6845fd1f68b70376ba53ffe67f0414";
static const char *BATCH_CHALLENGE_HEX =
    "539b5df396e82adab0760459590d38122d2552bc74f6bd860e915ff3b95e550a";
static const char *BATCH_W1_HEX =
    "0e7ff8be2ccb756d4ef390991bdd77eb65e8db624a2729fa1657c3cf8d7d4b55";
static const char *BATCH_W2_HEX =
    "6d026a181a6215b233e73b121d01908a1a1eb6911955bea5130bbf2f2966554d";

static int test_bls_batch(void)
{
    unsigned char ks[2 * 96], cs[2 * 48];
    hex_to_bytes(V3_K_HEX, ks, 96);
    hex_to_bytes(V3_K_HEX, ks + 96, 96);
    hex_to_bytes(BATCH_C1_HEX, cs, 48);
    hex_to_bytes(BATCH_C2_HEX, cs + 48, 48);

    const unsigned char *secrets[2] = {
        (const unsigned char *)"batch_proof_1",
        (const unsigned char *)"batch_proof_2",
    };
    const size_t secret_lens[2] = { 13, 13 };
    int pass = 1;

    /* The vector's C_i are the unblinded signatures a*Y_i: recompute one
     * from scratch to pin the interpretation. */
    {
        blst_scalar a;
        small_scalar(&a, 2);
        blst_p1 Y, C1;
        hash_to_g1(&Y, secrets[0], secret_lens[0]);
        p1_mul(&C1, &Y, &a);
        unsigned char c1_comp[48];
        blst_p1_compress(c1_comp, &C1);
        pass &= check_hex(c1_comp, 48, BATCH_C1_HEX, "batch C_1 = a*Y_1");
    }

    blst_scalar weights[2];
    unsigned char challenge[32];
    if (!derive_batch_weights(cs, ks, secrets, secret_lens, 2, weights, challenge)) {
        ESP_LOGE(TAG, "batch: weight derivation failed");
        return 0;
    }
    pass &= check_hex(challenge, 32, BATCH_CHALLENGE_HEX, "batch challenge");

    unsigned char w_be[32];
    blst_bendian_from_scalar(w_be, &weights[0]);
    pass &= check_hex(w_be, 32, BATCH_W1_HEX, "batch weight_1 (ctr=4)");
    blst_bendian_from_scalar(w_be, &weights[1]);
    pass &= check_hex(w_be, 32, BATCH_W2_HEX, "batch weight_2 (ctr=0)");

    if (!batch_pairing_verification(ks, cs, secrets, secret_lens, 2)) {
        ESP_LOGE(TAG, "batch verification: rejected a valid batch");
        pass = 0;
    } else {
        ESP_LOGI(TAG, "batch verification: OK");
    }

    /* One tampered member must sink the whole batch. */
    const unsigned char *bad_secrets[2] = {
        secrets[0], (const unsigned char *)"batch_proof_x",
    };
    if (batch_pairing_verification(ks, cs, bad_secrets, secret_lens, 2)) {
        ESP_LOGE(TAG, "batch verification: accepted a tampered batch");
        pass = 0;
    } else {
        ESP_LOGI(TAG, "batch tamper rejection: OK");
    }
    return pass;
}

static int test_bls_point_validation(void)
{
    int pass = 1;
    blst_p1_affine p1;
    blst_p2_affine p2;

    /* All-zero encodings: not canonical compressions. */
    unsigned char zero48[48] = {0}, zero96[96] = {0};
    if (validate_g1(&p1, zero48) || validate_g2(&p2, zero96)) {
        ESP_LOGE(TAG, "validation: accepted an all-zero point");
        pass = 0;
    }

    /* Compressed identity (infinity bit set): decodes but must be rejected —
     * the identity is never a valid blinded message, signature, or mint key. */
    unsigned char inf48[48] = {0}, inf96[96] = {0};
    inf48[0] = 0xc0;
    inf96[0] = 0xc0;
    if (validate_g1(&p1, inf48) || validate_g2(&p2, inf96)) {
        ESP_LOGE(TAG, "validation: accepted the identity point");
        pass = 0;
    }

    /* Valid point with the compression bit cleared: non-canonical. */
    unsigned char y_comp[48];
    hex_to_bytes(V3_Y_HEX, y_comp, 48);
    y_comp[0] &= 0x7f;
    if (validate_g1(&p1, y_comp)) {
        ESP_LOGE(TAG, "validation: accepted a non-canonical encoding");
        pass = 0;
    }

    if (pass)
        ESP_LOGI(TAG, "point validation: OK");
    return pass;
}

/* --------------------------------------------------------------------------
 * Suite-level tests: drive cashu_suite_bls through the byte-oriented vtable
 * exactly as the wallet does. The suite ops manage the MPI lock internally,
 * so these must run OUTSIDE any blst_hw_acquire window (the lock is not
 * recursive).
 * ------------------------------------------------------------------------ */

static int test_bls_suite(void)
{
    const cashu_suite_t *s = &cashu_suite_bls;
    const unsigned char *secret = (const unsigned char *)"test_message";
    int pass = 1;

    unsigned char r_be[32] = {0};
    r_be[31] = 3;

    /* blind: B_ = r*Y against the NUT-00 vector */
    unsigned char B[CASHU_MAX_POINT_LEN];
    size_t B_len = sizeof(B);
    if (!s->blind(NULL, secret, 12, r_be, 32, B, &B_len) || B_len != 48) {
        ESP_LOGE(TAG, "suite blind: failed");
        pass = 0;
    } else {
        pass &= check_hex(B, 48, V3_B_HEX, "suite blind");
    }

    /* unblind: C = r^-1*C_ against the vector (K is unused for BLS) */
    unsigned char C_blind[48], K[96];
    hex_to_bytes(V3_CBLIND_HEX, C_blind, 48);
    hex_to_bytes(V3_K_HEX, K, 96);
    unsigned char C[CASHU_MAX_POINT_LEN];
    size_t C_len = sizeof(C);
    if (!s->unblind(NULL, C_blind, 48, r_be, 32, K, 96, C, &C_len) || C_len != 48) {
        ESP_LOGE(TAG, "suite unblind: failed");
        pass = 0;
    } else {
        pass &= check_hex(C, 48, V3_C_HEX, "suite unblind");
    }

    /* verify_proofs n=1: the intrinsic pairing check */
    const unsigned char *sec1[1] = { secret };
    const size_t slen1[1] = { 12 };
    if (s->verify_proofs(NULL, 1, K, C, sec1, slen1) != 1) {
        ESP_LOGE(TAG, "suite verify_proofs n=1: rejected a valid proof");
        pass = 0;
    }
    const unsigned char *bad1[1] = { (const unsigned char *)"test_messagf" };
    if (s->verify_proofs(NULL, 1, K, C, bad1, slen1) != 0) {
        ESP_LOGE(TAG, "suite verify_proofs n=1: accepted a tampered secret");
        pass = 0;
    }

    /* verify_proofs n=2: the batch vector */
    unsigned char ks2[2 * 96], cs2[2 * 48];
    memcpy(ks2, K, 96);
    memcpy(ks2 + 96, K, 96);
    hex_to_bytes(BATCH_C1_HEX, cs2, 48);
    hex_to_bytes(BATCH_C2_HEX, cs2 + 48, 48);
    const unsigned char *sec2[2] = {
        (const unsigned char *)"batch_proof_1",
        (const unsigned char *)"batch_proof_2",
    };
    const size_t slen2[2] = { 13, 13 };
    if (s->verify_proofs(NULL, 2, ks2, cs2, sec2, slen2) != 1) {
        ESP_LOGE(TAG, "suite verify_proofs n=2: rejected a valid batch");
        pass = 0;
    }
    const unsigned char *bad2[2] = { sec2[0], (const unsigned char *)"batch_proof_x" };
    if (s->verify_proofs(NULL, 2, ks2, cs2, bad2, slen2) != 0) {
        ESP_LOGE(TAG, "suite verify_proofs n=2: accepted a tampered batch");
        pass = 0;
    }
    if (pass)
        ESP_LOGI(TAG, "suite verify_proofs: OK");

    /* invalid inputs fail closed */
    unsigned char zero_r[32] = {0};
    B_len = sizeof(B);
    if (s->blind(NULL, secret, 12, zero_r, 32, B, &B_len) != 0) {
        ESP_LOGE(TAG, "suite blind: accepted r = 0");
        pass = 0;
    }
    B_len = sizeof(B);
    if (s->blind(NULL, secret, 12, FR_ORDER_BE, 32, B, &B_len) != 0) {
        ESP_LOGE(TAG, "suite blind: accepted r = Fr order");
        pass = 0;
    }
    unsigned char zero_c[48] = {0};
    C_len = sizeof(C);
    if (s->unblind(NULL, zero_c, 48, r_be, 32, K, 96, C, &C_len) != 0) {
        ESP_LOGE(TAG, "suite unblind: accepted a malformed C_");
        pass = 0;
    }
    if (pass)
        ESP_LOGI(TAG, "suite input validation: OK");

    /* NUT-13 v3 vector (tests/13-tests.md): counter 3, attempt 0 rejected,
     * attempt 1 accepted — proves the rejection loop and u32_BE framing. */
    const unsigned char *seed = (const unsigned char *)"nut13 v3 test seed";
    const char *ks_id =
        "02abd02ebc1ff44652153375162407deaf0b30e590844cca0b6e4894a08a8828dd";
    unsigned char out32[32];
    if (!s->derive_secret(seed, 18, ks_id, 3, out32)) {
        ESP_LOGE(TAG, "suite derive_secret: failed");
        pass = 0;
    } else {
        pass &= check_hex(out32, 32,
            "7a45e04943504b25273e9569ab7019ab62f814dade23998c12f5f4cb1bb7978a",
            "NUT-13 v3 secret");
    }
    if (!s->derive_r(seed, 18, ks_id, 3, out32)) {
        ESP_LOGE(TAG, "suite derive_r: failed");
        pass = 0;
    } else {
        pass &= check_hex(out32, 32,
            "236dbcb12fc064ceeae6c5e2de7f79258374dccbf23ac0afdf72cf9eb53540c9",
            "NUT-13 v3 r (attempt=1)");
    }

    return pass;
}

/* --------------------------------------------------------------------------
 * MPI peripheral vs software Montgomery multiply — bit-exactness (C3 only)
 * ------------------------------------------------------------------------ */
#if defined(CONFIG_IDF_TARGET_ESP32C3)

/* BLS12-381 base-field prime, little-endian 32-bit limbs, and
 * -p^-1 mod 2^32 (bls-bench mpi.rs). */
static const uint32_t BLS_P_LE[12] = {
    0xFFFFAAAB, 0xB9FEFFFF, 0xB153FFFF, 0x1EABFFFE,
    0xF6B0F624, 0x6730D2A0, 0xF38512BF, 0x64774B84,
    0x434BACD7, 0x4B1BA7B6, 0x397FE69A, 0x1A0111EA,
};
#define BLS_P_N0 0xFFFCFFFDu

/* 48 deterministic pseudorandom bytes, masked below p's top word. */
static void det_operand(uint32_t out[12], uint32_t seed)
{
    unsigned char h[32], h2[32];
    unsigned char buf[4] = {
        (unsigned char)(seed >> 24), (unsigned char)(seed >> 16),
        (unsigned char)(seed >> 8), (unsigned char)seed,
    };
    blst_sha256(h, buf, 4);
    blst_sha256(h2, h, 32);
    memcpy(out, h, 32);
    memcpy((unsigned char *)out + 32, h2, 16);
    out[11] &= 0x19FFFFFF; /* < p's top limb 0x1A0111EA => value < p */
}

static int test_mpi_bit_exact(void)
{
    if (!blst_mpi_enabled()) {
        ESP_LOGW(TAG, "MPI disabled, skipping bit-exactness test");
        return 1;
    }

    uint32_t a[12], b[12], hw[12], sw[12];
    int pass = 1;

    blst_hw_acquire();
    for (int k = 0; k < 100 && pass; k++) {
        det_operand(a, (uint32_t)(2 * k));
        det_operand(b, (uint32_t)(2 * k + 1));
        if (k == 1)
            memcpy(b, a, sizeof(b)); /* squaring */
        if (k == 2) {
            memcpy(a, BLS_P_LE, sizeof(a)); /* operand at p-1 */
            a[0] -= 1;
        }
        mpi_mul_mont_n(hw, a, b, BLS_P_LE, BLS_P_N0, 12);
        blst_mpi_sw_mul_mont_384(sw, a, b, BLS_P_LE, BLS_P_N0);
        if (memcmp(hw, sw, sizeof(hw)) != 0) {
            ESP_LOGE(TAG, "MPI vs software mismatch at case %d", k);
            pass = 0;
        }
        if (k % 25 == 24)
            vTaskDelay(1);
    }

    /* Chained t = t*b: exercises the resident-X skip on the hardware side. */
    uint32_t thw[12], tsw[12];
    det_operand(thw, 999);
    memcpy(tsw, thw, sizeof(tsw));
    det_operand(b, 1000);
    for (int k = 0; k < 50 && pass; k++) {
        mpi_mul_mont_n(thw, thw, b, BLS_P_LE, BLS_P_N0, 12);
        blst_mpi_sw_mul_mont_384(tsw, tsw, b, BLS_P_LE, BLS_P_N0);
        if (memcmp(thw, tsw, sizeof(thw)) != 0) {
            ESP_LOGE(TAG, "MPI vs software mismatch in t=t*b chain at %d", k);
            pass = 0;
        }
    }

    /* Cache invalidation across a release/acquire cycle (peripheral reset). */
    blst_hw_release();
    blst_hw_acquire();
    det_operand(a, 2001);
    det_operand(b, 2002);
    mpi_mul_mont_n(hw, a, b, BLS_P_LE, BLS_P_N0, 12);
    blst_mpi_sw_mul_mont_384(sw, a, b, BLS_P_LE, BLS_P_N0);
    if (memcmp(hw, sw, sizeof(hw)) != 0) {
        ESP_LOGE(TAG, "MPI vs software mismatch after release/acquire");
        pass = 0;
    }
    blst_hw_release();

    if (pass)
        ESP_LOGI(TAG, "MPI vs software bit-exactness: OK");
    return pass;
}
#endif /* CONFIG_IDF_TARGET_ESP32C3 */

int crypto_bls_run_tests(void)
{
    ESP_LOGI(TAG, "running BLS12-381 (keyset v3) test vectors");

    int pass = 1;
    blst_hw_acquire();
    pass &= test_bls_round_trip();
    blst_hw_release();
    vTaskDelay(1);
    blst_hw_acquire();
    pass &= test_bls_batch();
    blst_hw_release();
    vTaskDelay(1);
    blst_hw_acquire();
    pass &= test_bls_point_validation();
    blst_hw_release();
    vTaskDelay(1);
    /* Outside any hold window: the suite ops acquire the (non-recursive)
     * MPI lock themselves. */
    pass &= test_bls_suite();
#if defined(CONFIG_IDF_TARGET_ESP32C3)
    vTaskDelay(1);
    pass &= test_mpi_bit_exact();
#endif

    if (pass)
        ESP_LOGI(TAG, "all BLS tests passed");
    else
        ESP_LOGE(TAG, "some BLS tests FAILED");
    return pass;
}

/* --------------------------------------------------------------------------
 * Benchmark — rows mirror bls-bench RESULTS.md
 * ------------------------------------------------------------------------ */

/* Per-op time is accumulated around each call so the yields between
 * iterations (which keep the watchdog fed) don't distort the numbers.
 * The body is variadic: braces don't protect commas in macro arguments. */
#define BENCH(label, iters, ...)                                         \
    do {                                                                 \
        int64_t total = 0;                                               \
        for (int bi = 0; bi < (iters); bi++) {                           \
            int64_t t0 = esp_timer_get_time();                           \
            __VA_ARGS__;                                                 \
            total += esp_timer_get_time() - t0;                          \
            vTaskDelay(1);                                               \
        }                                                                \
        ESP_LOGI(TAG, "%-24s x%-3d %8lld us/op", label, (iters),         \
                 total / (iters));                                       \
    } while (0)

static void bench_rows(void)
{
    unsigned char secret[32] = {0};
    blst_p1 Y;
    hash_to_g1(&Y, secret, 32);

    /* Bench key = the vector's K = 2*g2, parsed not derived (G2 mult is a
     * mint-side op with a ~9 KB stack table — the wallet never runs it). */
    blst_scalar a, r;
    small_scalar(&a, 2);
    unsigned char k_comp[96];
    hex_to_bytes(V3_K_HEX, k_comp, 96);
    /* r: an arbitrary full-width scalar so the mult isn't flattered by a
     * low Hamming weight. */
    {
        unsigned char be[32];
        for (int i = 0; i < 32; i++)
            be[i] = (unsigned char)(0xa3 ^ (i * 29));
        be[0] = 0x13; /* < Fr order */
        blst_scalar_from_be_bytes(&r, be, 32);
    }

    BENCH("hash_to_g1", 10, {
        secret[0] = (unsigned char)bi;
        hash_to_g1(&Y, secret, 32);
    });

    blst_p1 tmp;
    BENCH("g1_scalar_mul", 10, { p1_mul(&tmp, &Y, &r); });

    unsigned char y_comp[48];
    blst_p1_compress(y_comp, &Y);
    blst_p1_affine aff1;
    blst_p2_affine aff2;
    BENCH("point_validate_g1", 10, { validate_g1(&aff1, y_comp); });
    BENCH("point_validate_g2", 6, { validate_g2(&aff2, k_comp); });

    /* blind = hash_to_g1 + scalar mult (step1_alice) */
    BENCH("blind (B_=r*Y)", 6, {
        secret[0] = (unsigned char)bi;
        blst_p1 y, b;
        hash_to_g1(&y, secret, 32);
        p1_mul(&b, &y, &r);
    });

    /* unblind = validate + Fr inverse + scalar mult (step3_alice) */
    BENCH("unblind (C=1/r*C_)", 6, {
        blst_p1_affine ca;
        validate_g1(&ca, y_comp);
        blst_p1 c;
        blst_p1_from_affine(&c, &ca);
        blst_scalar rinv;
        invert_scalar(&rinv, &r);
        p1_mul(&tmp, &c, &rinv);
    });

    /* Proofs for verification rows: C_i = a*Y_i under the bench key. */
    static unsigned char cs[BATCH_MAX * 48];
    static unsigned char ks[BATCH_MAX * 96];
    static char secret_bufs[BATCH_MAX][16];
    const unsigned char *secrets[BATCH_MAX];
    size_t secret_lens[BATCH_MAX];
    for (int i = 0; i < BATCH_MAX; i++) {
        int n = snprintf(secret_bufs[i], sizeof(secret_bufs[i]), "bench_proof_%d", i);
        secrets[i] = (const unsigned char *)secret_bufs[i];
        secret_lens[i] = (size_t)n;
        blst_p1 y, c;
        hash_to_g1(&y, secrets[i], secret_lens[i]);
        p1_mul(&c, &y, &a);
        blst_p1_compress(cs + i * 48, &c);
        memcpy(ks + i * 96, k_comp, 96);
        vTaskDelay(1);
    }

    BENCH("pairing_verify n=1", 3, {
        pairing_verification(ks, cs, secrets[0], secret_lens[0]);
    });
    BENCH("batch_verify n=2", 2, {
        batch_pairing_verification(ks, cs, secrets, secret_lens, 2);
    });
    BENCH("batch_verify n=4", 2, {
        batch_pairing_verification(ks, cs, secrets, secret_lens, 4);
    });
    BENCH("batch_verify n=10", 1, {
        batch_pairing_verification(ks, cs, secrets, secret_lens, 10);
    });
}

void crypto_bls_run_benchmark(void)
{
#if defined(CONFIG_IDF_TARGET_ESP32C3)
    /* Both columns from one binary: the portable path first, then the
     * RSA/MPI-accelerated one. The whole accelerated pass runs inside one
     * hold window so the operand caches work as in steady state; TLS
     * (http_prewarm) simply waits — this is a diagnostic command. */
    ESP_LOGI(TAG, "--- portable path ---");
    blst_mpi_set_enabled(0);
    bench_rows();
    ESP_LOGI(TAG, "--- RSA/MPI-accelerated path ---");
    blst_mpi_set_enabled(1);
    blst_hw_acquire();
    bench_rows();
    blst_hw_release();
#else
    bench_rows();
#endif
}
