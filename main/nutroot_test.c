/* Nutroot (NUT-10 rev. cashubtc/nuts#421) selftest + benchmarks.
 *
 * Selftest pins the shared cross-implementation vectors from
 * tests/nutroot_v3_vectors.json (nutshell branch
 * bench/nutroot-witness-verification, byte-identical with the cashu-ts
 * copy): leaf wire forms, the sorted merkle fold, tweak math, transaction
 * transcripts, deterministic signatures, and full witness verification
 * with designed-to-fail variants.
 *
 * The benchmark mirrors nutshell's scripts/bench_nutroot_witness.py: the
 * timed unit is one nutroot_verify_transaction call (witness JSON parsing,
 * transcript digest, and the schnorr/merkle/script checks all inside),
 * case names match verbatim, and the sweeps cover the same axes. A second
 * section times the wallet's 10-proof v3 receive crypto (BLS batch verify,
 * spend-info reconstruction, witness signing, blind/unblind) in the
 * verify-now-swap-later and immediate-swap shapes. */
#if __has_include("sdkconfig.h")
#include "sdkconfig.h"
#endif
#include "nutroot_test.h"
#include "nutroot.h"
#include "cashu_suite.h"
#include "crypto_bls_test.h"
#include "hex.h"
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_ecdh.h>
#include <blst.h>
#include <blst_mpi.h>
#include <mbedtls/sha256.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <esp_log.h>
#include <esp_timer.h>
#include <esp_heap_caps.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#define TAG "nutroot"

/* Fixed clock for `after` evaluation: later than every locktime used here.
 * PAST_TIME mirrors nutshell's bench constant. */
#define NOW_TS    1788000000LL
#define PAST_TIME 1700000000LL

/* --------------------------------------------------------------------------
 * Shared vectors (tests/nutroot_v3_vectors.json). carol_priv = 3,
 * alice_refund_priv = 4; everything ties back to worked example 6.1.
 * ------------------------------------------------------------------------ */

static const char CAROL_PUB_HEX[] =
    "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
static const char ALICE_PUB_HEX[] =
    "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13";

/* example_6_1: one `after` leaf under a P2BK-derived internal key. */
static const char EX61_INTERNAL_HEX[] =
    "03a3e12cc077e5605f36441046f50c114fcc883b079a34028bed66732e3a419e51";
#define EX61_REFUND_TIME 1755561600LL
static const char EX61_LEAF_AFTER_HEX[] =
    "00020200010104002102e493dbf1c10d80f3581e4904930b1404cc6c13900ee075"
    "8474fa94abe8c4cd1306000468a3be80";
static const char EX61_ROOT_HEX[] =
    "9ed9c0b8907f7af4fce51cbeac218907bbf80ba40f3342df2406bce30616589a";
static const char EX61_TWEAK_HEX[] =
    "b3b7846b14be0650bb03272d179931221637744d1997df80bf27d2df5effe8a4";
static const char EX61_SECRET_HEX[] =
    "02d310a4d661e3158e7d360617e739d6bacbf015431b24a43168db0ab99ef8f828";
static const char EX61_KP_PRIV_HEX[] =
    "31b2e906239bae65b2d23718a037877b46a91b0b92f99fe8a899725f78d008e7";
static const char EX61_DIGEST_PREIMAGE[] = "illustrative transaction transcript";
static const char EX61_DIGEST_HEX[] =
    "e1d7170b89a2b6eedec90453e32b6c320dfadd590e6a6454bddec95a0e3834cd";
static const char EX61_KP_SIG_HEX[] =
    "619e0726595b5adff06cc3e6ea1c409f10f7b064cf8888f0eed0efbac854eabf"
    "4632642930bdc7c4d7d983379301a4f263991dbd19d96e5ebcfab9e8583bd510";
static const char EX61_SP_SIG_HEX[] =
    "0b2ea247bfca1264db86907aef4cb19935ed9a5b2043a757259dcdb5c599372c"
    "230602f2cfc0cd8b11aa98ff17fbed91f38f07db817263fcc7c50c846715873e";

/* empty_tweak: t = tagged(K) with no root; internal key is carol_pub. */
static const char ET_TWEAK_HEX[] =
    "764c0e0da0d17acb5cc863fbe939211869e04e522c017171a0b71e91d5b69908";
static const char ET_SECRET_HEX[] =
    "03b2bb251c006ae42d9c19f3157d02b3c347b1fb6512885225a8699a06d9233aee";
static const char ET_KP_PRIV_HEX[] =
    "764c0e0da0d17acb5cc863fbe939211869e04e522c017171a0b71e91d5b6990b";

/* leaf_forms: wire forms and the odd-count three-leaf fold. */
static const char LEAF_T11_HEX[] =
    "00010200010104002102f9308a019258c31049344f85f89d5229b531c845836f99"
    "b08601f113bce036f9";
static const char LEAF_T22_HEX[] =
    "00010200010204004202f9308a019258c31049344f85f89d5229b531c845836f99"
    "b08601f113bce036f902e493dbf1c10d80f3581e4904930b1404cc6c13900ee075"
    "8474fa94abe8c4cd13";
static const char HL_HASH_HEX[] =
    "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
static const char LEAF_HL_HEX[] =
    "00030200010104002102f9308a019258c31049344f85f89d5229b531c845836f99"
    "b08601f113bce036f9080020a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
    "a1a1a1a1a1a1a1a1a1a1a1";
static const char THREE_ROOT_HEX[] =
    "3d4fbecf46f5c716d7cebd48863f3c4ab89e675e3beb4b3a28f3bd13b49d43ad";
static const char THREE_PATH0_HEX[] =
    "23e8ff1693496ecad495b7ed3cdd7f8595c52a3adc0b92475835b0fb839116cb";
static const char THREE_PATH1_HEX[] =
    "9ed9c0b8907f7af4fce51cbeac218907bbf80ba40f3342df2406bce30616589a";
/* Tweak of example 6.1's internal key with the three-leaf root. */
static const char THREE_SECRET_HEX[] =
    "022d17fddb224e53e12b40c58ab3e8828d08931640105c52fc4eaf765ed51b9999";

/* transcript: one proof/output/quote shape per transaction kind. */
static const char TX_KID_HEX[] =
    "02b7e077d020fabed456a6be138a8e20e9ef40b44d873fa12c005b656eb0cf99f6";
static const char TX_SECRET_HEX[] =
    "02e6e7cfa7b82d4b3b449fa6466c893469a727d0214d48db4956a6054b8022a29b";
static const char TX_C_HEX[] =
    "84d1b7291ae5737f3c851aa33cafe0f7afeb5ccb4da086c482bb85b7525e6154"
    "7f1b5a6d1a01b1fed1f960d1a9d03327";
static const char TX_B_HEX[] =
    "b42a0bcc39598db1dca617aeea6bc367f2566636826dc961a54faae15b3b8d10"
    "afc1cb0206e70ab3b0e12c2b9478cd55";
static const char TX_DIGEST_SWAP_HEX[] =
    "77d581ac1ea31d85ecc5c251a7115ef6777e5b2a8f297933fd3a1a7e441094bd";
static const char TX_DIGEST_MINT_HEX[] =
    "096a9b2002cc0b8ebc9b79e0902159385a929f4e63f35eb9e1dee0119205efb6";
static const char TX_DIGEST_MELT_HEX[] =
    "172e38f867afa4d096fe0c1caef1aad4a19a2da6ffea25a33660172df66474b3";
static const char TX_DIGEST_MELTCH_HEX[] =
    "3b7a268b8c49e836d5235a4d4b89f1d5bfbe7bfa01d6427fa2a013f91b9d1a68";

/* --------------------------------------------------------------------------
 * Small helpers
 * ------------------------------------------------------------------------ */

static void sk_from_int(unsigned char sk[32], uint32_t v)
{
    memset(sk, 0, 32);
    sk[28] = (unsigned char)(v >> 24);
    sk[29] = (unsigned char)(v >> 16);
    sk[30] = (unsigned char)(v >> 8);
    sk[31] = (unsigned char)(v & 0xff);
}

static int pub_from_sk(const secp256k1_context *c, const unsigned char sk[32],
                       unsigned char pub[33])
{
    secp256k1_pubkey pk;
    size_t len = 33;
    return secp256k1_ec_pubkey_create((secp256k1_context *)c, &pk, sk) &&
           secp256k1_ec_pubkey_serialize(c, pub, &len, &pk,
                                         SECP256K1_EC_COMPRESSED) &&
           len == 33;
}

static int hexeq(const unsigned char *bytes, size_t len, const char *hex)
{
    /* Sized for the largest pinned vector (the 108-byte 2-of-2 leaf). */
    char buf[260];
    if (len * 2 + 1 > sizeof(buf))
        return 0;
    bytes_to_hex(bytes, len, buf);
    return strcmp(buf, hex) == 0;
}

/* --------------------------------------------------------------------------
 * Selftest
 * ------------------------------------------------------------------------ */

static int test_leaf_forms(const secp256k1_context *c)
{
    int pass = 1;
    unsigned char carol[33], alice[33], hash[32];
    hex_to_bytes(CAROL_PUB_HEX, carol, 33);
    hex_to_bytes(ALICE_PUB_HEX, alice, 33);
    hex_to_bytes(HL_HASH_HEX, hash, 32);

    unsigned char leaf[128];
    size_t len = sizeof(leaf);
    if (!nutroot_leaf_build(NUTROOT_LEAF_THRESHOLD, 1, carol, 1, 0, NULL,
                            leaf, &len) ||
        !hexeq(leaf, len, LEAF_T11_HEX)) {
        ESP_LOGE(TAG, "threshold_1of1 wire form mismatch");
        pass = 0;
    }

    unsigned char two[66];
    memcpy(two, carol, 33);
    memcpy(two + 33, alice, 33);
    len = sizeof(leaf);
    if (!nutroot_leaf_build(NUTROOT_LEAF_THRESHOLD, 2, two, 2, 0, NULL,
                            leaf, &len) ||
        !hexeq(leaf, len, LEAF_T22_HEX)) {
        ESP_LOGE(TAG, "threshold_2of2 wire form mismatch");
        pass = 0;
    }

    len = sizeof(leaf);
    if (!nutroot_leaf_build(NUTROOT_LEAF_HASHLOCK, 1, carol, 1, 0, hash,
                            leaf, &len) ||
        !hexeq(leaf, len, LEAF_HL_HEX)) {
        ESP_LOGE(TAG, "hashlock wire form mismatch");
        pass = 0;
    }

    len = sizeof(leaf);
    if (!nutroot_leaf_build(NUTROOT_LEAF_AFTER, 1, alice, 1, EX61_REFUND_TIME,
                            NULL, leaf, &len) ||
        !hexeq(leaf, len, EX61_LEAF_AFTER_HEX)) {
        ESP_LOGE(TAG, "after leaf wire form mismatch");
        pass = 0;
    }

    /* Parse round-trip of the after leaf. */
    nutroot_leaf_t parsed;
    if (!nutroot_leaf_parse(c, leaf, len, &parsed) ||
        parsed.type != NUTROOT_LEAF_AFTER || parsed.n != 1 ||
        parsed.num_keys != 1 || parsed.time != EX61_REFUND_TIME ||
        memcmp(parsed.keys, alice, 33) != 0) {
        ESP_LOGE(TAG, "after leaf parse round-trip failed");
        pass = 0;
    }

    if (pass)
        ESP_LOGI(TAG, "leaf wire forms: OK");
    return pass;
}

static int test_leaf_rejects(const secp256k1_context *c)
{
    int pass = 1;
    unsigned char base[128], buf[160];
    size_t base_len = strlen(LEAF_T11_HEX) / 2;
    hex_to_bytes(LEAF_T11_HEX, base, base_len);
    nutroot_leaf_t l;

    /* Unknown field type appended (odd types reserved, unknown even too). */
    memcpy(buf, base, base_len);
    buf[base_len] = 0x0c; buf[base_len + 1] = 0; buf[base_len + 2] = 1;
    buf[base_len + 3] = 1;
    if (nutroot_leaf_parse(c, buf, base_len + 4, &l)) {
        ESP_LOGE(TAG, "reject: unknown field accepted");
        pass = 0;
    }
    /* n = 0 (byte 5 is the n value in the T11 form). */
    memcpy(buf, base, base_len);
    buf[5] = 0;
    if (nutroot_leaf_parse(c, buf, base_len, &l)) {
        ESP_LOGE(TAG, "reject: n=0 accepted");
        pass = 0;
    }
    /* n exceeds key count. */
    memcpy(buf, base, base_len);
    buf[5] = 2;
    if (nutroot_leaf_parse(c, buf, base_len, &l)) {
        ESP_LOGE(TAG, "reject: n>keys accepted");
        pass = 0;
    }
    /* Parity twins: 02||x and 03||x count as one signer. */
    {
        unsigned char carol[33], twins[66];
        hex_to_bytes(CAROL_PUB_HEX, carol, 33);
        memcpy(twins, carol, 33);
        memcpy(twins + 33, carol, 33);
        twins[33] = 0x03;
        unsigned char leaf[128];
        size_t len = sizeof(leaf);
        if (nutroot_leaf_build(NUTROOT_LEAF_THRESHOLD, 1, twins, 2, 0, NULL,
                               leaf, &len)) {
            ESP_LOGE(TAG, "reject: parity twins built");
            pass = 0;
        }
    }
    /* Truncated TLV value. */
    if (nutroot_leaf_parse(c, base, base_len - 1, &l)) {
        ESP_LOGE(TAG, "reject: truncated leaf accepted");
        pass = 0;
    }
    /* Unknown leaf version. */
    memcpy(buf, base, base_len);
    buf[0] = 0x01;
    if (nutroot_leaf_parse(c, buf, base_len, &l)) {
        ESP_LOGE(TAG, "reject: version 0x01 accepted");
        pass = 0;
    }
    /* threshold leaf must not carry a time field (TLVs still ascend). */
    memcpy(buf, base, base_len);
    buf[base_len] = 0x06; buf[base_len + 1] = 0; buf[base_len + 2] = 1;
    buf[base_len + 3] = 1;
    if (nutroot_leaf_parse(c, buf, base_len + 4, &l)) {
        ESP_LOGE(TAG, "reject: threshold+time accepted");
        pass = 0;
    }

    if (pass)
        ESP_LOGI(TAG, "leaf parse rejections: OK");
    return pass;
}

static int test_merkle(void)
{
    int pass = 1;
    /* three_leaf_tree = [threshold_1of1, 6.1 after leaf, hashlock]. */
    const char *leaves_hex[3] = {LEAF_T11_HEX, EX61_LEAF_AFTER_HEX, LEAF_HL_HEX};
    unsigned char leaf[128], hashes[3 * 32], keep[3 * 32], root[32];
    for (int i = 0; i < 3; i++) {
        size_t len = strlen(leaves_hex[i]) / 2;
        hex_to_bytes(leaves_hex[i], leaf, len);
        nutroot_leaf_hash(leaf, len, keep + i * 32);
    }

    memcpy(hashes, keep, sizeof(keep));
    if (!nutroot_merkle_root(hashes, 3, root) ||
        !hexeq(root, 32, THREE_ROOT_HEX)) {
        ESP_LOGE(TAG, "three-leaf root mismatch");
        pass = 0;
    }
    /* Permutation invariance: the root commits the leaf set. */
    memcpy(hashes, keep + 64, 32);
    memcpy(hashes + 32, keep, 32);
    memcpy(hashes + 64, keep + 32, 32);
    if (!nutroot_merkle_root(hashes, 3, root) ||
        !hexeq(root, 32, THREE_ROOT_HEX)) {
        ESP_LOGE(TAG, "permuted three-leaf root mismatch");
        pass = 0;
    }
    /* Path for transmitted index 2 (two siblings via the odd-count fold). */
    unsigned char path[NUTROOT_MAX_TREE_DEPTH * 32];
    size_t path_len = 0;
    memcpy(hashes, keep, sizeof(keep));
    if (!nutroot_merkle_path(hashes, 3, 2, path, &path_len) || path_len != 2 ||
        !hexeq(path, 32, THREE_PATH0_HEX) ||
        !hexeq(path + 32, 32, THREE_PATH1_HEX)) {
        ESP_LOGE(TAG, "three-leaf path mismatch");
        pass = 0;
    }
    if (!nutroot_root_from_path(keep + 64, path, path_len, root) ||
        !hexeq(root, 32, THREE_ROOT_HEX)) {
        ESP_LOGE(TAG, "root_from_path mismatch");
        pass = 0;
    }
    /* Every leaf of an 8-leaf tree reconstructs the root through its path. */
    {
        unsigned char h8[8 * 32], scratch[8 * 32], r8[32], r[32];
        for (int i = 0; i < 8; i++) {
            unsigned char seed[2] = {(unsigned char)i, 0x5a};
            cashu_sha256(seed, 2, h8 + i * 32);
        }
        memcpy(scratch, h8, sizeof(h8));
        nutroot_merkle_root(scratch, 8, r8);
        for (int i = 0; i < 8; i++) {
            memcpy(scratch, h8, sizeof(h8));
            if (!nutroot_merkle_path(scratch, 8, (size_t)i, path, &path_len) ||
                !nutroot_root_from_path(h8 + i * 32, path, path_len, r) ||
                memcmp(r, r8, 32) != 0) {
                ESP_LOGE(TAG, "8-leaf path round-trip failed at %d", i);
                pass = 0;
            }
        }
    }

    if (pass)
        ESP_LOGI(TAG, "merkle fold + paths: OK");
    return pass;
}

static int test_tweak(const secp256k1_context *c)
{
    int pass = 1;
    unsigned char K[33], root[32], t[32], P[33];

    hex_to_bytes(EX61_INTERNAL_HEX, K, 33);
    hex_to_bytes(EX61_ROOT_HEX, root, 32);
    if (!nutroot_tweak_scalar(K, root, t) || !hexeq(t, 32, EX61_TWEAK_HEX)) {
        ESP_LOGE(TAG, "6.1 tweak scalar mismatch");
        pass = 0;
    }
    if (!nutroot_tweak_pubkey(c, K, root, P) || !hexeq(P, 33, EX61_SECRET_HEX)) {
        ESP_LOGE(TAG, "6.1 tweaked secret mismatch");
        pass = 0;
    }
    /* The 6.1 single-leaf root is the leaf hash itself. */
    {
        unsigned char leaf[64], lh[32];
        size_t len = strlen(EX61_LEAF_AFTER_HEX) / 2;
        hex_to_bytes(EX61_LEAF_AFTER_HEX, leaf, len);
        nutroot_leaf_hash(leaf, len, lh);
        if (!hexeq(lh, 32, EX61_ROOT_HEX)) {
            ESP_LOGE(TAG, "6.1 single-leaf root mismatch");
            pass = 0;
        }
    }
    /* three_leaf_secret: same internal key, three-leaf root. */
    hex_to_bytes(THREE_ROOT_HEX, root, 32);
    if (!nutroot_tweak_pubkey(c, K, root, P) ||
        !hexeq(P, 33, THREE_SECRET_HEX)) {
        ESP_LOGE(TAG, "three-leaf secret mismatch");
        pass = 0;
    }
    /* Empty tweak (spec 3.8): hash over K alone. */
    hex_to_bytes(CAROL_PUB_HEX, K, 33);
    if (!nutroot_tweak_scalar(K, NULL, t) || !hexeq(t, 32, ET_TWEAK_HEX)) {
        ESP_LOGE(TAG, "empty tweak scalar mismatch");
        pass = 0;
    }
    if (!nutroot_tweak_pubkey(c, K, NULL, P) || !hexeq(P, 33, ET_SECRET_HEX)) {
        ESP_LOGE(TAG, "empty tweak secret mismatch");
        pass = 0;
    }
    /* Key-path signing key: (carol_priv + t) mod n. */
    {
        unsigned char sk[32];
        sk_from_int(sk, 3);
        if (!nutroot_tweak_seckey(c, sk, NULL) ||
            !hexeq(sk, 32, ET_KP_PRIV_HEX)) {
            ESP_LOGE(TAG, "empty tweak seckey mismatch");
            pass = 0;
        }
    }

    if (pass)
        ESP_LOGI(TAG, "tweak derivations: OK");
    return pass;
}

static int test_transcript(void)
{
    int pass = 1;
    static unsigned char kid[33], secret[33], C[48], B[48];
    hex_to_bytes(TX_KID_HEX, kid, 33);
    hex_to_bytes(TX_SECRET_HEX, secret, 33);
    hex_to_bytes(TX_C_HEX, C, 48);
    hex_to_bytes(TX_B_HEX, B, 48);

    nutroot_input_t in = {0};
    in.amount = 8;
    in.keyset_id = kid; in.keyset_id_len = 33;
    in.secret = secret; in.secret_len = 33;
    in.C = C; in.C_len = 48;

    nutroot_output_t outs[2] = {{0}, {0}};
    for (int i = 0; i < 2; i++) {
        outs[i].amount = 4;
        outs[i].keyset_id = kid; outs[i].keyset_id_len = 33;
        outs[i].B_ = B; outs[i].B_len = 48;
    }
    nutroot_quote_t mint_q = {8, "quote-mint-0001"};
    nutroot_quote_t melt_q = {8, "quote-melt-0001"};

    unsigned char d[32];
    nutroot_tx_t tx = {0};

    tx.proof_inputs = &in; tx.n_proof_inputs = 1;
    tx.blinded_outputs = outs; tx.n_blinded_outputs = 2;
    if (!nutroot_legacy_tx_digest(&tx, d) || !hexeq(d, 32, TX_DIGEST_SWAP_HEX)) {
        ESP_LOGE(TAG, "swap transcript digest mismatch");
        pass = 0;
    }

    memset(&tx, 0, sizeof(tx));
    outs[0].amount = 8;
    tx.mint_quote_inputs = &mint_q; tx.n_mint_quote_inputs = 1;
    tx.blinded_outputs = outs; tx.n_blinded_outputs = 1;
    if (!nutroot_legacy_tx_digest(&tx, d) || !hexeq(d, 32, TX_DIGEST_MINT_HEX)) {
        ESP_LOGE(TAG, "mint transcript digest mismatch");
        pass = 0;
    }

    memset(&tx, 0, sizeof(tx));
    tx.proof_inputs = &in; tx.n_proof_inputs = 1;
    tx.melt_quote_outputs = &melt_q; tx.n_melt_quote_outputs = 1;
    if (!nutroot_legacy_tx_digest(&tx, d) || !hexeq(d, 32, TX_DIGEST_MELT_HEX)) {
        ESP_LOGE(TAG, "melt transcript digest mismatch");
        pass = 0;
    }

    /* Melt with NUT-08 change: zero amounts encode as zero-length records. */
    memset(&tx, 0, sizeof(tx));
    outs[0].amount = 0;
    outs[1].amount = 0;
    tx.proof_inputs = &in; tx.n_proof_inputs = 1;
    tx.blinded_outputs = outs; tx.n_blinded_outputs = 2;
    tx.melt_quote_outputs = &melt_q; tx.n_melt_quote_outputs = 1;
    if (!nutroot_legacy_tx_digest(&tx, d) || !hexeq(d, 32, TX_DIGEST_MELTCH_HEX)) {
        ESP_LOGE(TAG, "melt-with-change transcript digest mismatch");
        pass = 0;
    }

    if (pass)
        ESP_LOGI(TAG, "transaction transcripts: OK");
    return pass;
}

static int test_signatures(const secp256k1_context *c)
{
    int pass = 1;
    unsigned char digest[32], expect[32], sig[64], secret[33];

    /* The vector digest is the SHA256 of its illustrative preimage. */
    cashu_sha256((const unsigned char *)EX61_DIGEST_PREIMAGE,
                 strlen(EX61_DIGEST_PREIMAGE), digest);
    hex_to_bytes(EX61_DIGEST_HEX, expect, 32);
    if (memcmp(digest, expect, 32) != 0) {
        ESP_LOGE(TAG, "6.1 digest preimage mismatch");
        pass = 0;
    }
    /* Key-path signature verifies under the secret's x-only key. */
    hex_to_bytes(EX61_SECRET_HEX, secret, 33);
    {
        secp256k1_xonly_pubkey xonly;
        unsigned char sigv[64];
        hex_to_bytes(EX61_KP_SIG_HEX, sigv, 64);
        if (!secp256k1_xonly_pubkey_parse(c, &xonly, secret + 1) ||
            !secp256k1_schnorrsig_verify(c, sigv, digest, 32, &xonly)) {
            ESP_LOGE(TAG, "6.1 keypath signature does not verify");
            pass = 0;
        }
        /* Script-path signature is by the refund key (alice). */
        unsigned char alice[33];
        hex_to_bytes(ALICE_PUB_HEX, alice, 33);
        hex_to_bytes(EX61_SP_SIG_HEX, sigv, 64);
        if (!secp256k1_xonly_pubkey_parse(c, &xonly, alice + 1) ||
            !secp256k1_schnorrsig_verify(c, sigv, digest, 32, &xonly)) {
            ESP_LOGE(TAG, "6.1 scriptpath signature does not verify");
            pass = 0;
        }
    }
    /* Deterministic signing (zero aux) reproduces the vector byte-for-byte. */
    {
        unsigned char kp_priv[32];
        hex_to_bytes(EX61_KP_PRIV_HEX, kp_priv, 32);
        if (!nutroot_sign_digest(c, kp_priv, digest, sig) ||
            !hexeq(sig, 64, EX61_KP_SIG_HEX)) {
            ESP_LOGE(TAG, "deterministic keypath signature mismatch");
            pass = 0;
        }
    }

    if (pass)
        ESP_LOGI(TAG, "signature vectors: OK");
    return pass;
}

/* Fixed fake token bytes for e2e verification transactions (witness checks
 * never look at C/B_ beyond the transcript). */
static const unsigned char E2E_KID[8] = {0x02, 0, 0, 0, 0, 0, 0, 0};

static int e2e_verify(const secp256k1_context *c,
                      const unsigned char secret[33], const char *witness,
                      int64_t now)
{
    static unsigned char C[48], B[48];
    memset(C, 0x11, 48);
    memset(B, 0x22, 48);
    nutroot_input_t in = {0};
    in.amount = 8;
    in.keyset_id = E2E_KID; in.keyset_id_len = sizeof(E2E_KID);
    in.secret = secret; in.secret_len = 33;
    in.C = C; in.C_len = 48;
    in.witness = witness;
    nutroot_output_t out = {0};
    out.amount = 8;
    out.keyset_id = E2E_KID; out.keyset_id_len = sizeof(E2E_KID);
    out.B_ = B; out.B_len = 48;
    nutroot_tx_t tx = {0};
    tx.proof_inputs = &in; tx.n_proof_inputs = 1;
    tx.blinded_outputs = &out; tx.n_blinded_outputs = 1;
    return nutroot_legacy_verify_transaction(c, &tx, now);
}

static int e2e_digest(const secp256k1_context *c,
                      const unsigned char secret[33], unsigned char d[32])
{
    int ok = 0;
    /* Same shape as e2e_verify, witness-free (witnesses are not hashed). */
    (void)c;
    static unsigned char C[48], B[48];
    memset(C, 0x11, 48);
    memset(B, 0x22, 48);
    nutroot_input_t in = {0};
    in.amount = 8;
    in.keyset_id = E2E_KID; in.keyset_id_len = sizeof(E2E_KID);
    in.secret = secret; in.secret_len = 33;
    in.C = C; in.C_len = 48;
    nutroot_output_t out = {0};
    out.amount = 8;
    out.keyset_id = E2E_KID; out.keyset_id_len = sizeof(E2E_KID);
    out.B_ = B; out.B_len = 48;
    nutroot_tx_t tx = {0};
    tx.proof_inputs = &in; tx.n_proof_inputs = 1;
    tx.blinded_outputs = &out; tx.n_blinded_outputs = 1;
    ok = nutroot_legacy_tx_digest(&tx, d);
    return ok;
}

static int test_verify_e2e(const secp256k1_context *c)
{
    int pass = 1;
    unsigned char secret[33], d[32], sig[64];
    char sig_hex[129], wit[512];

    /* Key path: the empty-tweak secret spends with its tweaked key. */
    hex_to_bytes(ET_SECRET_HEX, secret, 33);
    e2e_digest(c, secret, d);
    {
        unsigned char kp[32];
        hex_to_bytes(ET_KP_PRIV_HEX, kp, 32);
        nutroot_sign_digest(c, kp, d, sig);
        bytes_to_hex(sig, 64, sig_hex);
        snprintf(wit, sizeof(wit), "{\"signatures\":[\"%s\"]}", sig_hex);
        if (!e2e_verify(c, secret, wit, NOW_TS)) {
            ESP_LOGE(TAG, "e2e keypath verify failed");
            pass = 0;
        }
        /* Missing witness rejects. */
        if (e2e_verify(c, secret, NULL, NOW_TS)) {
            ESP_LOGE(TAG, "e2e missing witness accepted");
            pass = 0;
        }
        /* Flipped signature bit rejects. */
        sig[10] ^= 0x01;
        bytes_to_hex(sig, 64, sig_hex);
        snprintf(wit, sizeof(wit), "{\"signatures\":[\"%s\"]}", sig_hex);
        if (e2e_verify(c, secret, wit, NOW_TS)) {
            ESP_LOGE(TAG, "e2e tampered keypath sig accepted");
            pass = 0;
        }
    }

    /* Script path: the 6.1 after leaf, empty path, signed by the refund key. */
    hex_to_bytes(EX61_SECRET_HEX, secret, 33);
    e2e_digest(c, secret, d);
    {
        unsigned char alice_sk[32];
        sk_from_int(alice_sk, 4);
        nutroot_sign_digest(c, alice_sk, d, sig);
        bytes_to_hex(sig, 64, sig_hex);
        snprintf(wit, sizeof(wit),
                 "{\"leaf\":\"%s\",\"control\":{\"K\":\"%s\",\"path\":[]},"
                 "\"signatures\":[\"%s\"]}",
                 EX61_LEAF_AFTER_HEX, EX61_INTERNAL_HEX, sig_hex);
        if (!e2e_verify(c, secret, wit, NOW_TS)) {
            ESP_LOGE(TAG, "e2e scriptpath verify failed");
            pass = 0;
        }
        /* Locktime not reached rejects. */
        if (e2e_verify(c, secret, wit, EX61_REFUND_TIME - 1)) {
            ESP_LOGE(TAG, "e2e premature after-spend accepted");
            pass = 0;
        }
        /* A bogus merkle path element breaks the commitment. */
        char wit_badpath[512];
        snprintf(wit_badpath, sizeof(wit_badpath),
                 "{\"leaf\":\"%s\",\"control\":{\"K\":\"%s\",\"path\":["
                 "\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                 "aaaaaaaa\"]},\"signatures\":[\"%s\"]}",
                 EX61_LEAF_AFTER_HEX, EX61_INTERNAL_HEX, sig_hex);
        if (e2e_verify(c, secret, wit_badpath, NOW_TS)) {
            ESP_LOGE(TAG, "e2e bogus merkle path accepted");
            pass = 0;
        }
    }

    /* Hashlock: preimage gates the spend. */
    {
        unsigned char pre[32], hl[32], carol[33], K[33], leaf[128], root[32];
        char leaf_hex[257];
        memset(pre, 0x07, 32);
        cashu_sha256(pre, 32, hl);
        hex_to_bytes(CAROL_PUB_HEX, carol, 33);
        hex_to_bytes(ALICE_PUB_HEX, K, 33);
        size_t leaf_len = sizeof(leaf);
        nutroot_leaf_build(NUTROOT_LEAF_HASHLOCK, 1, carol, 1, 0, hl,
                           leaf, &leaf_len);
        nutroot_leaf_hash(leaf, leaf_len, root); /* single-leaf tree */
        nutroot_tweak_pubkey(c, K, root, secret);
        e2e_digest(c, secret, d);
        unsigned char carol_sk[32];
        sk_from_int(carol_sk, 3);
        nutroot_sign_digest(c, carol_sk, d, sig);
        bytes_to_hex(sig, 64, sig_hex);
        bytes_to_hex(leaf, leaf_len, leaf_hex);
        char pre_hex[65];
        bytes_to_hex(pre, 32, pre_hex);
        char wit_hl[768];
        snprintf(wit_hl, sizeof(wit_hl),
                 "{\"leaf\":\"%s\",\"control\":{\"K\":\"%s\",\"path\":[]},"
                 "\"signatures\":[\"%s\"],\"preimage\":\"%s\"}",
                 leaf_hex, ALICE_PUB_HEX, sig_hex, pre_hex);
        if (!e2e_verify(c, secret, wit_hl, NOW_TS)) {
            ESP_LOGE(TAG, "e2e hashlock verify failed");
            pass = 0;
        }
        memset(pre, 0x08, 32);
        bytes_to_hex(pre, 32, pre_hex);
        snprintf(wit_hl, sizeof(wit_hl),
                 "{\"leaf\":\"%s\",\"control\":{\"K\":\"%s\",\"path\":[]},"
                 "\"signatures\":[\"%s\"],\"preimage\":\"%s\"}",
                 leaf_hex, ALICE_PUB_HEX, sig_hex, pre_hex);
        if (e2e_verify(c, secret, wit_hl, NOW_TS)) {
            ESP_LOGE(TAG, "e2e wrong preimage accepted");
            pass = 0;
        }
    }

    /* Threshold 2-of-2 (carol + alice): one signature is not enough. */
    {
        unsigned char leaf[128], root[32], carol_sk[32], alice_sk[32];
        char leaf_hex[257], sig2_hex[129];
        size_t leaf_len = strlen(LEAF_T22_HEX) / 2;
        hex_to_bytes(LEAF_T22_HEX, leaf, leaf_len);
        strcpy(leaf_hex, LEAF_T22_HEX);
        nutroot_leaf_hash(leaf, leaf_len, root);
        unsigned char K[33];
        hex_to_bytes(CAROL_PUB_HEX, K, 33);
        nutroot_tweak_pubkey(c, K, root, secret);
        e2e_digest(c, secret, d);
        sk_from_int(carol_sk, 3);
        sk_from_int(alice_sk, 4);
        nutroot_sign_digest(c, carol_sk, d, sig);
        bytes_to_hex(sig, 64, sig_hex);
        nutroot_sign_digest(c, alice_sk, d, sig);
        bytes_to_hex(sig, 64, sig2_hex);
        char wit_t[768];
        snprintf(wit_t, sizeof(wit_t),
                 "{\"leaf\":\"%s\",\"control\":{\"K\":\"%s\",\"path\":[]},"
                 "\"signatures\":[\"%s\",\"%s\"]}",
                 leaf_hex, CAROL_PUB_HEX, sig_hex, sig2_hex);
        if (!e2e_verify(c, secret, wit_t, NOW_TS)) {
            ESP_LOGE(TAG, "e2e 2of2 verify failed");
            pass = 0;
        }
        snprintf(wit_t, sizeof(wit_t),
                 "{\"leaf\":\"%s\",\"control\":{\"K\":\"%s\",\"path\":[]},"
                 "\"signatures\":[\"%s\"]}",
                 leaf_hex, CAROL_PUB_HEX, sig_hex);
        if (e2e_verify(c, secret, wit_t, NOW_TS)) {
            ESP_LOGE(TAG, "e2e 2of2 with one sig accepted");
            pass = 0;
        }
    }

    /* Mixed transaction: a pre-v3 input is skipped, the v3 input verifies. */
    {
        static unsigned char C[48], B[48];
        memset(C, 0x11, 48);
        memset(B, 0x22, 48);
        static const unsigned char v1_kid[8] = {0x01, 0, 0, 0, 0, 0, 0, 0};
        hex_to_bytes(ET_SECRET_HEX, secret, 33);
        nutroot_input_t ins[2] = {{0}, {0}};
        ins[0].amount = 8;
        ins[0].keyset_id = v1_kid; ins[0].keyset_id_len = 8;
        ins[0].secret = (const unsigned char *)"plain-secret";
        ins[0].secret_len = 12;
        ins[0].C = C; ins[0].C_len = 48;
        ins[1].amount = 8;
        ins[1].keyset_id = E2E_KID; ins[1].keyset_id_len = 8;
        ins[1].secret = secret; ins[1].secret_len = 33;
        ins[1].C = C; ins[1].C_len = 48;
        nutroot_output_t out = {0};
        out.amount = 16;
        out.keyset_id = E2E_KID; out.keyset_id_len = 8;
        out.B_ = B; out.B_len = 48;
        nutroot_tx_t tx = {0};
        tx.proof_inputs = ins; tx.n_proof_inputs = 2;
        tx.blinded_outputs = &out; tx.n_blinded_outputs = 1;
        unsigned char kp[32];
        hex_to_bytes(ET_KP_PRIV_HEX, kp, 32);
        if (!nutroot_legacy_tx_digest(&tx, d) || !nutroot_sign_digest(c, kp, d, sig)) {
            ESP_LOGE(TAG, "e2e mixed setup failed");
            pass = 0;
        }
        bytes_to_hex(sig, 64, sig_hex);
        snprintf(wit, sizeof(wit), "{\"signatures\":[\"%s\"]}", sig_hex);
        ins[1].witness = wit;
        if (!nutroot_legacy_verify_transaction(c, &tx, NOW_TS)) {
            ESP_LOGE(TAG, "e2e mixed transaction verify failed");
            pass = 0;
        }
    }

    if (pass)
        ESP_LOGI(TAG, "witness verification e2e: OK");
    return pass;
}

int nutroot_run_tests(const secp256k1_context *ctx)
{
    int pass = 1;
    pass &= test_leaf_forms(ctx);
    pass &= test_leaf_rejects(ctx);
    pass &= test_merkle();
    pass &= test_tweak(ctx);
    pass &= test_transcript();
    vTaskDelay(2);
    pass &= test_signatures(ctx);
    pass &= test_verify_e2e(ctx);
    if (pass)
        ESP_LOGI(TAG, "all nutroot tests passed");
    else
        ESP_LOGE(TAG, "some nutroot tests FAILED");
    return pass;
}

/* --------------------------------------------------------------------------
 * Benchmark: witness verification, mirroring nutshell's
 * scripts/bench_nutroot_witness.py case names and timed boundary.
 * ------------------------------------------------------------------------ */

static void bench_yield(void)
{
    vTaskDelay(2);
}

static int cmp_i64(const void *a, const void *b)
{
    int64_t d = *(const int64_t *)a - *(const int64_t *)b;
    return d < 0 ? -1 : d > 0 ? 1 : 0;
}

#define NB_MAX_ITERS 8

static int64_t nb_report(const char *label, int iters, int64_t *s,
                         size_t per_div)
{
    qsort(s, (size_t)iters, sizeof(int64_t), cmp_i64);
    int64_t total = 0;
    for (int i = 0; i < iters; i++)
        total += s[i];
    int64_t mean = total / iters;
    int64_t med = (iters % 2) ? s[iters / 2]
                              : (s[iters / 2 - 1] + s[iters / 2]) / 2;
    if (per_div)
        ESP_LOGI(TAG, "%-24s x%-2d mean %8lld med %8lld min %8lld us (%lld us/in)",
                 label, iters, mean, med, s[0], mean / (int64_t)per_div);
    else
        ESP_LOGI(TAG, "%-24s x%-2d mean %8lld med %8lld min %8lld us",
                 label, iters, mean, med, s[0]);
    return mean;
}

/* Timed samples with a yield between iterations (feeds the idle watchdog
 * without distorting per-call time). Body is variadic: braces don't
 * protect commas in macro arguments. */
#define NBENCH(mean_out, label, iters, per_div, ...)                       \
    do {                                                                   \
        int64_t nb_s[NB_MAX_ITERS];                                        \
        int nb_n = (iters) > NB_MAX_ITERS ? NB_MAX_ITERS : (iters);        \
        for (int bi = 0; bi < nb_n; bi++) {                                \
            int64_t t0 = esp_timer_get_time();                             \
            __VA_ARGS__;                                                   \
            nb_s[bi] = esp_timer_get_time() - t0;                          \
            vTaskDelay(2);                                                 \
        }                                                                  \
        mean_out = nb_report(label, nb_n, nb_s, (per_div));                \
    } while (0)

/* Bench proofs sit on the short-form v3 keyset id nutshell's bench uses. */
static const unsigned char BENCH_KID[8] = {0x02, 0, 0, 0, 0, 0, 0, 0};

enum { BMAX = 64 };

/* One benchmark transaction: fixed-capacity arrays, heap-allocated once. */
typedef struct {
    size_t n_in, n_out;
    nutroot_input_t ins[BMAX];
    nutroot_output_t outs[BMAX];
    unsigned char secrets[BMAX][33];
    unsigned char Cs[BMAX][48];
    unsigned char Bs[BMAX][48];
    char *wit[BMAX];
    nutroot_tx_t tx;
} btx_t;

/* Per-input state carried from secret creation to witness signing (the
 * witness signs the whole transaction's digest, so multi-input cases build
 * all secrets first). Heap members freed by btx_reset. */
typedef struct {
    unsigned char *leaf;   /* script path: serialized leaf */
    uint16_t leaf_len;
    unsigned char *path;   /* script path: merkle siblings */
    uint8_t path_len;
    unsigned char K33[33];
    unsigned char sk[32];  /* the one signer (multi-sig cases are inline) */
    uint8_t keypath;
} pend_t;

static pend_t pend[BMAX];

static void pend_reset(void)
{
    for (int i = 0; i < BMAX; i++) {
        free(pend[i].leaf);
        free(pend[i].path);
        memset(&pend[i], 0, sizeof(pend[i]));
    }
}

static void btx_reset(btx_t *b)
{
    for (int i = 0; i < BMAX; i++) {
        free(b->wit[i]);
        b->wit[i] = NULL;
    }
    b->n_in = b->n_out = 0;
    pend_reset();
}

/* Deterministic realistic-looking bytes (nutshell's _fake_bytes). */
static void fake48(const char *seed, uint32_t i, unsigned char out[48])
{
    char buf[48];
    unsigned char h[32];
    int n = snprintf(buf, sizeof(buf), "%s:%lu:0", seed, (unsigned long)i);
    cashu_sha256((const unsigned char *)buf, (size_t)n, h);
    memcpy(out, h, 32);
    n = snprintf(buf, sizeof(buf), "%s:%lu:1", seed, (unsigned long)i);
    cashu_sha256((const unsigned char *)buf, (size_t)n, h);
    memcpy(out + 32, h, 16);
}

/* Amount 8, bench keyset id, fake C/B_ everywhere; secrets filled later. */
static void btx_frame(btx_t *b, size_t n_in, size_t n_out, const char *tag)
{
    btx_reset(b);
    b->n_in = n_in;
    b->n_out = n_out;
    for (size_t i = 0; i < n_in; i++) {
        nutroot_input_t *in = &b->ins[i];
        memset(in, 0, sizeof(*in));
        in->amount = 8;
        in->keyset_id = BENCH_KID; in->keyset_id_len = sizeof(BENCH_KID);
        in->secret = b->secrets[i]; in->secret_len = 33;
        fake48(tag, (uint32_t)i, b->Cs[i]);
        in->C = b->Cs[i]; in->C_len = 48;
    }
    for (size_t i = 0; i < n_out; i++) {
        nutroot_output_t *o = &b->outs[i];
        memset(o, 0, sizeof(*o));
        o->amount = 8;
        o->keyset_id = BENCH_KID; o->keyset_id_len = sizeof(BENCH_KID);
        fake48(tag, (uint32_t)(0x1000 + i), b->Bs[i]);
        o->B_ = b->Bs[i]; o->B_len = 48;
    }
    memset(&b->tx, 0, sizeof(b->tx));
    b->tx.proof_inputs = b->ins; b->tx.n_proof_inputs = n_in;
    b->tx.blinded_outputs = b->outs; b->tx.n_blinded_outputs = n_out;
}

static int sig_hex_for(const secp256k1_context *c, const unsigned char sk[32],
                       const unsigned char d[32], char out[129])
{
    unsigned char sig[64];
    if (!nutroot_sign_digest(c, sk, d, sig))
        return 0;
    bytes_to_hex(sig, 64, out);
    return 1;
}

static char *wit_keypath_json(const secp256k1_context *c,
                              const unsigned char sk[32],
                              const unsigned char d[32])
{
    char sig[129];
    if (!sig_hex_for(c, sk, d, sig))
        return NULL;
    char *w = malloc(160);
    if (w)
        snprintf(w, 160, "{\"signatures\":[\"%s\"]}", sig);
    return w;
}

static char *wit_script_json(const unsigned char *leaf, size_t leaf_len,
                             const unsigned char K33[33],
                             const unsigned char *path, size_t path_len,
                             char sig_hex[][129], int n_sigs,
                             const unsigned char *pre, size_t pre_len)
{
    size_t cap = leaf_len * 2 + 70 + path_len * 70 + (size_t)n_sigs * 134 +
                 pre_len * 2 + 96;
    char *w = malloc(cap);
    if (!w)
        return NULL;
    char *p = w;
    p += sprintf(p, "{\"leaf\":\"");
    bytes_to_hex(leaf, leaf_len, p);
    p += leaf_len * 2;
    p += sprintf(p, "\",\"control\":{\"K\":\"");
    bytes_to_hex(K33, 33, p);
    p += 66;
    p += sprintf(p, "\",\"path\":[");
    for (size_t i = 0; i < path_len; i++) {
        *p++ = '"';
        bytes_to_hex(path + i * 32, 32, p);
        p += 64;
        *p++ = '"';
        if (i + 1 < path_len)
            *p++ = ',';
    }
    p += sprintf(p, "]},\"signatures\":[");
    for (int i = 0; i < n_sigs; i++) {
        p += sprintf(p, "\"%s\"%s", sig_hex[i], i + 1 < n_sigs ? "," : "");
    }
    *p++ = ']';
    if (pre) {
        p += sprintf(p, ",\"preimage\":\"");
        bytes_to_hex(pre, pre_len, p);
        p += pre_len * 2;
        *p++ = '"';
    }
    *p++ = '}';
    *p = '\0';
    return w;
}

/* One 1-of-1 threshold leaf, heap-serialized. */
static unsigned char *leaf_t11(const secp256k1_context *c, uint32_t key_i,
                               size_t *len_out)
{
    unsigned char sk[32], pub[33];
    sk_from_int(sk, key_i);
    if (!pub_from_sk(c, sk, pub))
        return NULL;
    unsigned char *leaf = malloc(64);
    if (!leaf)
        return NULL;
    size_t len = 64;
    if (!nutroot_leaf_build(NUTROOT_LEAF_THRESHOLD, 1, pub, 1, 0, NULL,
                            leaf, &len)) {
        free(leaf);
        return NULL;
    }
    *len_out = len;
    return leaf;
}

/* Phase 1 of a script 1-of-1 input: single-leaf tree under internal key
 * key_i+1, spend key key_i; fills the secret and the pend slot. */
static int script_input_1of1(const secp256k1_context *c, btx_t *b, size_t ii,
                             uint32_t key_i)
{
    pend_t *pd = &pend[ii];
    size_t leaf_len;
    unsigned char *leaf = leaf_t11(c, key_i, &leaf_len);
    if (!leaf)
        return 0;
    unsigned char root[32], K_sk[32];
    nutroot_leaf_hash(leaf, leaf_len, root); /* 1-leaf tree: root = hash */
    sk_from_int(K_sk, key_i + 1);
    if (!pub_from_sk(c, K_sk, pd->K33) ||
        !nutroot_tweak_pubkey(c, pd->K33, root, b->secrets[ii])) {
        free(leaf);
        return 0;
    }
    pd->leaf = leaf;
    pd->leaf_len = (uint16_t)leaf_len;
    pd->path = NULL;
    pd->path_len = 0;
    sk_from_int(pd->sk, key_i);
    pd->keypath = 0;
    return 1;
}

/* Phase 1 of a key-path input: bare pubkey secret. */
static int keypath_input(const secp256k1_context *c, btx_t *b, size_t ii,
                         uint32_t key_i)
{
    pend_t *pd = &pend[ii];
    sk_from_int(pd->sk, key_i);
    pd->keypath = 1;
    return pub_from_sk(c, pd->sk, b->secrets[ii]);
}

/* Phase 2: digest, then per-input witness from the pend slots. */
static int finish_witnesses(const secp256k1_context *c, btx_t *b)
{
    unsigned char d[32];
    if (!nutroot_legacy_tx_digest(&b->tx, d))
        return 0;
    for (size_t i = 0; i < b->n_in; i++) {
        pend_t *pd = &pend[i];
        if (pd->keypath) {
            b->wit[i] = wit_keypath_json(c, pd->sk, d);
        } else {
            char sig[1][129];
            if (!sig_hex_for(c, pd->sk, d, sig[0]))
                return 0;
            b->wit[i] = wit_script_json(pd->leaf, pd->leaf_len, pd->K33,
                                        pd->path, pd->path_len, sig, 1,
                                        NULL, 0);
        }
        if (!b->wit[i])
            return 0;
        b->ins[i].witness = b->wit[i];
        if (i % 4 == 3)
            vTaskDelay(2);
    }
    return 1;
}

static int bench_sanity(const secp256k1_context *c, btx_t *b, const char *name)
{
    if (!nutroot_legacy_verify_transaction(c, &b->tx, NOW_TS)) {
        ESP_LOGE(TAG, "SANITY FAILED: %s", name);
        return 0;
    }
    return 1;
}

static void bench_case_run(const secp256k1_context *c, btx_t *b,
                           const char *label, int iters, int hook,
                           size_t per_div)
{
    if (!bench_sanity(c, b, label))
        return;
    if (hook)
        nutroot_set_yield_hook(bench_yield);
    int64_t mean;
    NBENCH(mean, label, iters, per_div,
           { nutroot_legacy_verify_transaction(c, &b->tx, NOW_TS); });
    (void)mean;
    nutroot_set_yield_hook(NULL);
}

/* A single-input script case over an arbitrary leaf set. leaf_kind(i)
 * selects the mix; the spend leaf is a 1-of-1 threshold at spend_idx. */
typedef int (*leaf_mix_fn)(const secp256k1_context *c, uint32_t base,
                           size_t idx, unsigned char *leaf, size_t *len);

static int mix_thresh_only(const secp256k1_context *c, uint32_t base,
                           size_t idx, unsigned char *leaf, size_t *len)
{
    unsigned char sk[32], pub[33];
    sk_from_int(sk, base + (uint32_t)idx);
    if (!pub_from_sk(c, sk, pub))
        return 0;
    return nutroot_leaf_build(NUTROOT_LEAF_THRESHOLD, 1, pub, 1, 0, NULL,
                              leaf, len);
}

/* nutshell's script_multileaf_8 mix: threshold / after / hashlock / spend /
 * 2-of-2 / after / hashlock / 1-of-2. */
static int mix_nutshell8(const secp256k1_context *c, uint32_t base,
                         size_t idx, unsigned char *leaf, size_t *len)
{
    unsigned char sk[32], pub[33], pub2[33], keys[66], pre[32], h[32];
    sk_from_int(sk, base + (uint32_t)idx);
    if (!pub_from_sk(c, sk, pub))
        return 0;
    switch (idx) {
    case 1:
    case 5:
        return nutroot_leaf_build(NUTROOT_LEAF_AFTER, 1, pub, 1, PAST_TIME,
                                  NULL, leaf, len);
    case 2:
    case 6:
        memset(pre, (int)idx, 32);
        cashu_sha256(pre, 32, h);
        return nutroot_leaf_build(NUTROOT_LEAF_HASHLOCK, 1, pub, 1, 0, h,
                                  leaf, len);
    case 4:
    case 7: {
        unsigned char sk2[32];
        sk_from_int(sk2, base + (uint32_t)idx + 100);
        if (!pub_from_sk(c, sk2, pub2))
            return 0;
        memcpy(keys, pub, 33);
        memcpy(keys + 33, pub2, 33);
        return nutroot_leaf_build(NUTROOT_LEAF_THRESHOLD,
                                  idx == 4 ? 2 : 1, keys, 2, 0, NULL,
                                  leaf, len);
    }
    default:
        return nutroot_leaf_build(NUTROOT_LEAF_THRESHOLD, 1, pub, 1, 0, NULL,
                                  leaf, len);
    }
}

/* nutshell's leaves-sweep mix: kind = i % 3 (1 threshold, 2 after,
 * 0 hashlock); index 0 is the spend threshold leaf. */
static int mix_cycle(const secp256k1_context *c, uint32_t base, size_t idx,
                     unsigned char *leaf, size_t *len)
{
    unsigned char sk[32], pub[33], pre[32], h[32];
    sk_from_int(sk, base + (uint32_t)idx);
    if (!pub_from_sk(c, sk, pub))
        return 0;
    if (idx == 0 || idx % 3 == 1)
        return nutroot_leaf_build(NUTROOT_LEAF_THRESHOLD, 1, pub, 1, 0, NULL,
                                  leaf, len);
    if (idx % 3 == 2)
        return nutroot_leaf_build(NUTROOT_LEAF_AFTER, 1, pub, 1, PAST_TIME,
                                  NULL, leaf, len);
    memset(pre, (int)(idx % 256), 32);
    cashu_sha256(pre, 32, h);
    return nutroot_leaf_build(NUTROOT_LEAF_HASHLOCK, 1, pub, 1, 0, h,
                              leaf, len);
}

/* Build a 1-input case on an n_leaves tree, spending the threshold leaf at
 * spend_idx with key base+spend_idx. Reports the merkle path length. */
static int build_tree_case(const secp256k1_context *c, btx_t *b,
                           const char *tag, uint32_t base, size_t n_leaves,
                           size_t spend_idx, leaf_mix_fn mix,
                           size_t *path_len_out)
{
    btx_frame(b, 1, 1, tag);
    unsigned char *hashes = malloc(n_leaves * 32);
    unsigned char *spend_leaf = malloc(2 + NUTROOT_MAX_LEAF_BODY);
    unsigned char scratch[160];
    size_t spend_len = 0;
    int ok = hashes && spend_leaf;
    for (size_t i = 0; ok && i < n_leaves; i++) {
        size_t len = sizeof(scratch);
        ok = mix(c, base, i, scratch, &len);
        if (ok)
            ok = nutroot_leaf_hash(scratch, len, hashes + i * 32);
        if (ok && i == spend_idx) {
            memcpy(spend_leaf, scratch, len);
            spend_len = len;
        }
        if (i % 16 == 15)
            vTaskDelay(2);
    }
    unsigned char spend_hash[32], root[32], K_sk[32];
    unsigned char path[NUTROOT_MAX_TREE_DEPTH * 32];
    size_t path_len = 0;
    if (ok)
        ok = nutroot_leaf_hash(spend_leaf, spend_len, spend_hash) &&
             nutroot_merkle_path(hashes, n_leaves, spend_idx, path, &path_len) &&
             nutroot_root_from_path(spend_hash, path, path_len, root);
    pend_t *pd = &pend[0];
    if (ok) {
        sk_from_int(K_sk, base + 1000);
        ok = pub_from_sk(c, K_sk, pd->K33) &&
             nutroot_tweak_pubkey(c, pd->K33, root, b->secrets[0]);
    }
    if (ok) {
        pd->leaf = spend_leaf;
        pd->leaf_len = (uint16_t)spend_len;
        pd->path = malloc(path_len > 0 ? path_len * 32 : 1);
        ok = pd->path != NULL;
        if (ok) {
            memcpy(pd->path, path, path_len * 32);
            pd->path_len = (uint8_t)path_len;
            sk_from_int(pd->sk, base + (uint32_t)spend_idx);
            pd->keypath = 0;
        }
    }
    if (!ok)
        free(spend_leaf);
    free(hashes);
    if (ok)
        ok = finish_witnesses(c, b);
    if (path_len_out)
        *path_len_out = path_len;
    return ok;
}

/* Single-input threshold n-of-m case; signatures by the first n keys. */
static int build_threshold_case(const secp256k1_context *c, btx_t *b,
                                const char *tag, uint32_t base, int n, int m)
{
    btx_frame(b, 1, 1, tag);
    unsigned char keys[15 * 33], sk[32], root[32], K_sk[32];
    if (m > 15 || m < 1 || n < 1 || n > m)
        return 0;
    for (int i = 0; i < m; i++) {
        sk_from_int(sk, base + (uint32_t)i);
        if (!pub_from_sk(c, sk, keys + (size_t)i * 33))
            return 0;
    }
    unsigned char leaf[520];
    size_t leaf_len = sizeof(leaf);
    if (!nutroot_leaf_build(NUTROOT_LEAF_THRESHOLD, (uint8_t)n, keys,
                            (uint8_t)m, 0, NULL, leaf, &leaf_len))
        return 0;
    nutroot_leaf_hash(leaf, leaf_len, root);
    pend_t *pd = &pend[0];
    sk_from_int(K_sk, base + 50);
    if (!pub_from_sk(c, K_sk, pd->K33) ||
        !nutroot_tweak_pubkey(c, pd->K33, root, b->secrets[0]))
        return 0;
    unsigned char d[32];
    if (!nutroot_legacy_tx_digest(&b->tx, d))
        return 0;
    char sig_hex[15][129];
    for (int i = 0; i < n; i++) {
        sk_from_int(sk, base + (uint32_t)i);
        if (!sig_hex_for(c, sk, d, sig_hex[i]))
            return 0;
        if (i % 4 == 3)
            vTaskDelay(2);
    }
    b->wit[0] = wit_script_json(leaf, leaf_len, pd->K33, NULL, 0,
                                sig_hex, n, NULL, 0);
    if (!b->wit[0])
        return 0;
    b->ins[0].witness = b->wit[0];
    return 1;
}

/* --------------------------------------------------------------- cases */

static void bench_named_cases(const secp256k1_context *c, btx_t *b)
{
    ESP_LOGI(TAG, "--- named cases (labels mirror nutshell) ---");

    /* 1. keypath_bare */
    btx_frame(b, 1, 1, "keypath_bare");
    if (keypath_input(c, b, 0, 101) && finish_witnesses(c, b))
        bench_case_run(c, b, "keypath_bare", 5, 0, 0);

    /* 2. keypath_tweaked: a 3-leaf tree committed, spent via key path (the
     * verify side cannot tell — that is the point of the tweak). */
    {
        btx_frame(b, 1, 1, "keypath_tweaked");
        unsigned char hashes[3 * 32], scratch[160], root[32], K_sk[32], K[33];
        int ok = 1;
        size_t len;
        len = sizeof(scratch);
        ok &= mix_thresh_only(c, 200, 1, scratch, &len);
        ok &= nutroot_leaf_hash(scratch, len, hashes);
        len = sizeof(scratch);
        ok &= mix_cycle(c, 200, 2, scratch, &len); /* after leaf */
        ok &= nutroot_leaf_hash(scratch, len, hashes + 32);
        len = sizeof(scratch);
        ok &= mix_cycle(c, 200, 3, scratch, &len); /* hashlock leaf */
        ok &= nutroot_leaf_hash(scratch, len, hashes + 64);
        unsigned char sk[32];
        sk_from_int(sk, 200);
        ok &= nutroot_merkle_root(hashes, 3, root) && pub_from_sk(c, sk, K) &&
              nutroot_tweak_pubkey(c, K, root, b->secrets[0]);
        (void)K_sk;
        unsigned char d[32];
        ok = ok && nutroot_legacy_tx_digest(&b->tx, d) &&
             nutroot_tweak_seckey(c, sk, root) &&
             (b->wit[0] = wit_keypath_json(c, sk, d)) != NULL;
        if (ok) {
            b->ins[0].witness = b->wit[0];
            bench_case_run(c, b, "keypath_tweaked", 5, 0, 0);
        } else {
            ESP_LOGE(TAG, "keypath_tweaked setup failed");
        }
    }

    /* 3. script_threshold_1of1 */
    btx_frame(b, 1, 1, "script_threshold_1of1");
    if (script_input_1of1(c, b, 0, 301) && finish_witnesses(c, b))
        bench_case_run(c, b, "script_threshold_1of1", 5, 0, 0);

    /* 4. script_threshold_2of3, signed by keys 0 and 2 as in nutshell. */
    {
        btx_frame(b, 1, 1, "script_threshold_2of3");
        unsigned char keys[3 * 33], sk[32], root[32], K[33], K_sk[32];
        int ok = 1;
        for (int i = 0; i < 3; i++) {
            sk_from_int(sk, 401 + (uint32_t)i);
            ok &= pub_from_sk(c, sk, keys + (size_t)i * 33);
        }
        unsigned char leaf[160];
        size_t leaf_len = sizeof(leaf);
        ok &= nutroot_leaf_build(NUTROOT_LEAF_THRESHOLD, 2, keys, 3, 0, NULL,
                                 leaf, &leaf_len);
        sk_from_int(K_sk, 400);
        ok &= nutroot_leaf_hash(leaf, leaf_len, root) &&
              pub_from_sk(c, K_sk, K) &&
              nutroot_tweak_pubkey(c, K, root, b->secrets[0]);
        unsigned char d[32];
        static char sigs[2][129];
        ok = ok && nutroot_legacy_tx_digest(&b->tx, d);
        if (ok) {
            sk_from_int(sk, 401);
            ok &= sig_hex_for(c, sk, d, sigs[0]);
            sk_from_int(sk, 403);
            ok &= sig_hex_for(c, sk, d, sigs[1]);
        }
        if (ok &&
            (b->wit[0] = wit_script_json(leaf, leaf_len, K, NULL, 0, sigs, 2,
                                         NULL, 0)) != NULL) {
            b->ins[0].witness = b->wit[0];
            bench_case_run(c, b, "script_threshold_2of3", 3, 0, 0);
        } else {
            ESP_LOGE(TAG, "script_threshold_2of3 setup failed");
        }
    }

    /* 5. script_after_refund: locktime in the past. */
    {
        btx_frame(b, 1, 1, "script_after_refund");
        unsigned char sk[32], pub[33], root[32], K[33], K_sk[32];
        unsigned char leaf[160];
        size_t leaf_len = sizeof(leaf);
        sk_from_int(sk, 501);
        int ok = pub_from_sk(c, sk, pub) &&
                 nutroot_leaf_build(NUTROOT_LEAF_AFTER, 1, pub, 1, PAST_TIME,
                                    NULL, leaf, &leaf_len);
        sk_from_int(K_sk, 500);
        ok = ok && nutroot_leaf_hash(leaf, leaf_len, root) &&
             pub_from_sk(c, K_sk, K) &&
             nutroot_tweak_pubkey(c, K, root, b->secrets[0]);
        unsigned char d[32];
        static char sigs1[1][129];
        ok = ok && nutroot_legacy_tx_digest(&b->tx, d) &&
             sig_hex_for(c, sk, d, sigs1[0]) &&
             (b->wit[0] = wit_script_json(leaf, leaf_len, K, NULL, 0, sigs1, 1,
                                          NULL, 0)) != NULL;
        if (ok) {
            b->ins[0].witness = b->wit[0];
            bench_case_run(c, b, "script_after_refund", 5, 0, 0);
        } else {
            ESP_LOGE(TAG, "script_after_refund setup failed");
        }
    }

    /* 6. script_hashlock: preimage + one signature. */
    {
        btx_frame(b, 1, 1, "script_hashlock");
        unsigned char sk[32], pub[33], root[32], K[33], K_sk[32];
        unsigned char pre[32], h[32], leaf[160];
        size_t leaf_len = sizeof(leaf);
        memset(pre, 0x07, 32);
        cashu_sha256(pre, 32, h);
        sk_from_int(sk, 601);
        int ok = pub_from_sk(c, sk, pub) &&
                 nutroot_leaf_build(NUTROOT_LEAF_HASHLOCK, 1, pub, 1, 0, h,
                                    leaf, &leaf_len);
        sk_from_int(K_sk, 600);
        ok = ok && nutroot_leaf_hash(leaf, leaf_len, root) &&
             pub_from_sk(c, K_sk, K) &&
             nutroot_tweak_pubkey(c, K, root, b->secrets[0]);
        unsigned char d[32];
        static char sigs1[1][129];
        ok = ok && nutroot_legacy_tx_digest(&b->tx, d) &&
             sig_hex_for(c, sk, d, sigs1[0]) &&
             (b->wit[0] = wit_script_json(leaf, leaf_len, K, NULL, 0, sigs1, 1,
                                          pre, 32)) != NULL;
        if (ok) {
            b->ins[0].witness = b->wit[0];
            bench_case_run(c, b, "script_hashlock", 5, 0, 0);
        } else {
            ESP_LOGE(TAG, "script_hashlock setup failed");
        }
    }

    /* 7-8. Multileaf trees: 8 mixed leaves (spend index 3), 64 leaves
     * (spend index 17). */
    {
        size_t plen = 0;
        if (build_tree_case(c, b, "script_multileaf_8", 700, 8, 3,
                            mix_nutshell8, &plen))
            bench_case_run(c, b, "script_multileaf_8", 5, 0, 0);
        else
            ESP_LOGE(TAG, "script_multileaf_8 setup failed");
        /* 64-leaf trees were historical fixtures; the current cap is eight. */
    }

    /* 9. script_p2bk_blinded: a NUT-28 slot-blinded leaf key is an ordinary
     * pubkey by the time the mint sees it, so verification is identical to
     * a 1-of-1 — constructed here without NUT-28 code. */
    btx_frame(b, 1, 1, "script_p2bk_blinded");
    if (script_input_1of1(c, b, 0, 1001) && finish_witnesses(c, b))
        bench_case_run(c, b, "script_p2bk_blinded", 5, 0, 0);

    /* 10-11. Four-input transactions. */
    {
        btx_frame(b, 4, 4, "multi_input_4_keypath");
        int ok = 1;
        for (size_t i = 0; i < 4; i++)
            ok &= keypath_input(c, b, i, 1100 + (uint32_t)i);
        if (ok && finish_witnesses(c, b))
            bench_case_run(c, b, "multi_input_4_keypath", 3, 0, 4);
        else
            ESP_LOGE(TAG, "multi_input_4_keypath setup failed");

        btx_frame(b, 4, 4, "multi_input_4_script");
        ok = 1;
        for (size_t i = 0; i < 4; i++)
            ok &= script_input_1of1(c, b, i, 1201 + (uint32_t)i * 10);
        if (ok && finish_witnesses(c, b))
            bench_case_run(c, b, "multi_input_4_script", 3, 0, 4);
        else
            ESP_LOGE(TAG, "multi_input_4_script setup failed");
    }
}

/* ---------------------------------------------------------------- sweeps */

static void bench_sweeps(const secp256k1_context *c, btx_t *b, int full)
{
    static const size_t IN_SIZES[] = {1, 2, 4, 8, 16, 32, 64};
    static const size_t LEAF_SIZES[] = {1, 2, 4, 8};
    static const int TH_NM[][2] = {{1, 1}, {2, 3}, {3, 5}, {5, 8}, {8, 15}};
    char label[48];

    ESP_LOGI(TAG, "--- inputs sweep (N inputs + N outputs per call) ---");
    for (size_t s = 0; s < sizeof(IN_SIZES) / sizeof(IN_SIZES[0]); s++) {
        size_t n = IN_SIZES[s];
        int is_default = (n == 1 || n == 4 || n == 16);
        if (!full && !is_default)
            continue;
        /* The 64-input script case holds ~23 KB of witness JSON at once. */
        if (n == 64 &&
            heap_caps_get_largest_free_block(MALLOC_CAP_8BIT) < 28 * 1024) {
            ESP_LOGW(TAG, "inputs N=64 skipped: heap too fragmented");
            continue;
        }
        int iters = n >= 16 ? 2 : 3;
        int hook = n >= 32; /* keep single calls from starving the idle WDT */

        btx_frame(b, n, n, "inputs_keypath");
        int ok = 1;
        for (size_t i = 0; i < n; i++)
            ok &= keypath_input(c, b, i, 20000 + (uint32_t)i);
        if (ok && finish_witnesses(c, b)) {
            snprintf(label, sizeof(label), "inputs_keypath N=%u", (unsigned)n);
            bench_case_run(c, b, label, iters, hook && n >= 64, n);
        }

        btx_frame(b, n, n, "inputs_script");
        ok = 1;
        for (size_t i = 0; i < n; i++)
            ok &= script_input_1of1(c, b, i, 21000 + (uint32_t)i * 2);
        if (ok && finish_witnesses(c, b)) {
            snprintf(label, sizeof(label), "inputs_script N=%u", (unsigned)n);
            bench_case_run(c, b, label, iters, hook, n);
        }
    }

    ESP_LOGI(TAG, "--- leaves sweep (1 script input, L-leaf tree) ---");
    for (size_t s = 0; s < sizeof(LEAF_SIZES) / sizeof(LEAF_SIZES[0]); s++) {
        size_t l = LEAF_SIZES[s];
        int is_default = (l == 1 || l == 8 || l == 64);
        if (!full && !is_default)
            continue;
        size_t plen = 0;
        if (build_tree_case(c, b, "leaves", 30000 + (uint32_t)s * 2000, l, 0,
                            mix_cycle, &plen)) {
            snprintf(label, sizeof(label), "leaves L=%u path=%u",
                     (unsigned)l, (unsigned)plen);
            bench_case_run(c, b, label, 3, 0, 0);
        } else {
            ESP_LOGE(TAG, "leaves L=%u setup failed", (unsigned)l);
        }
    }

    ESP_LOGI(TAG, "--- threshold n-of-m sweep (single-leaf tree) ---");
    for (size_t s = 0; s < sizeof(TH_NM) / sizeof(TH_NM[0]); s++) {
        int n = TH_NM[s][0], m = TH_NM[s][1];
        int is_default = (n <= 3);
        if (!full && !is_default)
            continue;
        if (build_threshold_case(c, b, "thresh", 50000 + (uint32_t)s * 100,
                                 n, m)) {
            nutroot_stat_sig_verifies = 0;
            nutroot_stat_batch_verifies = 0;
            if (!bench_sanity(c, b, "threshold"))
                continue;
            unsigned long verifies = nutroot_stat_sig_verifies;
            snprintf(label, sizeof(label), "thresh %d-of-%d sv=%lu", n, m,
                     verifies);
            int hook = n >= 5;
            if (hook)
                nutroot_set_yield_hook(bench_yield);
            int64_t mean;
            NBENCH(mean, label, n >= 5 ? 2 : 3, 0,
                   { nutroot_legacy_verify_transaction(c, &b->tx, NOW_TS); });
            (void)mean;
            nutroot_set_yield_hook(NULL);
        } else {
            ESP_LOGE(TAG, "threshold %d-of-%d setup failed", n, m);
        }
    }
}

/* --------------------------------------------------------------------------
 * Receive benchmark: the wallet's 10-proof v3 receive crypto with realistic
 * point secrets. Mirrors bench_suite_swap's setup (crypto_bls_test.c) —
 * mint keys K_i = (2+i)*g2 from the host-precomputed table, valid
 * signatures via the small-scalar trick — but the secrets are 33-byte
 * nutroot points and the nutroot phases (spend-info reconstruction and
 * witness signing) are timed alongside the BLS suite ops.
 * ------------------------------------------------------------------------ */

static const unsigned char BLS_DST[] = "CASHU_BLS12_381_G1_XMD:SHA-256_SSWU_RO_";

static void bls_small_scalar(blst_scalar *s, unsigned char n)
{
    unsigned char be[32] = {0};
    be[31] = n;
    blst_scalar_from_be_bytes(s, be, 32);
}

static void bls_hash_to_g1(blst_p1 *out, const unsigned char *msg, size_t len)
{
    blst_hash_to_g1(out, msg, len, BLS_DST, sizeof(BLS_DST) - 1, NULL, 0);
}

static void bls_p1_mul(blst_p1 *out, const blst_p1 *p, const blst_scalar *s)
{
    unsigned char le[32];
    blst_lendian_from_scalar(le, s);
    blst_p1_mult(out, p, le, 256);
}

static void bench_recv_v3(const secp256k1_context *c)
{
    enum { N = 10 };
    static unsigned char Ks[N * 96], Cin[N * 48], Cblind[N * 48], Cout[N * 48];
    static unsigned char Bs[N * 48];
    static unsigned char secrets[N][33], out_secrets[N][33];
    static unsigned char leaves[N][64];
    static size_t leaf_lens[N];
    static unsigned char K33s[N][33], internal_sks[N][32];
    const unsigned char *in_ptrs[N], *out_ptrs[N];
    size_t lens33[N];
    unsigned char r_be[32] = {0};
    r_be[31] = 3;

    ESP_LOGI(TAG, "--- 10-proof v3 receive (point secrets, distinct keys) ---");

    /* Wallet-side setup: each incoming proof is receiver-keyed — internal
     * key ours, one 1-of-1 refund leaf — so spend-info reconstruction below
     * does real work. Output secrets are fresh bare wallet keys. */
    int ok = 1;
    for (int i = 0; i < N; i++) {
        unsigned char leaf_sk[32], pub[33], root[32];
        sk_from_int(leaf_sk, 3000 + (uint32_t)i);
        ok &= pub_from_sk(c, leaf_sk, pub);
        size_t llen = sizeof(leaves[i]);
        ok &= nutroot_leaf_build(NUTROOT_LEAF_THRESHOLD, 1, pub, 1, 0, NULL,
                                 leaves[i], &llen);
        leaf_lens[i] = llen;
        sk_from_int(internal_sks[i], 3100 + (uint32_t)i);
        ok &= pub_from_sk(c, internal_sks[i], K33s[i]);
        ok &= nutroot_leaf_hash(leaves[i], llen, root) &&
              nutroot_tweak_pubkey(c, K33s[i], root, secrets[i]);
        unsigned char out_sk[32];
        sk_from_int(out_sk, 3200 + (uint32_t)i);
        ok &= pub_from_sk(c, out_sk, out_secrets[i]);
        in_ptrs[i] = secrets[i];
        out_ptrs[i] = out_secrets[i];
        lens33[i] = 33;
    }
    if (!ok) {
        ESP_LOGE(TAG, "receive bench secp setup failed");
        return;
    }

    /* Mint-side setup (untimed): C_i = (2+i)*Y_i, blinded C__i = (2+i)*B_i
     * with r = 3 — G1 only, inside one hold window. */
    blst_hw_acquire();
    for (int i = 0; i < N; i++) {
        hex_to_bytes(crypto_bls_bench_key_hex(i), Ks + i * 96, 96);
        blst_scalar a, r;
        bls_small_scalar(&a, (unsigned char)(2 + i));
        bls_small_scalar(&r, 3);
        blst_p1 y, cpt, yo, bpt, cb;
        bls_hash_to_g1(&y, secrets[i], 33);
        bls_p1_mul(&cpt, &y, &a);
        blst_p1_compress(Cin + i * 48, &cpt);
        bls_hash_to_g1(&yo, out_secrets[i], 33);
        bls_p1_mul(&bpt, &yo, &r);
        blst_p1_compress(Bs + i * 48, &bpt);
        bls_p1_mul(&cb, &bpt, &a);
        blst_p1_compress(Cblind + i * 48, &cb);
        vTaskDelay(2);
    }
    blst_hw_release();

    const cashu_suite_t *s = &cashu_suite_bls;
    int64_t m_verify_in, m_spendinfo, m_sign, m_blind, m_unblind, m_verify_out;

    /* Phase 1: intrinsic BLS verification of the incoming proofs. */
    NBENCH(m_verify_in, "recv verify n=10", 2, 0, {
        if (!s->verify_proofs(NULL, N, Ks, Cin, in_ptrs, lens33))
            ESP_LOGE(TAG, "recv verify n=10 FAILED");
    });

    /* Phase 2: spend-info reconstruction — parse the disclosed leaf,
     * rebuild the root, tweak the internal key, compare to the secret. */
    NBENCH(m_spendinfo, "recv spendinfo n=10", 3, 0, {
        for (int i = 0; i < N; i++) {
            nutroot_leaf_t pl;
            unsigned char root[32], P[33];
            if (!nutroot_leaf_parse(c, leaves[i], leaf_lens[i], &pl) ||
                !nutroot_leaf_hash(leaves[i], leaf_lens[i], root) ||
                !nutroot_tweak_pubkey(c, K33s[i], root, P) ||
                memcmp(P, secrets[i], 33) != 0)
                ESP_LOGE(TAG, "recv spendinfo %d FAILED", i);
        }
    });

    /* Phase 3: swap witness signing — one transcript, per-input tweaked
     * key derivation + BIP-340 signature + witness JSON, as the wallet
     * does at spend time. */
    NBENCH(m_sign, "swap sign n=10", 3, 0, {
        nutroot_input_t ins[N];
        nutroot_output_t outs[N];
        unsigned char root[32], d[32], sk[32], sig[64];
        for (int i = 0; i < N; i++) {
            memset(&ins[i], 0, sizeof(ins[i]));
            ins[i].amount = 8;
            ins[i].keyset_id = BENCH_KID; ins[i].keyset_id_len = 8;
            ins[i].secret = secrets[i]; ins[i].secret_len = 33;
            ins[i].C = Cin + i * 48; ins[i].C_len = 48;
            memset(&outs[i], 0, sizeof(outs[i]));
            outs[i].amount = 8;
            outs[i].keyset_id = BENCH_KID; outs[i].keyset_id_len = 8;
            outs[i].B_ = Bs + i * 48; outs[i].B_len = 48;
        }
        nutroot_tx_t tx = {0};
        tx.proof_inputs = ins; tx.n_proof_inputs = N;
        tx.blinded_outputs = outs; tx.n_blinded_outputs = N;
        if (!nutroot_legacy_tx_digest(&tx, d))
            ESP_LOGE(TAG, "swap sign digest FAILED");
        for (int i = 0; i < N; i++) {
            memcpy(sk, internal_sks[i], 32);
            nutroot_leaf_hash(leaves[i], leaf_lens[i], root);
            if (!nutroot_tweak_seckey(c, sk, root) ||
                !nutroot_sign_digest(c, sk, d, sig))
                ESP_LOGE(TAG, "swap sign %d FAILED", i);
            char sig_hex[129], w[160];
            bytes_to_hex(sig, sizeof(sig), sig_hex);
            snprintf(w, sizeof(w), "{\"signatures\":[\"%s\"]}", sig_hex);
        }
    });

    /* Phases 4-6: the existing suite swap ops with 33-byte point secrets. */
    NBENCH(m_blind, "swap blind n=10", 3, 0, {
        unsigned char B[48];
        for (int i = 0; i < N; i++) {
            size_t bl = sizeof(B);
            s->blind(NULL, out_secrets[i], 33, r_be, 32, B, &bl);
        }
    });
    NBENCH(m_unblind, "swap unblind n=10", 3, 0, {
        for (int i = 0; i < N; i++) {
            size_t cl = 48;
            s->unblind(NULL, Cblind + i * 48, 48, r_be, 32, Ks + i * 96, 96,
                       Cout + i * 48, &cl);
        }
    });
    NBENCH(m_verify_out, "recv verify out n=10", 2, 0, {
        if (!s->verify_proofs(NULL, N, Ks, Cout, out_ptrs, lens33))
            ESP_LOGE(TAG, "recv verify out n=10 FAILED");
    });

    int64_t tap = m_verify_in + m_spendinfo;
    int64_t later = m_sign + m_blind + m_unblind + m_verify_out;
    ESP_LOGI(TAG, "variant A (verify at tap, swap later): tap %lld us + later %lld us = %lld us",
             tap, later, tap + later);
    ESP_LOGI(TAG, "variant B (immediate swap+verify):     total %lld us",
             tap + later);
    ESP_LOGI(TAG, "nutroot overhead vs plain v3 swap (spendinfo+sign): %lld us",
             m_spendinfo + m_sign);
}

void nutroot_run_benchmark(const secp256k1_context *ctx, int full)
{
    btx_t *b = calloc(1, sizeof(btx_t));
    if (!b) {
        ESP_LOGE(TAG, "benchmark: no heap for case buffer (%u bytes)",
                 (unsigned)sizeof(btx_t));
        return;
    }
    ESP_LOGI(TAG, "nutroot witness verification benchmark%s "
                  "(timed unit = one verify call, as nutshell's)",
             full ? " [full]" : "");
    if (full >= 2) {
        unsigned char sk[32], d[32], sig[64], shared[32], serialized[33];
        for (size_t i = 0; i < 32; i++) { sk[i] = (unsigned char)(17+i*7); d[i] = (unsigned char)(123-i*3); }
        secp256k1_keypair kp;
        secp256k1_pubkey pk;
        secp256k1_xonly_pubkey xonly;
        int ok = secp256k1_keypair_create(ctx, &kp, sk) &&
                 secp256k1_keypair_pub(ctx, &pk, &kp) &&
                 secp256k1_keypair_xonly_pub(ctx, &xonly, NULL, &kp) &&
                 nutroot_sign_digest(ctx, sk, d, sig);
        if (!ok) { ESP_LOGE(TAG, "quick setup FAILED"); free(b); return; }
        int64_t mean;
        NBENCH(mean, "keypair full scalar", 10, 0, { ok &= secp256k1_keypair_create(ctx, &kp, sk); });
        NBENCH(mean, "sign incl keypair", 10, 0, { ok &= nutroot_sign_digest(ctx, sk, d, sig); });
        unsigned char aux[32] = {0};
        NBENCH(mean, "sign retained keypair", 10, 0, { ok &= secp256k1_schnorrsig_sign32(ctx, sig, d, &kp, aux); });
        NBENCH(mean, "schnorr verify", 10, 0, { ok &= secp256k1_schnorrsig_verify(ctx, sig, d, 32, &xonly); });
        NBENCH(mean, "ECDH full scalar", 10, 0, { ok &= secp256k1_ecdh(ctx, shared, &pk, sk, NULL, NULL); });
        size_t length = sizeof(serialized);
        ok &= secp256k1_ec_pubkey_serialize(ctx, serialized, &length, &pk, SECP256K1_EC_COMPRESSED);
        NBENCH(mean, "parse compressed key", 10, 0, { ok &= secp256k1_ec_pubkey_parse(ctx, &pk, serialized, length); });
        static const int sizes[][2] = {{2,3},{3,5},{8,15},{15,15}};
        for (size_t i = 0; i < sizeof(sizes)/sizeof(sizes[0]); i++) {
            int n = sizes[i][0], m = sizes[i][1];
            ok &= build_threshold_case(ctx, b, "thresh", 50000+(uint32_t)i*100, n, m);
            nutroot_stat_sig_verifies = 0;
            nutroot_stat_batch_verifies = 0;
            ok &= bench_sanity(ctx, b, "quick threshold");
            if(!ok){btx_reset(b);free(b);return;}
            char label[48];
            snprintf(label, sizeof(label), "threshold %d/%d c=%lu b=%lu", n, m, nutroot_stat_sig_verifies, nutroot_stat_batch_verifies);
            nutroot_set_yield_hook(bench_yield);
            NBENCH(mean, label, 3, 0, { ok &= nutroot_legacy_verify_transaction(ctx, &b->tx, NOW_TS); });
            nutroot_set_yield_hook(NULL);
        }
        if(full==3) {
            static const size_t counts[]={16,32,64};
            for(size_t j=0;j<sizeof(counts)/sizeof(counts[0]);j++) {
                size_t n=counts[j];btx_frame(b,n,n,"large_keypath");
                for(size_t i=0;i<n;i++)ok&=keypath_input(ctx,b,i,20000+(uint32_t)i);
                ok&=finish_witnesses(ctx,b);
                nutroot_stat_sig_verifies=nutroot_stat_batch_verifies=0;
                ok&=bench_sanity(ctx,b,"large keypath");
                if(!ok){btx_reset(b);free(b);return;}
                char label[64];snprintf(label,sizeof(label),"keypaths %u c=%lu b=%lu",(unsigned)n,nutroot_stat_sig_verifies,nutroot_stat_batch_verifies);
                nutroot_set_yield_hook(bench_yield);
                NBENCH(mean,label,3,0,{ok&=nutroot_legacy_verify_transaction(ctx,&b->tx,NOW_TS);});
                nutroot_set_yield_hook(NULL);
            }
        }
        (void)mean;
        ESP_LOGI(TAG, "quick correctness: %s, options=%u", ok ? "OK" : "FAILED", nutroot_optimizations());
    } else {
        bench_named_cases(ctx, b);
        bench_sweeps(ctx, b, full);
    }
    btx_reset(b);
    free(b);
    if (full < 2) bench_recv_v3(ctx);
}
