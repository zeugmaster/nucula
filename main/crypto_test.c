#include "crypto_test.h"
#include "crypto.h"
#include "bip39.h"
#include "hex.h"
#include <stdio.h>
#include <string.h>
#include <esp_log.h>
#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#define TAG "crypto_test"

static int test_hash_to_curve(const secp256k1_context *ctx)
{
    static const struct {
        const char *msg_hex;
        const char *expected_hex;
    } vectors[] = {
        {
            "0000000000000000000000000000000000000000000000000000000000000000",
            "024cce997d3b518f739663b757deaec95bcd9473c30a14ac2fd04023a739d1a725"
        },
        {
            "0000000000000000000000000000000000000000000000000000000000000001",
            "022e7158e11c9506f1aa4248bf531298daa7febd6194f003edcd9b93ade6253acf"
        },
        {
            "0000000000000000000000000000000000000000000000000000000000000002",
            "026cdbe15362df59cd1dd3c9c11de8aedac2106eca69236ecd9fbe117af897be4f"
        },
    };

    for (int i = 0; i < 3; i++) {
        unsigned char msg[32];
        hex_to_bytes(vectors[i].msg_hex, msg, 32);

        unsigned char expected[33];
        hex_to_bytes(vectors[i].expected_hex, expected, 33);

        secp256k1_pubkey point;
        if (!cashu_hash_to_curve(ctx, &point, msg, 32)) {
            ESP_LOGE(TAG, "hash_to_curve %d: failed", i + 1);
            return 0;
        }

        unsigned char result[33];
        cashu_pubkey_serialize(ctx, result, &point);

        if (memcmp(result, expected, 33) != 0) {
            char got[67];
            bytes_to_hex(result, 33, got);
            ESP_LOGE(TAG, "hash_to_curve %d: mismatch\n  got:    %s\n  expect: %s",
                     i + 1, got, vectors[i].expected_hex);
            return 0;
        }
        ESP_LOGI(TAG, "hash_to_curve %d: OK", i + 1);
    }
    return 1;
}

static int test_blind_message(const secp256k1_context *ctx)
{
    static const struct {
        const char *x_hex;
        const char *r_hex;
        const char *B_hex;
    } vectors[] = {
        {
            "d341ee4871f1f889041e63cf0d3823c713eea6aff01e80f1719f08f9e5be98f6",
            "99fce58439fc37412ab3468b73db0569322588f62fb3a49182d67e23d877824a",
            "033b1a9737a40cc3fd9b6af4b723632b76a67a36782596304612a6c2bfb5197e6d"
        },
        {
            "f1aaf16c2239746f369572c0784d9dd3d032d952c2d992175873fb58fae31a60",
            "f78476ea7cc9ade20f9e05e58a804cf19533f03ea805ece5fee88c8e2874ba50",
            "029bdf2d716ee366eddf599ba252786c1033f47e230248a4612a5670ab931f1763"
        },
    };

    for (int i = 0; i < 2; i++) {
        unsigned char x[32];
        hex_to_bytes(vectors[i].x_hex, x, 32);

        unsigned char r[32];
        hex_to_bytes(vectors[i].r_hex, r, 32);

        unsigned char expected[33];
        hex_to_bytes(vectors[i].B_hex, expected, 33);

        secp256k1_pubkey B_;
        if (!cashu_blind_message(ctx, &B_, x, 32, r)) {
            ESP_LOGE(TAG, "blind_message %d: failed", i + 1);
            return 0;
        }

        unsigned char result[33];
        cashu_pubkey_serialize(ctx, result, &B_);

        if (memcmp(result, expected, 33) != 0) {
            char got[67];
            bytes_to_hex(result, 33, got);
            ESP_LOGE(TAG, "blind_message %d: mismatch\n  got:    %s\n  expect: %s",
                     i + 1, got, vectors[i].B_hex);
            return 0;
        }
        ESP_LOGI(TAG, "blind_message %d: OK", i + 1);
    }
    return 1;
}

static int test_unblind(const secp256k1_context *ctx)
{
    unsigned char k_bytes[32] = {0};
    k_bytes[31] = 1;

    secp256k1_pubkey K;
    if (!secp256k1_ec_pubkey_create(ctx, &K, k_bytes)) {
        ESP_LOGE(TAG, "unblind: pubkey create failed");
        return 0;
    }

    unsigned char C_bytes[33];
    hex_to_bytes("02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2",
                 C_bytes, 33);
    secp256k1_pubkey C_;
    cashu_pubkey_parse(ctx, &C_, C_bytes);

    unsigned char r[32] = {0};
    r[31] = 1;

    secp256k1_pubkey C;
    if (!cashu_unblind(ctx, &C, &C_, r, &K)) {
        ESP_LOGE(TAG, "unblind: failed");
        return 0;
    }

    secp256k1_pubkey G;
    unsigned char one[32] = {0};
    one[31] = 1;
    if (!secp256k1_ec_pubkey_create(ctx, &G, one)) {
        ESP_LOGE(TAG, "unblind: G create failed");
        return 0;
    }

    secp256k1_pubkey check;
    const secp256k1_pubkey *pts[2] = {&C, &G};
    if (!secp256k1_ec_pubkey_combine(ctx, &check, pts, 2)) {
        ESP_LOGE(TAG, "unblind: combine failed");
        return 0;
    }

    unsigned char check_ser[33];
    cashu_pubkey_serialize(ctx, check_ser, &check);

    if (memcmp(check_ser, C_bytes, 33) != 0) {
        ESP_LOGE(TAG, "unblind: verification failed (C + G != C_)");
        return 0;
    }

    ESP_LOGI(TAG, "unblind: OK");
    return 1;
}

static int test_dleq(const secp256k1_context *ctx)
{
    unsigned char A_bytes[33], B_bytes[33], C_bytes[33];
    hex_to_bytes("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                 A_bytes, 33);
    hex_to_bytes("02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2",
                 B_bytes, 33);
    hex_to_bytes("02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2",
                 C_bytes, 33);

    secp256k1_pubkey A, B_, C_;
    cashu_pubkey_parse(ctx, &A, A_bytes);
    cashu_pubkey_parse(ctx, &B_, B_bytes);
    cashu_pubkey_parse(ctx, &C_, C_bytes);

    unsigned char e[32], s[32];
    hex_to_bytes("9818e061ee51d5c8edc3342369a554998ff7b4381c8652d724cdf46429be73d9", e, 32);
    hex_to_bytes("9818e061ee51d5c8edc3342369a554998ff7b4381c8652d724cdf46429be73da", s, 32);

    int ok = cashu_verify_dleq(ctx, &A, &B_, &C_, e, s);
    if (!ok) {
        ESP_LOGE(TAG, "DLEQ BlindSignature: verification failed");
        return 0;
    }
    ESP_LOGI(TAG, "DLEQ BlindSignature: OK");

    /* NUT-12 test: DLEQ on Proof (Carol's verification) */
    unsigned char C_proof_bytes[33];
    hex_to_bytes("024369d2d22a80ecf78f3937da9d5f30c1b9f74f0c32684d583cca0fa6a61cdcfc",
                 C_proof_bytes, 33);
    secp256k1_pubkey C_proof;
    cashu_pubkey_parse(ctx, &C_proof, C_proof_bytes);

    unsigned char e2[32], s2[32], r2[32];
    hex_to_bytes("b31e58ac6527f34975ffab13e70a48b6d2b0d35abc4b03f0151f09ee1a9763d4", e2, 32);
    hex_to_bytes("8fbae004c59e754d71df67e392b6ae4e29293113ddc2ec86592a0431d16306d8", s2, 32);
    hex_to_bytes("a6d13fcd7a18442e6076f5e1e7c887ad5de40a019824bdfa9fe740d302e8d861", r2, 32);

    const char *secret = "daf4dd00a2b68a0858a80450f52c8a7d2ccf87d375e43e216e0c571f089f63e9";

    ok = cashu_verify_dleq_unblinded(ctx, &A, &C_proof,
                                     (const unsigned char *)secret, strlen(secret),
                                     e2, s2, r2);
    if (!ok) {
        ESP_LOGE(TAG, "DLEQ Proof: verification failed");
        return 0;
    }
    ESP_LOGI(TAG, "DLEQ Proof: OK");
    return 1;
}

static int test_nut13_v2(void)
{
    /* NUT-13 V2 test vectors (HMAC-SHA256 derivation) */
    static const char *mnemonic =
        "half depart obvious quality work element tank gorilla view sugar picture humble";
    static const char *keyset_id =
        "015ba18a8adcd02e715a58358eb618da4a4b3791151a4bee5e968bb88406ccf76a";

    static const char *expected_secrets[5] = {
        "db5561a07a6e6490f8dadeef5be4e92f7cebaecf2f245356b5b2a4ec40687298",
        "b70e7b10683da3bf1cdf0411206f8180c463faa16014663f39f2529b2fda922e",
        "78a7ac32ccecc6b83311c6081b89d84bb4128f5a0d0c5e1af081f301c7a513f5",
        "094a2b6c63bfa7970bc09cda0e1cfc9cd3d7c619b8e98fabcfc60aea9e4963e5",
        "5e89fc5d30d0bf307ddf0a3ac34aa7a8ee3702169dafa3d3fe1d0cae70ecd5ef"
    };
    static const char *expected_rs[5] = {
        "6d26181a3695e32e9f88b80f039ba1ae2ab5a200ad4ce9dbc72c6d3769f2b035",
        "bde4354cee75545bea1a2eee035a34f2d524cee2bb01613823636e998386952e",
        "f40cc1218f085b395c8e1e5aaa25dccc851be3c6c7526a0f4e57108f12d6dac4",
        "099ed70fc2f7ac769bc20b2a75cb662e80779827b7cc358981318643030577d0",
        "5550337312d223ba62e3f75cfe2ab70477b046d98e3e71804eade3956c7b98cf"
    };

    /* Derive seed from mnemonic via BIP39 */
    unsigned char seed[64];
    if (!bip39_to_seed(mnemonic, seed)) {
        ESP_LOGE(TAG, "NUT-13 V2: bip39_to_seed failed");
        return 0;
    }

    for (int i = 0; i < 5; i++) {
        unsigned char secret[32], r[32];
        char secret_hex[65], r_hex[65];

        if (!cashu_derive_secret(seed, 64, keyset_id, (uint32_t)i, secret)) {
            ESP_LOGE(TAG, "NUT-13 V2: derive_secret failed at counter %d", i);
            return 0;
        }
        if (!cashu_derive_r(seed, 64, keyset_id, (uint32_t)i, r)) {
            ESP_LOGE(TAG, "NUT-13 V2: derive_r failed at counter %d", i);
            return 0;
        }

        bytes_to_hex(secret, 32, secret_hex);
        bytes_to_hex(r, 32, r_hex);

        if (strcmp(secret_hex, expected_secrets[i]) != 0) {
            ESP_LOGE(TAG, "NUT-13 V2 secret[%d]: MISMATCH\n  got:    %s\n  expect: %s",
                     i, secret_hex, expected_secrets[i]);
            return 0;
        }
        if (strcmp(r_hex, expected_rs[i]) != 0) {
            ESP_LOGE(TAG, "NUT-13 V2 r[%d]: MISMATCH\n  got:    %s\n  expect: %s",
                     i, r_hex, expected_rs[i]);
            return 0;
        }
        ESP_LOGI(TAG, "NUT-13 V2 counter=%d: OK", i);
    }

    /* Also verify bip39_validate works on this mnemonic */
    if (!bip39_validate(mnemonic)) {
        ESP_LOGE(TAG, "NUT-13 V2: bip39_validate failed on test mnemonic");
        return 0;
    }
    ESP_LOGI(TAG, "NUT-13 V2: all test vectors passed");
    return 1;
}

int crypto_run_tests(const secp256k1_context *ctx)
{
    ESP_LOGI(TAG, "running crypto test vectors");

    int pass = 1;
    pass &= test_hash_to_curve(ctx);
    pass &= test_blind_message(ctx);
    pass &= test_unblind(ctx);
    pass &= test_dleq(ctx);
    pass &= test_nut13_v2();

    if (pass)
        ESP_LOGI(TAG, "all crypto tests passed");
    else
        ESP_LOGE(TAG, "some crypto tests FAILED");

    return pass;
}

void crypto_run_benchmark(const secp256k1_context *ctx)
{
    #define BENCH_N 1000

    ESP_LOGI(TAG, "benchmarking %d blind messages...", BENCH_N);

    unsigned char secret[32] = {0};
    unsigned char r[32] = {0};
    r[31] = 1;
    secp256k1_pubkey B_;

    int64_t start = esp_timer_get_time();

    for (int i = 0; i < BENCH_N; i++) {
        secret[0] = (unsigned char)(i & 0xff);
        secret[1] = (unsigned char)((i >> 8) & 0xff);
        r[0] = (unsigned char)((i + 77) & 0xff);
        r[1] = (unsigned char)(((i + 77) >> 8) & 0xff);

        if (!cashu_blind_message(ctx, &B_, secret, 32, r)) {
            ESP_LOGE(TAG, "benchmark: blind_message failed at i=%d", i);
            return;
        }

        if (i % 100 == 99)
            vTaskDelay(1);
    }

    int64_t elapsed_us = esp_timer_get_time() - start;
    int64_t per_op_us = elapsed_us / BENCH_N;

    ESP_LOGI(TAG, "blind_message x%d: %lld ms total, %lld us/op (~%lld ops/sec)",
             BENCH_N,
             elapsed_us / 1000,
             per_op_us,
             per_op_us > 0 ? (int64_t)1000000 / per_op_us : 0);

    #undef BENCH_N
}
