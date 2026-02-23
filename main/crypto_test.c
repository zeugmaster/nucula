#include "crypto_test.h"
#include "crypto.h"
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

int crypto_run_tests(const secp256k1_context *ctx)
{
    ESP_LOGI(TAG, "running crypto test vectors");

    int pass = 1;
    pass &= test_hash_to_curve(ctx);
    pass &= test_blind_message(ctx);
    pass &= test_unblind(ctx);
    pass &= test_dleq(ctx);

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
