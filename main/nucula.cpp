#include <cstdio>
#include <cstring>
#include <esp_log.h>
#include "secp256k1.h"
#include "crypto.h"
#include "crypto_test.h"
#include "wifi.h"
#include "http.h"
#include "cashu.hpp"
#include "cashu_json.hpp"
#include "wallet.hpp"

#define TAG "nucula"

static void test_token_v3_decode()
{
    static const char *v3_token =
        "cashuAeyJ0b2tlbiI6W3sibWludCI6Imh0dHBzOi8vODMzMy5zcGFjZTozMzM4"
        "IiwicHJvb2ZzIjpbeyJhbW91bnQiOjIsImlkIjoiMDA5YTFmMjkzMjUzZTQxZSIs"
        "InNlY3JldCI6IjQwNzkxNWJjMjEyYmU2MWE3N2UzZTZkMmFlYjRjNzI3OTgwYmRh"
        "NTFjZDA2YTZhZmMyOWUyODYxNzY4YTc4MzciLCJDIjoiMDJiYzkwOTc5OTdkODFh"
        "ZmIyY2M3MzQ2YjVlNDM0NWE5MzQ2YmQyYTUwNmViNzk1ODU5OGE3MmYwY2Y4NTE2"
        "M2VhIn0seyJhbW91bnQiOjgsImlkIjoiMDA5YTFmMjkzMjUzZTQxZSIsInNlY3Jl"
        "dCI6ImZlMTUxMDkzMTRlNjFkNzc1NmIwZjhlZTBmMjNhNjI0YWNhYTNmNGUwNDJm"
        "NjE0MzNjNzI4YzcwNTdiOTMxYmUiLCJDIjoiMDI5ZThlNTA1MGI4OTBhN2Q2YzA5"
        "NjhkYjE2YmMxZDVkNWZhMDQwZWExZGUyODRmNmVjNjlkNjEyOTlmNjcxMDU5In1d"
        "fV0sInVuaXQiOiJzYXQiLCJtZW1vIjoiVGhhbmsgeW91LiJ9";

    cashu::Token token;
    if (!cashu::deserialize_token_v3(v3_token, token)) {
        ESP_LOGE(TAG, "token_v3 decode: FAILED to parse");
        return;
    }

    bool ok = true;
    ok &= (token.mint == "https://8333.space:3338");
    ok &= (token.unit == "sat");
    ok &= (token.memo && *token.memo == "Thank you.");
    ok &= (token.proofs.size() == 2);

    if (ok) {
        ok &= (token.proofs[0].amount == 2);
        ok &= (token.proofs[0].id == "009a1f293253e41e");
        ok &= (token.proofs[1].amount == 8);

        std::string roundtrip = cashu::serialize_token_v3(token);
        cashu::Token token2;
        ok &= cashu::deserialize_token_v3(roundtrip.c_str(), token2);
        ok &= (token2.proofs.size() == 2);
        ok &= (token2.mint == token.mint);
    }

    if (ok)
        ESP_LOGI(TAG, "token_v3 decode: OK");
    else
        ESP_LOGE(TAG, "token_v3 decode: FAILED");
}

static void test_wallet_keysets(secp256k1_context* ctx)
{
    if (!wifi_is_connected()) {
        ESP_LOGW(TAG, "wallet test: skipped (offline)");
        return;
    }

    cashu::Wallet wallet("https://testmint.macadamia.cash", ctx);

    if (!wallet.load_keysets()) {
        ESP_LOGE(TAG, "wallet test: failed to load keysets");
        return;
    }

    const cashu::Keyset* ks = wallet.active_keyset("sat");
    if (!ks) {
        ESP_LOGE(TAG, "wallet test: no active sat keyset");
        return;
    }

    ESP_LOGI(TAG, "wallet test: active keyset %s with %d keys",
             ks->id.c_str(), (int)ks->keys.size());

    auto amounts = cashu::Wallet::split_amount(13);
    ESP_LOGI(TAG, "wallet test: split(13) = [");
    for (int a : amounts)
        ESP_LOGI(TAG, "  %d", a);
    ESP_LOGI(TAG, "]");

    cashu::Wallet::BlindingData bd;
    if (wallet.generate_outputs({1, 4, 8}, ks->id, bd)) {
        ESP_LOGI(TAG, "wallet test: generated %d blinded outputs",
                 (int)bd.outputs.size());
    } else {
        ESP_LOGE(TAG, "wallet test: generate_outputs failed");
    }

    ESP_LOGI(TAG, "wallet test: OK");
}

extern "C" void app_main(void)
{
    ESP_LOGI(TAG, "nucula cashu wallet");

    if (wifi_init() != ESP_OK) {
        ESP_LOGE(TAG, "wifi failed, continuing offline");
    }

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!ctx) {
        ESP_LOGE(TAG, "failed to create secp256k1 context");
        return;
    }

    crypto_run_tests(ctx);
    test_token_v3_decode();
    test_wallet_keysets(ctx);

    ESP_LOGI(TAG, "online: %s", wifi_is_connected() ? "yes" : "no");

    secp256k1_context_destroy(ctx);
}
