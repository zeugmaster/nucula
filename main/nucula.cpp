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
        ok &= (token.proofs[0].secret == "407915bc212be61a77e3e6d2aeb4c727980bda51cd06a6afc29e2861768a7837");
        ok &= (token.proofs[0].C == "02bc9097997d81afb2cc7346b5e4345a9346bd2a506eb7958598a72f0cf85163ea");
        ok &= (token.proofs[1].amount == 8);
        ok &= (token.proofs[1].id == "009a1f293253e41e");
    }

    if (ok) {
        std::string roundtrip = cashu::serialize_token_v3(token);
        cashu::Token token2;
        ok &= cashu::deserialize_token_v3(roundtrip.c_str(), token2);
        ok &= (token2.proofs.size() == 2);
        ok &= (token2.mint == token.mint);
        ok &= (token2.proofs[0].secret == token.proofs[0].secret);
    }

    if (ok)
        ESP_LOGI(TAG, "token_v3 decode: OK (mint=%s, %d proofs, %d sat)",
                 token.mint.c_str(), (int)token.proofs.size(),
                 token.proofs[0].amount + token.proofs[1].amount);
    else
        ESP_LOGE(TAG, "token_v3 decode: FAILED field check");
}

static void test_http_connectivity()
{
    if (!wifi_is_connected()) {
        ESP_LOGW(TAG, "http test: skipped (offline)");
        return;
    }

    http_response_t resp = {};
    esp_err_t err = http_get("https://mint.minibits.cash/Bitcoin/v1/info", &resp);
    if (err == ESP_OK && resp.status == 200 && resp.body) {
        ESP_LOGI(TAG, "http test: OK (status %d, %zu bytes)", resp.status, resp.body_len);
    } else {
        ESP_LOGE(TAG, "http test: FAILED (err=%s, status=%d)",
                 esp_err_to_name(err), resp.status);
    }
    http_response_free(&resp);
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
    test_http_connectivity();

    ESP_LOGI(TAG, "online: %s", wifi_is_connected() ? "yes" : "no");

    secp256k1_context_destroy(ctx);
}
