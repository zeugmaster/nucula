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

// -------------------------------------------------------------------------
// Paste your cashuA... token here for the receive test
// -------------------------------------------------------------------------
static const char *TEST_TOKEN =
    "cashuAeyJtZW1vIjoidGVzdCIsInRva2VuIjpbeyJtaW50IjoiaHR0cHM6XC9cL3Rlc3RtaW50Lm1hY2FkYW1pYS5jYXNoIiwicHJvb2ZzIjpbeyJzZWNyZXQiOiJjNTU2MWRkNmRlNDM0OTc2MjM3ZTcyNDBkYTdiNDA2NjYwMWYyOWQ2MmZmNTNjNTBhOWQ0NDViYmFjNGFjMTJhIiwiQyI6IjAzN2I3YjgwYjM5YzlkMGRiNWZiOTEyMmMwMjYzZDdiZjliMzA3YTlkMzE1MzViMDlmMWNkYjY5ZjA4YmRmMDZmNCIsImlkIjoiMDBlYTBkNDE2NjQ0MTI4YyIsImFtb3VudCI6MTZ9LHsic2VjcmV0IjoiZjY3MWNmOTQxODVmZjA4NTA1ODk2Y2FmN2MxOTQ4MjU0M2I1NDFiZGVkNGZiM2JkNmY2NmRmZmNiM2QxY2U5NCIsIkMiOiIwM2IxMTc0NjFhZGMwYjUwMzNjYzNiNzgyZmY2YjQxNzk4NDYwNmI1OWIxN2JmOTk5NDNmYTQ5NWUyYTMxNmUzNDgiLCJpZCI6IjAwZWEwZDQxNjY0NDEyOGMiLCJhbW91bnQiOjF9LHsic2VjcmV0IjoiOTFiYmVmNGU5N2Y2MzJjNDAyZTJhZjc3MTlhOTNkMjRhMTJhZDcyOWNmNGE2MzVjMzI4ODMxNTQwMGZjZjZkMyIsIkMiOiIwMjEwNDFmMDA4YzEzMjZiMTJmNWQ5YzNhYmU4MWY2ZDQxZmFiODEwNzAxYjRmODNkNTRlNzlmYjAxM2QxMWQ1MzAiLCJpZCI6IjAwZWEwZDQxNjY0NDEyOGMiLCJhbW91bnQiOjJ9LHsic2VjcmV0IjoiNzg1ODRkNjQ0NDc2ZjBhZDA4MzBhNWFkOTIzOWZlYjk4M2MzYzQ0Zjg4ODJjM2ZhOTJmZjI5MDY1OGI1MWYwNSIsIkMiOiIwMzgyMmVlMzM5YWIyYzg2OGU0MTZjMjI5MjZlNzQxZDk1NDIyNDFhYjY1MTc2NDI5YmZjYWQ4MmUxMTM5Y2RhYmIiLCJpZCI6IjAwZWEwZDQxNjY0NDEyOGMiLCJhbW91bnQiOjJ9XX1dLCJ1bml0Ijoic2F0In0=";

static void test_receive(secp256k1_context* ctx)
{
    if (!wifi_is_connected()) {
        ESP_LOGW(TAG, "receive test: skipped (offline)");
        return;
    }

    cashu::Token token;
    if (!cashu::deserialize_token_v3(TEST_TOKEN, token)) {
        ESP_LOGE(TAG, "receive test: failed to decode token");
        return;
    }

    int input_total = 0;
    for (const auto& p : token.proofs)
        input_total += p.amount;
    ESP_LOGI(TAG, "receive test: decoded token from %s (%d proofs, %d sat)",
             token.mint.c_str(), (int)token.proofs.size(), input_total);

    cashu::Wallet wallet(token.mint, ctx);

    if (!wallet.load_keysets()) {
        ESP_LOGE(TAG, "receive test: failed to load keysets");
        return;
    }

    std::vector<cashu::Proof> received;
    if (!wallet.receive(token, received)) {
        ESP_LOGE(TAG, "receive test: swap failed");
        return;
    }

    int output_total = 0;
    for (const auto& p : received) {
        output_total += p.amount;
        ESP_LOGI(TAG, "  proof: %d sat (keyset %s)",
                 p.amount, p.id.c_str());
    }
    ESP_LOGI(TAG, "receive test: SUCCESS - received %d sat in %d proofs",
             output_total, (int)received.size());
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
    test_receive(ctx);

    ESP_LOGI(TAG, "online: %s", wifi_is_connected() ? "yes" : "no");

    secp256k1_context_destroy(ctx);
}
