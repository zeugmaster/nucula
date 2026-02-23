#include <cstdio>
#include <esp_log.h>
#include "secp256k1.h"
#include "crypto.h"
#include "crypto_test.h"
#include "cashu.hpp"

#define TAG "nucula"

extern "C" void app_main(void)
{
    ESP_LOGI(TAG, "nucula cashu wallet");

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!ctx) {
        ESP_LOGE(TAG, "failed to create secp256k1 context");
        return;
    }

    crypto_run_tests(ctx);

    secp256k1_context_destroy(ctx);
}
