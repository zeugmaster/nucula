#include <stdio.h>
#include <esp_log.h>
#include "secp256k1.h"
#include "secp256k1_schnorrsig.h"
#include "secp256k1_extrakeys.h"

void app_main(void)
{
    ESP_LOGI("nucula", "running main");


    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    ESP_LOGI("nucula", "secp256k1 context: %p", (void *)ctx);
    secp256k1_context_destroy(ctx);
}
