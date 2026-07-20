#include <esp_log.h>
#include "task_config.h"
#include <esp_random.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <nvs_flash.h>
#include "secp256k1.h"
#include "crypto_test.h"
#include "wifi.h"
#include "http.h"
#include "cashu_json.hpp"
#include "wallet.hpp"
#include "keyset.hpp"
#include "unit.hpp"
#include "commands.h"
#include "console.h"
#include "selftest.hpp"
#include "display.h"
#include "i2c_bus.h"
#include "nfc.hpp"
#include "keypad.h"
#include "wallet_store.hpp"
#include "ui.h"

#define TAG "nucula"

// Boot sequence only — the console command handlers live in the
// commands_*.cpp files.

// Drain task: while WiFi is connected, walk each wallet's pending queue
// and try to swap the stashed offline-receive tokens. We can't drain just
// once on the rising edge: DNS/routing is often not usable for the first
// few seconds after GOT_IP, and a link that stays up never produces
// another edge. So once connected we retry with an exponential backoff
// until everything is redeemed (or the link drops), then re-arm on the
// next reconnect.
static void wifi_drain_task(void *)
{
    EventGroupHandle_t eg = wifi_get_event_group();
    for (;;) {
        xEventGroupWaitBits(eg, WIFI_CONNECTED_BIT,
                            pdFALSE, pdTRUE, portMAX_DELAY);
        /* Settle: give the IP stack a moment before the first HTTP. */
        vTaskDelay(pdMS_TO_TICKS(2000));

        TickType_t backoff = pdMS_TO_TICKS(5000);
        const TickType_t backoff_max = pdMS_TO_TICKS(60000);
        while (xEventGroupGetBits(eg) & WIFI_CONNECTED_BIT) {
            if (wallet_store_total_pending() == 0)
                break;

            int total_ok = 0, total_fail = 0;
            for (int i = 0; i < MAX_MINTS; i++) {
                // Per-slot guard: released between slots so console
                // commands can interleave with a long drain pass.
                wallet_store_guard guard;
                auto *w = wallet_store_get(i);
                if (!w || w->pending_count() == 0) continue;
                int ok = 0, fail = 0;
                w->drain_pending_tokens(ok, fail);
                total_ok += ok;
                total_fail += fail;
            }
            if (total_ok || total_fail) {
                ESP_LOGI(TAG, "drain: %d ok, %d failed across all slots",
                         total_ok, total_fail);
                ui_refresh();
            }

            if (total_ok > 0) {
                /* Made progress; retry promptly for the rest. */
                backoff = pdMS_TO_TICKS(5000);
                vTaskDelay(backoff);
            } else {
                /* No progress (DNS not ready / mint down). Back off so we
                 * don't hammer the network, capped at backoff_max. */
                vTaskDelay(backoff);
                if (backoff < backoff_max)
                    backoff = backoff * 2 < backoff_max ? backoff * 2
                                                        : backoff_max;
            }
        }

        /* Drained, or the link dropped. Wait until the bit clears so the
         * next reconnect re-arms us. */
        while (xEventGroupGetBits(eg) & WIFI_CONNECTED_BIT)
            vTaskDelay(pdMS_TO_TICKS(5000));
    }
}

// -------------------------------------------------------------------------
// Main
// -------------------------------------------------------------------------

extern "C" void app_main(void)
{
    ESP_LOGI(TAG, "nucula cashu wallet");

    // NVS backs the wallet itself (proofs, seed, keysets) — bring it up
    // first and independently of WiFi.
    esp_err_t nvs_err = nvs_flash_init();
    if (nvs_err == ESP_ERR_NVS_NO_FREE_PAGES ||
        nvs_err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS needs erase (%s)", esp_err_to_name(nvs_err));
        if (nvs_flash_erase() == ESP_OK)
            nvs_err = nvs_flash_init();
    }
    if (nvs_err != ESP_OK)
        ESP_LOGE(TAG, "NVS init failed: %s — wallet persistence disabled",
                 esp_err_to_name(nvs_err));

    http_init();

    if (wifi_init() != ESP_OK)
        ESP_LOGE(TAG, "wifi failed, continuing offline");

    // Reserve the console's allocations FIRST, while heap is plentiful, so
    // its USB driver + line buffer always succeed. (Initializing it last
    // starved it once WiFi + every wallet's keysets were loaded.) The
    // command TASK starts only after wallet_store_init below, so no
    // handler can ever run against a half-initialized store.
    console_init(NULL);
    commands_wallet_register();
    commands_seed_register();
    commands_system_register();

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!ctx) {
        ESP_LOGE(TAG, "failed to create secp256k1 context");
        return;
    }
    {
        unsigned char rand32[32];
        esp_fill_random(rand32, sizeof(rand32));
        if (!secp256k1_context_randomize(ctx, rand32))
            ESP_LOGW(TAG, "secp256k1 context randomize failed");
    }

    if (!wallet_store_init(ctx)) {
        ESP_LOGE(TAG, "wallet store init failed");
        return;
    }
    console_start();

#if CONFIG_NUCULA_SELFTEST_ON_BOOT
    crypto_run_tests(ctx);
    if (!cashu::keyset_run_tests())
        ESP_LOGE(TAG, "keyset id derivation self-test FAILED");
    if (!cashu::unit_run_tests())
        ESP_LOGE(TAG, "unit formatter self-test FAILED");
    if (!cashu::cashu_json_run_tests())
        ESP_LOGE(TAG, "quote/mint-info JSON self-test FAILED");
    if (!nucula_pure_selftests())
        ESP_LOGE(TAG, "pure codec/math self-test FAILED");
    if (!cashu::Wallet::run_tests())
        ESP_LOGE(TAG, "wallet logic self-test FAILED");
#endif

    cashu::Wallet::load_seed();
    cashu::Wallet::ensure_p2pk_keypair(wallet_store_ctx());
    // Warm the cache before the keypad/UI tasks exist so later reads
    // from other tasks never hit the lazy NVS load.
    cashu::Wallet::default_unit();

    if (wifi_is_connected()) {
        for (int i = 0; i < MAX_MINTS; i++) {
            auto *w = wallet_store_get(i);
            if (!w) continue;
            if (!w->load_keysets())
                ESP_LOGW(TAG, "failed to refresh keysets for [%d]", i);
        }
    }


    xTaskCreate(wifi_drain_task, "wifi_drain", NUCULA_TASK_STACK_WIFI_DRAIN,
                NULL, NUCULA_TASK_PRIO_WIFI_DRAIN, NULL);

    // Shared I2C bus for display, keypad, and NFC. Each driver probes for
    // its device and disables itself when absent, so a bare module still
    // boots into a fully working console + wallet.
    if (i2c_bus_init() != ESP_OK)
        ESP_LOGW(TAG, "I2C bus init failed; display/keypad/NFC disabled");

    display_init(i2c_bus_get());

    if (keypad_init(i2c_bus_get()) == ESP_OK) {
        keypad_start_task();
        xTaskCreate(keypad_ui_task, "keypad_ui", NUCULA_TASK_STACK_KEYPAD_UI,
                    NULL, NUCULA_TASK_PRIO_KEYPAD_UI, NULL);
    }

    if (!nfc_init(i2c_bus_get()))
        ESP_LOGW(TAG, "PN7160 init failed, NFC disabled");

    ui_refresh();
}
