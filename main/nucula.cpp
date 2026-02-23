#include <cstdio>
#include <cstring>
#include <esp_log.h>
#include <esp_system.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include "secp256k1.h"
#include "crypto.h"
#include "crypto_test.h"
#include "wifi.h"
#include "cashu.hpp"
#include "cashu_json.hpp"
#include "wallet.hpp"
#include "console.h"

#define TAG "nucula"

static secp256k1_context *g_ctx = nullptr;
static cashu::Wallet *g_wallet = nullptr;

// -------------------------------------------------------------------------
// Console commands
// -------------------------------------------------------------------------

static void cmd_status(const char *arg)
{
    (void)arg;
    console_printf("wifi:    %s\r\n", wifi_is_connected() ? "connected" : "disconnected");

    if (g_wallet) {
        int n_keysets = (int)g_wallet->keysets().size();
        const cashu::Keyset *ks = g_wallet->active_keyset();
        console_printf("mint:    %s\r\n", g_wallet->mint_url().c_str());
        console_printf("keysets: %d\r\n", n_keysets);
        if (ks)
            console_printf("active:  %s (%d keys)\r\n",
                           ks->id.c_str(), (int)ks->keys.size());

        int balance = 0;
        for (const auto &p : g_wallet->proofs())
            balance += p.amount;
        console_printf("balance: %d sat (%d proofs)\r\n",
                       balance, (int)g_wallet->proofs().size());
    } else {
        nucula_console_write("wallet:  not initialized\r\n");
    }
}

static void cmd_balance(const char *arg)
{
    (void)arg;
    if (!g_wallet) {
        nucula_console_write("wallet not initialized\r\n");
        return;
    }

    int total = 0;
    for (const auto &p : g_wallet->proofs()) {
        console_printf("  %d sat  (keyset %s)\r\n", p.amount, p.id.c_str());
        total += p.amount;
    }
    console_printf("total: %d sat\r\n", total);
}

static void cmd_receive(const char *arg)
{
    if (!arg || strlen(arg) == 0) {
        nucula_console_write("usage: receive <cashuA...token>\r\n");
        return;
    }
    if (!wifi_is_connected()) {
        nucula_console_write("error: not connected to wifi\r\n");
        return;
    }

    cashu::Token token;
    if (!cashu::deserialize_token_v3(arg, token)) {
        nucula_console_write("error: failed to decode token\r\n");
        return;
    }

    int input_total = 0;
    for (const auto &p : token.proofs)
        input_total += p.amount;
    console_printf("token: %d sat in %d proofs from %s\r\n",
                   input_total, (int)token.proofs.size(), token.mint.c_str());

    if (!g_wallet || g_wallet->mint_url() != token.mint) {
        nucula_console_write("loading keysets for token mint...\r\n");
        delete g_wallet;
        g_wallet = new cashu::Wallet(token.mint, g_ctx);
        if (!g_wallet->load_keysets()) {
            nucula_console_write("error: failed to load keysets\r\n");
            return;
        }
    }

    nucula_console_write("swapping...\r\n");
    std::vector<cashu::Proof> received;
    if (!g_wallet->receive(token, received)) {
        nucula_console_write("error: receive failed\r\n");
        return;
    }

    int output_total = 0;
    for (const auto &p : received)
        output_total += p.amount;
    console_printf("received %d sat in %d proofs\r\n",
                   output_total, (int)received.size());
}

static void cmd_reboot(const char *arg)
{
    (void)arg;
    nucula_console_write("rebooting...\r\n");
    vTaskDelay(pdMS_TO_TICKS(100));
    esp_restart();
}

// -------------------------------------------------------------------------
// Main
// -------------------------------------------------------------------------

extern "C" void app_main(void)
{
    ESP_LOGI(TAG, "nucula cashu wallet");

    if (wifi_init() != ESP_OK)
        ESP_LOGE(TAG, "wifi failed, continuing offline");

    g_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!g_ctx) {
        ESP_LOGE(TAG, "failed to create secp256k1 context");
        return;
    }

    crypto_run_tests(g_ctx);

    if (wifi_is_connected()) {
        g_wallet = new cashu::Wallet("https://testmint.macadamia.cash", g_ctx);
        if (!g_wallet->load_keysets())
            ESP_LOGE(TAG, "failed to load keysets");
    }

    console_init(NULL);
    console_register_cmd("status",  cmd_status,  "show system and wallet status");
    console_register_cmd("balance", cmd_balance,  "show wallet balance");
    console_register_cmd("receive", cmd_receive,  "receive a cashuA token");
    console_register_cmd("reboot",  cmd_reboot,   "restart the device");
    console_start();
}
