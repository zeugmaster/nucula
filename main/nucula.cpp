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
#include "cashu_cbor.hpp"
#include "wallet.hpp"
#include "console.h"
#include "display.h"

#define TAG "nucula"

static secp256k1_context *g_ctx = nullptr;
static cashu::Wallet *g_wallets[MAX_MINTS] = {};

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

static cashu::Wallet *find_wallet(const char *mint_url)
{
    for (int i = 0; i < MAX_MINTS; i++)
        if (g_wallets[i] && g_wallets[i]->mint_url() == mint_url)
            return g_wallets[i];
    return nullptr;
}

static int find_free_slot()
{
    for (int i = 0; i < MAX_MINTS; i++)
        if (!g_wallets[i])
            return i;
    return -1;
}

static int wallet_count()
{
    int n = 0;
    for (int i = 0; i < MAX_MINTS; i++)
        if (g_wallets[i]) n++;
    return n;
}

// -------------------------------------------------------------------------
// Display
// -------------------------------------------------------------------------

static void display_refresh()
{
    int y = 4;
    display_clear(COLOR_BLACK);

    // Title
    const char *title = "nucula";
    int tx = (LCD_W - display_text_width(title, 2)) / 2;
    display_text(tx, y, title, COLOR_AMBER, COLOR_BLACK, 2);
    y += 20;
    display_fill_rect(4, y, LCD_W - 8, 1, COLOR_DGRAY);
    y += 8;

    // Balance
    int total_balance = 0;
    int total_proofs = 0;
    for (int i = 0; i < MAX_MINTS; i++) {
        if (!g_wallets[i]) continue;
        for (const auto &p : g_wallets[i]->proofs())
            total_balance += p.amount;
        total_proofs += (int)g_wallets[i]->proofs().size();
    }
    char buf[32];
    snprintf(buf, sizeof(buf), "%d", total_balance);
    int bx = (LCD_W - display_text_width(buf, 4)) / 2;
    display_text(bx, y, buf, COLOR_WHITE, COLOR_BLACK, 4);
    y += 36;

    int ux = (LCD_W - display_text_width("sat", 2)) / 2;
    display_text(ux, y, "sat", COLOR_LGRAY, COLOR_BLACK, 2);
    y += 24;

    snprintf(buf, sizeof(buf), "%d proofs", total_proofs);
    int px = (LCD_W - display_text_width(buf, 1)) / 2;
    display_text(px, y, buf, COLOR_LGRAY, COLOR_BLACK, 1);
    y += 16;

    display_fill_rect(4, y, LCD_W - 8, 1, COLOR_DGRAY);
    y += 8;

    // Mints
    int count = wallet_count();
    snprintf(buf, sizeof(buf), "mints: %d/%d", count, MAX_MINTS);
    display_text(4, y, buf, COLOR_LGRAY, COLOR_BLACK, 1);
    y += 12;

    for (int i = 0; i < MAX_MINTS; i++) {
        if (!g_wallets[i]) continue;
        const char *url = g_wallets[i]->mint_url().c_str();
        if (strncmp(url, "https://", 8) == 0) url += 8;
        else if (strncmp(url, "http://", 7) == 0) url += 7;

        char line[30];
        snprintf(line, sizeof(line), "[%d] %.24s", i, url);
        display_text(4, y, line, COLOR_CYAN, COLOR_BLACK, 1);
        y += 10;

        int bal = 0;
        for (const auto &p : g_wallets[i]->proofs())
            bal += p.amount;
        snprintf(line, sizeof(line), "    %d sat", bal);
        display_text(4, y, line, COLOR_LGRAY, COLOR_BLACK, 1);
        y += 12;
    }

    display_fill_rect(4, y, LCD_W - 8, 1, COLOR_DGRAY);
    y += 8;

    // Status
    snprintf(buf, sizeof(buf), "wifi: %s",
             wifi_is_connected() ? "connected" : "offline");
    display_text(4, y, buf, wifi_is_connected() ? COLOR_GREEN : COLOR_AMBER,
                 COLOR_BLACK, 1);
    y += 12;

    snprintf(buf, sizeof(buf), "heap: %lu",
             (unsigned long)esp_get_free_heap_size());
    display_text(4, y, buf, COLOR_LGRAY, COLOR_BLACK, 1);
}

// -------------------------------------------------------------------------
// Console commands
// -------------------------------------------------------------------------

static void cmd_status(const char *arg)
{
    (void)arg;
    console_printf("wifi:    %s\r\n", wifi_is_connected() ? "connected" : "disconnected");
    console_printf("heap:    %lu bytes free\r\n",
                   (unsigned long)esp_get_free_heap_size());

    int count = wallet_count();
    console_printf("mints:   %d/%d\r\n", count, MAX_MINTS);

    int total_balance = 0;
    for (int i = 0; i < MAX_MINTS; i++) {
        auto *w = g_wallets[i];
        if (!w) continue;
        const cashu::Keyset *ks = w->active_keyset();
        console_printf("[%d] %s\r\n", i, w->mint_url().c_str());
        if (ks)
            console_printf("    active:  %s (%d keys)\r\n",
                           ks->id.c_str(), (int)ks->keys.size());
        console_printf("    keysets: %d\r\n", (int)w->keysets().size());
        int bal = 0;
        for (const auto &p : w->proofs())
            bal += p.amount;
        console_printf("    balance: %d sat (%d proofs)\r\n",
                       bal, (int)w->proofs().size());
        total_balance += bal;
    }
    if (count > 0)
        console_printf("total:   %d sat\r\n", total_balance);
}

static void cmd_balance(const char *arg)
{
    (void)arg;
    int total = 0;
    bool any = false;
    for (int i = 0; i < MAX_MINTS; i++) {
        auto *w = g_wallets[i];
        if (!w || w->proofs().empty()) continue;
        any = true;
        console_printf("[%s]\r\n", w->mint_url().c_str());
        int sub = 0;
        for (const auto &p : w->proofs()) {
            console_printf("  %d sat  (keyset %s)\r\n", p.amount, p.id.c_str());
            sub += p.amount;
        }
        console_printf("  subtotal: %d sat\r\n", sub);
        total += sub;
    }
    if (!any)
        nucula_console_write("no proofs\r\n");
    else
        console_printf("total: %d sat\r\n", total);
}

static void cmd_receive(const char *arg)
{
    if (!arg || strlen(arg) == 0) {
        nucula_console_write("usage: receive <cashu token>\r\n");
        return;
    }
    if (!wifi_is_connected()) {
        nucula_console_write("error: not connected to wifi\r\n");
        return;
    }

    cashu::Token token;
    bool decoded = false;
    if (strncmp(arg, "cashuB", 6) == 0)
        decoded = cashu::deserialize_token_v4(arg, token);
    else if (strncmp(arg, "cashuA", 6) == 0)
        decoded = cashu::deserialize_token_v3(arg, token);

    if (!decoded) {
        nucula_console_write("error: failed to decode token\r\n");
        return;
    }

    int input_total = 0;
    for (const auto &p : token.proofs)
        input_total += p.amount;
    console_printf("token: %d sat in %d proofs from %s\r\n",
                   input_total, (int)token.proofs.size(), token.mint.c_str());

    cashu::Wallet *w = find_wallet(token.mint.c_str());

    if (!w) {
        int slot = find_free_slot();
        if (slot < 0) {
            console_printf("error: max %d mints, remove one first\r\n", MAX_MINTS);
            return;
        }
        w = new cashu::Wallet(token.mint, g_ctx, slot);
        g_wallets[slot] = w;
        w->save_mint_url();
        console_printf("added mint [%d]: %s\r\n", slot, token.mint.c_str());
    }

    if (w->keysets().empty() || !w->active_keyset()) {
        nucula_console_write("loading keysets...\r\n");
        if (!w->load_keysets()) {
            nucula_console_write("error: failed to load keysets\r\n");
            return;
        }
    }

    nucula_console_write("swapping...\r\n");
    std::vector<cashu::Proof> received;
    if (!w->receive(token, received)) {
        nucula_console_write("error: receive failed\r\n");
        return;
    }

    int output_total = 0;
    for (const auto &p : received)
        output_total += p.amount;
    console_printf("received %d sat in %d proofs\r\n",
                   output_total, (int)received.size());
    display_refresh();
}

static void cmd_mint(const char *arg)
{
    if (!arg || strlen(arg) == 0 || strcmp(arg, "list") == 0) {
        int count = wallet_count();
        if (count == 0) {
            nucula_console_write("no mints configured\r\n");
            return;
        }
        for (int i = 0; i < MAX_MINTS; i++) {
            if (!g_wallets[i]) continue;
            int bal = 0;
            for (const auto &p : g_wallets[i]->proofs())
                bal += p.amount;
            console_printf("[%d] %s  (%d keysets, %d sat)\r\n",
                           i, g_wallets[i]->mint_url().c_str(),
                           (int)g_wallets[i]->keysets().size(), bal);
        }
        console_printf("%d/%d slots used\r\n", count, MAX_MINTS);
        return;
    }

    if (strncmp(arg, "add ", 4) == 0) {
        const char *url = arg + 4;
        while (*url == ' ') url++;
        if (strlen(url) == 0) {
            nucula_console_write("usage: mint add <url>\r\n");
            return;
        }
        if (find_wallet(url)) {
            nucula_console_write("mint already added\r\n");
            return;
        }
        int slot = find_free_slot();
        if (slot < 0) {
            console_printf("error: max %d mints, remove one first\r\n", MAX_MINTS);
            return;
        }
        auto *w = new cashu::Wallet(url, g_ctx, slot);
        g_wallets[slot] = w;
        w->save_mint_url();
        console_printf("added mint [%d]: %s\r\n", slot, url);

        if (wifi_is_connected()) {
            nucula_console_write("loading keysets...\r\n");
            if (!w->load_keysets())
                nucula_console_write("warning: failed to load keysets\r\n");
        } else {
            nucula_console_write("offline: keysets will load when connected\r\n");
        }
        display_refresh();
        return;
    }

    if (strncmp(arg, "remove ", 7) == 0) {
        const char *id = arg + 7;
        while (*id == ' ') id++;

        int slot = -1;
        if (strlen(id) == 1 && id[0] >= '0' && id[0] < ('0' + MAX_MINTS))
            slot = id[0] - '0';

        cashu::Wallet *w = nullptr;
        if (slot >= 0 && g_wallets[slot]) {
            w = g_wallets[slot];
        } else {
            for (int i = 0; i < MAX_MINTS; i++) {
                if (g_wallets[i] && g_wallets[i]->mint_url() == id) {
                    w = g_wallets[i];
                    slot = i;
                    break;
                }
            }
        }

        if (!w) {
            nucula_console_write("mint not found\r\n");
            return;
        }

        int bal = 0;
        for (const auto &p : w->proofs())
            bal += p.amount;
        console_printf("removing [%d] %s (%d sat, %d proofs erased)\r\n",
                       slot, w->mint_url().c_str(),
                       bal, (int)w->proofs().size());
        w->erase_nvs();
        delete w;
        g_wallets[slot] = nullptr;
        display_refresh();
        return;
    }

    nucula_console_write("usage: mint [list|add <url>|remove <index|url>]\r\n");
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

    display_init();

    if (wifi_init() != ESP_OK)
        ESP_LOGE(TAG, "wifi failed, continuing offline");

    g_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!g_ctx) {
        ESP_LOGE(TAG, "failed to create secp256k1 context");
        return;
    }

    crypto_run_tests(g_ctx);

    for (int i = 0; i < MAX_MINTS; i++) {
        std::string url = cashu::Wallet::load_mint_url_for_slot(i);
        if (url.empty()) continue;
        auto *w = new cashu::Wallet(url, g_ctx, i);
        w->load_from_nvs();
        g_wallets[i] = w;
        ESP_LOGI(TAG, "restored wallet [%d] %s (%d keysets, %d proofs)",
                 i, url.c_str(), (int)w->keysets().size(), (int)w->proofs().size());
    }

    if (wifi_is_connected()) {
        for (int i = 0; i < MAX_MINTS; i++) {
            if (!g_wallets[i]) continue;
            if (!g_wallets[i]->load_keysets())
                ESP_LOGW(TAG, "failed to refresh keysets for [%d]", i);
        }
    }

    display_refresh();

    console_init(NULL);
    console_register_cmd("status",  cmd_status,  "show system and wallet status");
    console_register_cmd("balance", cmd_balance,  "show wallet balance");
    console_register_cmd("receive", cmd_receive,  "receive a cashuA token");
    console_register_cmd("mint",    cmd_mint,     "mint [list|add <url>|remove <idx>]");
    console_register_cmd("reboot",  cmd_reboot,   "restart the device");
    console_start();
}
