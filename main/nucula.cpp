#include <cstdio>
#include <cstring>
#include <esp_heap_caps.h>
#include <esp_log.h>
#include <esp_random.h>
#include <esp_system.h>
#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <nvs_flash.h>
#include "secp256k1.h"
#include "crypto.h"
#include "crypto_test.h"
#include "wifi.h"
#include "http.h"
#include "cashu.hpp"
#include "cashu_json.hpp"
#include "cashu_cbor.hpp"
#include "wallet.hpp"
#include "keyset.hpp"
#include "unit.hpp"
#include "console.h"
#include "display.h"
#include "i2c_bus.h"
#include "nfc.hpp"
#include "keypad.h"
#include "bip39.h"
#include "wallet_store.hpp"
#include "ui.h"

#define TAG "nucula"

// -------------------------------------------------------------------------
// Console commands
// -------------------------------------------------------------------------

static void cmd_status(const char *arg)
{
    wallet_store_guard guard;
    (void)arg;
    console_printf("wifi:    %s\r\n", wifi_is_connected() ? "connected" : "disconnected");
    console_printf("nfc:     %s\r\n", nfc_status_str());
    console_printf("heap:    %lu bytes free\r\n",
                   (unsigned long)esp_get_free_heap_size());

    int count = wallet_store_count();
    console_printf("mints:   %d/%d\r\n", count, MAX_MINTS);

    long long total_balance = 0;
    for (int i = 0; i < MAX_MINTS; i++) {
        auto *w = wallet_store_get(i);
        if (!w) continue;
        const cashu::Keyset *ks = w->active_keyset();
        console_printf("[%d] %s\r\n", i, w->mint_url().c_str());
        if (ks)
            console_printf("    active:  %s (%d keys)\r\n",
                           ks->id.c_str(), (int)ks->keys.size());
        console_printf("    keysets: %d\r\n", (int)w->keysets().size());
        long long bal = w->balance();
        console_printf("    balance: %lld sat (%d proofs)\r\n",
                       bal, (int)w->proofs().size());
        total_balance += bal;
    }
    if (count > 0)
        console_printf("total:   %lld sat\r\n", (long long)total_balance);
}

static void cmd_balance(const char *arg)
{
    wallet_store_guard guard;
    (void)arg;
    long long total = 0;
    bool any = false;
    for (int i = 0; i < MAX_MINTS; i++) {
        auto *w = wallet_store_get(i);
        if (!w || w->proofs().empty()) continue;
        any = true;
        console_printf("[%s]\r\n", w->mint_url().c_str());
        for (const auto &p : w->proofs())
            console_printf("  %d sat  (keyset %s)\r\n", p.amount, p.id.c_str());
        long long sub = w->balance();
        console_printf("  subtotal: %lld sat\r\n", sub);
        total += sub;
    }
    if (!any)
        nucula_console_write("no proofs\r\n");
    else
        console_printf("total: %lld sat\r\n", total);
}

static void cmd_receive(const char *arg)
{
    wallet_store_guard guard;
    if (!arg || strlen(arg) == 0) {
        nucula_console_write("usage: receive <cashu token>\r\n");
        return;
    }
    if (!wifi_is_connected()) {
        nucula_console_write("error: not connected to wifi\r\n");
        return;
    }

    cashu::Token token;
    if (!cashu::deserialize_token(arg, token)) {
        nucula_console_write("error: failed to decode token\r\n");
        return;
    }

    console_printf("token: %lld sat in %d proofs from %s\r\n",
                   (long long)cashu::proofs_sum(token.proofs),
                   (int)token.proofs.size(), token.mint.c_str());

    cashu::Wallet *w = wallet_store_get_or_create(token.mint);
    if (!w) {
        console_printf("error: max %d mints, remove one first\r\n", MAX_MINTS);
        return;
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
    int64_t t0 = esp_timer_get_time();
    if (!w->receive(token, received)) {
        nucula_console_write("error: receive failed\r\n");
        return;
    }
    long long ms = (esp_timer_get_time() - t0) / 1000;

    console_printf("received %lld sat in %d proofs (%lld ms)\r\n",
                   (long long)cashu::proofs_sum(received), (int)received.size(), ms);
    display_refresh();
}

static void cmd_mint(const char *arg)
{
    wallet_store_guard guard;
    if (!arg || strlen(arg) == 0 || strcmp(arg, "list") == 0) {
        int count = wallet_store_count();
        if (count == 0) {
            nucula_console_write("no mints configured\r\n");
            return;
        }
        for (int i = 0; i < MAX_MINTS; i++) {
            if (!wallet_store_get(i)) continue;
            console_printf("[%d] %s  (%d keysets, %lld sat)\r\n",
                           i, wallet_store_get(i)->mint_url().c_str(),
                           (int)wallet_store_get(i)->keysets().size(),
                           (long long)wallet_store_get(i)->balance());
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
        if (wallet_store_find(url)) {
            nucula_console_write("mint already added\r\n");
            return;
        }
        auto *w = wallet_store_get_or_create(url);
        if (!w) {
            console_printf("error: max %d mints, remove one first\r\n", MAX_MINTS);
            return;
        }
        console_printf("added mint [%d]: %s\r\n", w->nvs_slot(), url);

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

        cashu::Wallet *w = wallet_store_get(slot);
        if (!w) {
            w = wallet_store_find(id);
            if (w)
                slot = w->nvs_slot();
        }

        if (!w) {
            nucula_console_write("mint not found\r\n");
            return;
        }

        console_printf("removing [%d] %s (%lld sat, %d proofs erased)\r\n",
                       slot, w->mint_url().c_str(),
                       (long long)w->balance(), (int)w->proofs().size());
        wallet_store_remove(slot);
        display_refresh();
        return;
    }

    nucula_console_write("usage: mint [list|add <url>|remove <index|url>]\r\n");
}

static void cmd_nfc(const char *arg)
{
    if (!arg || strlen(arg) == 0) {
        console_printf("nfc: %s\r\n", nfc_status_str());
        return;
    }
    if (strncmp(arg, "request ", 8) == 0) {
        int amount = atoi(arg + 8);
        if (amount <= 0) {
            nucula_console_write("usage: nfc request <amount>\r\n");
            return;
        }
        if (nfc_state() == NfcState::off) {
            nucula_console_write("error: NFC not available\r\n");
            return;
        }
        console_printf("requesting %d sat via NFC...\r\n", amount);
        if (!nfc_request_start(amount, nullptr))
            nucula_console_write("error: failed to start\r\n");
        return;
    }
    if (strcmp(arg, "stop") == 0) {
        nfc_request_stop();
        nucula_console_write("nfc stopped\r\n");
        display_refresh();
        return;
    }
    nucula_console_write("usage: nfc [request <amount>|stop]\r\n");
}

// Caller must hold the wallet_store guard (all cmd_* callers do).
static cashu::Wallet *resolve_wallet(const char *idx_str)
{
    int count = wallet_store_count();
    if (count == 0) {
        nucula_console_write("error: no mints configured\r\n");
        return nullptr;
    }
    if (idx_str && *idx_str) {
        int slot = atoi(idx_str);
        if (slot >= 0 && slot < MAX_MINTS && wallet_store_get(slot))
            return wallet_store_get(slot);
        nucula_console_write("error: invalid mint index\r\n");
        return nullptr;
    }
    if (count == 1) {
        for (int i = 0; i < MAX_MINTS; i++)
            if (wallet_store_get(i)) return wallet_store_get(i);
    }
    nucula_console_write("error: multiple mints, specify index\r\n");
    for (int i = 0; i < MAX_MINTS; i++) {
        if (!wallet_store_get(i)) continue;
        console_printf("  [%d] %s\r\n", i, wallet_store_get(i)->mint_url().c_str());
    }
    return nullptr;
}

static void cmd_invoice(const char *arg)
{
    wallet_store_guard guard;
    if (!arg || strlen(arg) == 0) {
        nucula_console_write("usage: invoice <amount> [mint_index]\r\n");
        return;
    }
    if (!wifi_is_connected()) {
        nucula_console_write("error: not connected to wifi\r\n");
        return;
    }

    int amount = atoi(arg);
    if (amount <= 0) {
        nucula_console_write("error: amount must be positive\r\n");
        return;
    }

    const char *idx_str = nullptr;
    const char *space = strchr(arg, ' ');
    if (space) {
        idx_str = space + 1;
        while (*idx_str == ' ') idx_str++;
        if (*idx_str == '\0') idx_str = nullptr;
    }

    cashu::Wallet *w = resolve_wallet(idx_str);
    if (!w) return;

    if (w->keysets().empty() || !w->active_keyset()) {
        nucula_console_write("loading keysets...\r\n");
        if (!w->load_keysets()) {
            nucula_console_write("error: failed to load keysets\r\n");
            return;
        }
    }

    nucula_console_write("requesting mint quote...\r\n");
    cashu::MintQuote quote;
    if (!w->request_mint_quote(amount, "sat", "bolt11", quote)) {
        nucula_console_write("error: failed to get mint quote\r\n");
        return;
    }

    nucula_console_write("pay this invoice:\r\n");
    nucula_console_write(quote.request.c_str());
    nucula_console_write("\r\n");
    console_printf("quote: %s\r\n", quote.quote.c_str());
    console_printf("amount: %d sat\r\n", quote.amount);
    nucula_console_write("then run: claim <quote_id>\r\n");
}

static void cmd_claim(const char *arg)
{
    wallet_store_guard guard;
    if (!arg || strlen(arg) == 0) {
        nucula_console_write("usage: claim <quote_id> [mint_index]\r\n");
        return;
    }
    if (!wifi_is_connected()) {
        nucula_console_write("error: not connected to wifi\r\n");
        return;
    }

    // Split quote_id and optional mint index
    std::string quote_id;
    const char *space = strchr(arg, ' ');
    const char *idx_str = nullptr;
    if (space) {
        quote_id = std::string(arg, space - arg);
        idx_str = space + 1;
        while (*idx_str == ' ') idx_str++;
        if (*idx_str == '\0') idx_str = nullptr;
    } else {
        quote_id = arg;
    }

    cashu::Wallet *w = nullptr;
    cashu::MintQuote quote;

    if (idx_str) {
        w = resolve_wallet(idx_str);
        if (!w) return;
        if (!w->check_mint_quote(quote_id, "bolt11", quote)) {
            nucula_console_write("error: quote not found on this mint\r\n");
            return;
        }
    } else {
        for (int i = 0; i < MAX_MINTS; i++) {
            if (!wallet_store_get(i)) continue;
            if (wallet_store_get(i)->check_mint_quote(quote_id, "bolt11", quote)) {
                w = wallet_store_get(i);
                break;
            }
        }
    }

    if (!w) {
        nucula_console_write("error: quote not found on any mint\r\n");
        return;
    }

    // Claimable = amount_paid - amount_issued on current mints; legacy
    // bolt11 mints only expose state, where PAID means the full amount.
    int claimable = quote.mintable();
    if (claimable <= 0) {
        if (quote.state == "UNPAID")
            nucula_console_write("invoice not paid yet\r\n");
        else if (quote.state == "ISSUED")
            nucula_console_write("tokens already claimed\r\n");
        else if (quote.amount_paid && quote.amount_issued)
            nucula_console_write("nothing mintable (paid amount fully issued)\r\n");
        else
            console_printf("unexpected state: %s\r\n", quote.state.c_str());
        return;
    }

    if (w->keysets().empty() || !w->active_keyset()) {
        nucula_console_write("loading keysets...\r\n");
        if (!w->load_keysets()) {
            nucula_console_write("error: failed to load keysets\r\n");
            return;
        }
    }

    nucula_console_write("minting tokens...\r\n");
    if (!w->mint_tokens(quote, claimable)) {
        nucula_console_write("error: minting failed\r\n");
        return;
    }

    char amt[48];
    cashu::format_amount(amt, sizeof(amt), claimable,
                         quote.unit.empty() ? "sat" : quote.unit.c_str());
    console_printf("minted %s\r\n", amt);
    display_refresh();
}

static void cmd_melt(const char *arg)
{
    wallet_store_guard guard;
    if (!arg || strlen(arg) == 0) {
        nucula_console_write("usage: melt <bolt11_invoice> [mint_index]\r\n");
        return;
    }
    if (!wifi_is_connected()) {
        nucula_console_write("error: not connected to wifi\r\n");
        return;
    }

    // Split bolt11 and optional mint index
    std::string bolt11;
    const char *idx_str = nullptr;
    const char *space = strchr(arg, ' ');
    if (space) {
        bolt11 = std::string(arg, space - arg);
        idx_str = space + 1;
        while (*idx_str == ' ') idx_str++;
        if (*idx_str == '\0') idx_str = nullptr;
    } else {
        bolt11 = arg;
    }

    cashu::Wallet *w = resolve_wallet(idx_str);
    if (!w) return;

    if (w->keysets().empty() || !w->active_keyset()) {
        nucula_console_write("loading keysets...\r\n");
        if (!w->load_keysets()) {
            nucula_console_write("error: failed to load keysets\r\n");
            return;
        }
    }

    nucula_console_write("requesting melt quote...\r\n");
    cashu::MeltQuote quote;
    if (!w->request_melt_quote(bolt11, "sat", "bolt11", quote)) {
        nucula_console_write("error: failed to get melt quote\r\n");
        return;
    }

    long long wallet_bal = w->balance();
    int total_needed = quote.amount + quote.fee_reserve;
    console_printf("amount:      %d sat\r\n", quote.amount);
    console_printf("fee_reserve: %d sat\r\n", quote.fee_reserve);
    console_printf("balance:     %lld sat\r\n", wallet_bal);

    if (wallet_bal < total_needed) {
        console_printf("error: insufficient balance (%lld < %d)\r\n",
                       wallet_bal, total_needed);
        return;
    }

    nucula_console_write("paying invoice...\r\n");
    int change_amount = 0;
    if (!w->melt_tokens(quote, change_amount)) {
        nucula_console_write("error: melt failed\r\n");
        return;
    }

    console_printf("paid %d sat\r\n", quote.amount);
    if (change_amount > 0)
        console_printf("change: %d sat\r\n", change_amount);
    display_refresh();
}

static void cmd_stickup(const char *arg)
{
    wallet_store_guard guard;
    (void)arg;

    bool any = false;
    for (int i = 0; i < MAX_MINTS; i++) {
        auto *w = wallet_store_get(i);
        if (!w || w->proofs().empty()) continue;

        any = true;
        console_printf("[%d] %s: %lld sat in %d proofs\r\n",
                       i, w->mint_url().c_str(),
                       (long long)w->balance(), (int)w->proofs().size());

        cashu::Token token;
        token.mint = w->mint_url();
        token.unit = "sat";
        token.proofs = w->proofs();

        std::string serialized = cashu::serialize_token_v4(token);
        if (serialized.empty()) {
            // Without this token string the proofs have no other exit —
            // clearing them here would destroy the funds.
            console_printf("[%d] error: token serialization failed, not draining\r\n", i);
            continue;
        }

        nucula_console_write(serialized.c_str());
        nucula_console_write("\r\n");

        w->clear_proofs();
        console_printf("[%d] drained\r\n", i);
    }

    if (!any)
        nucula_console_write("nothing to drain\r\n");
    else
        display_refresh();
}

// -------------------------------------------------------------------------
// Seed management (NUT-13)
// -------------------------------------------------------------------------

static void erase_all_wallets()
{
    wallet_store_guard guard;
    wallet_store_remove_all();
}

static void cmd_seed(const char *arg)
{
    wallet_store_guard guard;
    if (!arg || strlen(arg) == 0 || strcmp(arg, "show") == 0) {
        std::string mnemonic;
        if (cashu::Wallet::load_mnemonic(mnemonic)) {
            nucula_console_write("WARNING: keep your seed phrase secret!\r\n");
            nucula_console_write(mnemonic.c_str());
            nucula_console_write("\r\n");
        } else {
            nucula_console_write("no seed configured\r\n");
        }
        return;
    }

    if (strcmp(arg, "generate") == 0) {
        char mnemonic[256];
        if (!bip39_generate(mnemonic, sizeof(mnemonic))) {
            nucula_console_write("ERROR: mnemonic generation failed\r\n");
            return;
        }

        unsigned char seed[64];
        if (!bip39_to_seed(mnemonic, seed)) {
            nucula_console_write("ERROR: seed derivation failed\r\n");
            return;
        }

        erase_all_wallets();
        cashu::Wallet::erase_seed();

        if (!cashu::Wallet::save_seed(seed, mnemonic)) {
            nucula_console_write("ERROR: failed to save seed\r\n");
            return;
        }

        nucula_console_write("seed generated. write down your seed phrase:\r\n\r\n");
        nucula_console_write(mnemonic);
        nucula_console_write("\r\n\r\nall wallet data erased. add mints with 'mint add <url>'\r\n");
        display_refresh();
        return;
    }

    if (strncmp(arg, "restore ", 8) == 0) {
        const char *words = arg + 8;
        while (*words == ' ') words++;

        if (!bip39_validate(words)) {
            nucula_console_write("ERROR: invalid mnemonic (bad checksum or unknown words)\r\n");
            return;
        }

        unsigned char seed[64];
        if (!bip39_to_seed(words, seed)) {
            nucula_console_write("ERROR: seed derivation failed\r\n");
            return;
        }

        erase_all_wallets();
        cashu::Wallet::erase_seed();

        if (!cashu::Wallet::save_seed(seed, words)) {
            nucula_console_write("ERROR: failed to save seed\r\n");
            return;
        }

        nucula_console_write("seed restored. all wallet data erased.\r\n");
        nucula_console_write("add mints with 'mint add <url>' to begin recovery\r\n");
        display_refresh();
        return;
    }

    if (strcmp(arg, "wipe") == 0) {
        erase_all_wallets();
        cashu::Wallet::erase_seed();
        nucula_console_write("seed and all wallet data erased\r\n");
        display_refresh();
        return;
    }

    nucula_console_write("usage: seed [show|generate|restore <12 words>|wipe]\r\n");
}

static void cmd_reboot(const char *arg)
{
    (void)arg;
    nucula_console_write("rebooting...\r\n");
    vTaskDelay(pdMS_TO_TICKS(100));
    esp_restart();
}

// -------------------------------------------------------------------------
// Telemetry
// -------------------------------------------------------------------------

static void cmd_heap(const char *arg)
{
    (void)arg;
    console_printf("free:          %lu\r\n", (unsigned long)esp_get_free_heap_size());
    console_printf("largest block: %u\r\n",
                   (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
    console_printf("min ever free: %lu\r\n",
                   (unsigned long)esp_get_minimum_free_heap_size());
}

static void cmd_tasks(const char *arg)
{
    (void)arg;
    UBaseType_t n = uxTaskGetNumberOfTasks();
    TaskStatus_t *st = (TaskStatus_t *)malloc(n * sizeof(TaskStatus_t));
    if (!st) {
        nucula_console_write("error: out of memory\r\n");
        return;
    }
    n = uxTaskGetSystemState(st, n, NULL);
    console_printf("%-16s %4s %10s\r\n", "name", "prio", "stack-min");
    for (UBaseType_t i = 0; i < n; i++)
        console_printf("%-16s %4u %10u\r\n", st[i].pcTaskName,
                       (unsigned)st[i].uxCurrentPriority,
                       (unsigned)st[i].usStackHighWaterMark);
    free(st);
}

static void cmd_log(const char *arg)
{
    esp_log_level_t level;
    if (arg && arg[0] && (arg[1] == '\0' || arg[1] == ' ')) {
        switch (arg[0]) {
            case 'e': level = ESP_LOG_ERROR; break;
            case 'w': level = ESP_LOG_WARN;  break;
            case 'i': level = ESP_LOG_INFO;  break;
            case 'd': level = ESP_LOG_DEBUG; break;
            default:  goto usage;
        }
        const char *tag = arg + 1;
        while (*tag == ' ') tag++;
        esp_log_level_set(*tag ? tag : "*", level);
        console_printf("log level '%c' set for %s\r\n", arg[0], *tag ? tag : "*");
        return;
    }
usage:
    nucula_console_write("usage: log <e|w|i|d> [tag]\r\n");
}

static void cmd_bench(const char *arg)
{
    (void)arg;
    nucula_console_write("benchmarking crypto primitives...\r\n");
    crypto_run_benchmark(wallet_store_ctx());
    nucula_console_write("done (results logged at info level)\r\n");
}

static void cmd_selftest(const char *arg)
{
    (void)arg;
    nucula_console_write("running self-tests (details logged at info level)...\r\n");
    bool ok = crypto_run_tests(wallet_store_ctx()) != 0;
    if (!cashu::keyset_run_tests())
        ok = false;
    if (!cashu::unit_run_tests())
        ok = false;
    if (!cashu::cashu_json_run_tests())
        ok = false;
    console_printf("self-tests %s\r\n", ok ? "PASSED" : "FAILED");
}

// -------------------------------------------------------------------------
// Keypad
// -------------------------------------------------------------------------

static void cmd_keypad(const char *arg)
{
    if (!arg || strcmp(arg, "scan") != 0) {
        nucula_console_write("usage: keypad scan\r\n");
        nucula_console_write("  scan: probe each PCF8574 pin (P0-P6) and report which\r\n");
        nucula_console_write("        other pins go low. Press keys while scanning.\r\n");
        return;
    }

    nucula_console_write("keypad scan — press keys, each fires once per press (~30s)\r\n\r\n");

    int64_t deadline = esp_timer_get_time() + 30LL * 1000000;
    while (esp_timer_get_time() < deadline) {
        // Pull from the queue the background task fills — 200ms window per iteration
        char key = keypad_wait_event(200);
        if (key) {
            char line[32];
            snprintf(line, sizeof(line), "key: '%c'\r\n", key);
            nucula_console_write(line);
        }
    }
    nucula_console_write("scan done\r\n");
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

    // Bring up the interactive console FIRST, while heap is plentiful, so its
    // USB driver + line buffer always allocate. Command handlers tolerate the
    // wallets not being ready yet (they null-check wallet_store_get(i)). Initializing
    // it last starved it once WiFi + every wallet's keysets were loaded.
    console_init(NULL);
    console_register_cmd("status",  cmd_status,  "show system and wallet status");
    console_register_cmd("balance", cmd_balance,  "show wallet balance");
    console_register_cmd("receive", cmd_receive,  "receive a cashuA token");
    console_register_cmd("mint",    cmd_mint,     "mint [list|add <url>|remove <idx>]");
    console_register_cmd("nfc",     cmd_nfc,      "nfc [request <amount>|stop]");
    console_register_cmd("invoice", cmd_invoice,  "invoice <amount> [mint_idx]");
    console_register_cmd("claim",   cmd_claim,    "claim <quote_id> [mint_idx]");
    console_register_cmd("melt",    cmd_melt,     "melt <bolt11> [mint_idx]");
    console_register_cmd("stickup", cmd_stickup,  "drain wallet into v4 tokens");
    console_register_cmd("seed",    cmd_seed,     "seed [show|generate|restore|wipe]");
    console_register_cmd("keypad",  cmd_keypad,   "keypad scan — probe PCF8574 wiring");
    console_register_cmd("reboot",  cmd_reboot,   "restart the device");
    console_register_cmd("heap",    cmd_heap,     "show heap usage");
    console_register_cmd("tasks",   cmd_tasks,    "show task stack high-water marks");
    console_register_cmd("log",     cmd_log,      "log <e|w|i|d> [tag] — set log level");
    console_register_cmd("bench",   cmd_bench,    "benchmark crypto primitives");
    console_register_cmd("selftest", cmd_selftest, "run crypto/keyset self-tests");
    console_start();

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

#if CONFIG_NUCULA_SELFTEST_ON_BOOT
    crypto_run_tests(ctx);
    if (!cashu::keyset_run_tests())
        ESP_LOGE(TAG, "keyset id derivation self-test FAILED");
    if (!cashu::unit_run_tests())
        ESP_LOGE(TAG, "unit formatter self-test FAILED");
    if (!cashu::cashu_json_run_tests())
        ESP_LOGE(TAG, "quote/mint-info JSON self-test FAILED");
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

    // Drain task: while WiFi is connected, walk each wallet's pending queue
    // and try to swap the stashed offline-receive tokens. We can't drain just
    // once on the rising edge: DNS/routing is often not usable for the first
    // few seconds after GOT_IP, and a link that stays up never produces
    // another edge. So once connected we retry with an exponential backoff
    // until everything is redeemed (or the link drops), then re-arm on the
    // next reconnect.
    xTaskCreate([](void *) {
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
                    display_refresh();
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
    }, "wifi_drain", 8192, NULL, 4, NULL);

    // Shared I2C bus for display, keypad, and NFC. Each driver probes for
    // its device and disables itself when absent, so a bare module still
    // boots into a fully working console + wallet.
    if (i2c_bus_init() != ESP_OK)
        ESP_LOGW(TAG, "I2C bus init failed; display/keypad/NFC disabled");

    display_init(i2c_bus_get());

    if (keypad_init(i2c_bus_get()) == ESP_OK) {
        keypad_start_task();
        xTaskCreate(keypad_ui_task, "keypad_ui", 4096, NULL, 3, NULL);
    }

    if (!nfc_init(i2c_bus_get()))
        ESP_LOGW(TAG, "PN7160 init failed, NFC disabled");

    display_refresh();
}
