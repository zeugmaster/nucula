#include "nfc.hpp"
#include "ndef.hpp"
#include "cashu.hpp"
#include "cashu_json.hpp"
#include "cashu_cbor.hpp"
#include "wallet.hpp"
#include "wallet_store.hpp"
#include "unit.hpp"
#include "ui.h"
#include "wifi.h"
#include "http.h"

#include <cstring>
#include <string>
#include <atomic>
#include <esp_log.h>
#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include "nci.h"

#define TAG "nfc"

#define PAYMENT_TIMEOUT_MS 120000

static nci_context_t s_nci;
static bool s_hw_init = false;
static std::atomic<NfcState> s_state{NfcState::off};
static std::atomic<bool> s_stop_flag{false};
static TaskHandle_t s_task_handle = nullptr;

// -------------------------------------------------------------------------
// Token redemption
// -------------------------------------------------------------------------

// Returns:
//   1  on online success (swapped immediately)
//   0  on offline success (stashed for later drain)
//  -1  on failure
// `expected_unit` is what our NUT-18 request asked for — a different unit
// is accepted (receive() enforces internal consistency) but logged.
// `desc`/`desc_len` receive the formatted received amount for the display.
static int redeem_or_stash_token(const std::string &token_str,
                                 const char *expected_unit,
                                 char *desc, size_t desc_len)
{
    // Hold the store for the whole redeem/stash: the wallet pointer must
    // stay valid across the swap, and stickup/mint-remove must not
    // interleave with an in-flight redemption.
    wallet_store_guard guard;

    cashu::Token token;
    if (!cashu::deserialize_token(token_str.c_str(), token)) {
        ESP_LOGE(TAG, "token decode failed");
        return -1;
    }

    long long input_total = cashu::proofs_sum(token.proofs);
    char amt[32];
    cashu::format_amount(amt, sizeof(amt), input_total, token.unit.c_str());
    ESP_LOGI(TAG, "token: %s, %d proofs from %s",
             amt, (int)token.proofs.size(), token.mint.c_str());
    if (desc && desc_len)
        snprintf(desc, desc_len, "%s", amt);

    if (expected_unit && expected_unit[0] && token.unit != expected_unit)
        ESP_LOGW(TAG, "payer sent %s, request asked for %s — accepting",
                 token.unit.c_str(), expected_unit);

    if (!wifi_is_connected()) {
        // Offline: only accept a token from a mint we already hold keysets
        // for. Verifying the proofs' DLEQ (NUT-12) requires that mint's
        // public keys; without them a forged token is indistinguishable from
        // real ecash, and there is no online swap to fall back on. Refuse —
        // and do NOT create a new mint slot for an unknown mint.
        cashu::Wallet *w = wallet_store_find(token.mint.c_str());
        if (!w || w->keysets().empty()) {
            ESP_LOGE(TAG, "offline: refusing token from unknown mint %s "
                          "(no keysets, cannot verify DLEQ)",
                     token.mint.c_str());
            return -1;
        }
        if (!w->stash_pending_token(token_str)) {
            ESP_LOGE(TAG, "pending: stash failed");
            return -1;
        }
        ESP_LOGI(TAG, "offline: stashed %s for later drain", amt);
        return 0;
    }

    cashu::Wallet *w = wallet_store_get_or_create(token.mint);
    if (!w) return -1;

    if (w->keysets().empty() || !w->active_keyset(token.unit)) {
        if (!w->load_keysets()) { ESP_LOGE(TAG, "keyset load failed"); return -1; }
    }

    std::vector<cashu::Proof> received;
    if (!w->receive(token, received)) { ESP_LOGE(TAG, "swap failed"); return -1; }

    cashu::format_amount(amt, sizeof(amt),
                         cashu::proofs_sum(received), token.unit.c_str());
    if (desc && desc_len)
        snprintf(desc, desc_len, "%s", amt);
    ESP_LOGI(TAG, "redeemed %s (%d proofs)", amt, (int)received.size());
    return 1;
}

// -------------------------------------------------------------------------
// NDEF write callback
// -------------------------------------------------------------------------

static volatile bool s_token_received = false;
static std::string   s_received_token;

static void on_ndef_written(const uint8_t *data, size_t len)
{
    ESP_LOGI(TAG, "NDEF written (%d bytes)", (int)len);

    std::string text;
    if (!ndef_parse_message(data, len, text)) {
        ESP_LOGW(TAG, "NDEF parse failed");
        return;
    }

    std::string token = ndef_extract_cashu_token(text);
    if (token.empty()) {
        ESP_LOGW(TAG, "no cashu token in: %.60s", text.c_str());
        return;
    }

    ESP_LOGI(TAG, "cashu token (%d chars)", (int)token.size());
    s_received_token = std::move(token);
    s_token_received = true;
}

// -------------------------------------------------------------------------
// NCI helpers
// -------------------------------------------------------------------------

// Stop and restart RF discovery (called after reader deactivates)
static void restart_discovery()
{
    const uint8_t stop[] = {0x21, 0x06, 0x01, 0x00};
    if (nci_write(&s_nci, stop, sizeof(stop)) != ESP_OK) {
        ESP_LOGW(TAG, "restart discovery: deactivate write failed");
        return;
    }
    // Drain responses
    for (int i = 0; i < 10; i++) {
        if (nci_wait_for_irq(200)) {
            if (nci_read(&s_nci, s_nci.rx_buf, &s_nci.rx_len) != ESP_OK)
                break;
            if (s_nci.rx_buf[0] == 0x41 && s_nci.rx_buf[1] == 0x06) break;
        } else break;
    }
    if (nci_write(&s_nci, s_nci.discovery_cmd, s_nci.discovery_cmd_len) != ESP_OK) {
        ESP_LOGW(TAG, "restart discovery: discover write failed");
        return;
    }
    if (nci_wait_for_irq(200))
        nci_read(&s_nci, s_nci.rx_buf, &s_nci.rx_len);
}

// Send APDU response wrapped in NCI DATA packet
static void send_nci_response(const uint8_t *apdu, size_t apdu_len)
{
    static uint8_t frame[NCI_MAX_FRAME_SIZE];
    if (apdu_len > sizeof(frame) - 3) {
        ESP_LOGE(TAG, "APDU response too large (%d)", (int)apdu_len);
        return;
    }
    frame[0] = 0x00;
    frame[1] = (apdu_len >> 8) & 0xFF;
    frame[2] = apdu_len & 0xFF;
    if (apdu_len > 0)
        memcpy(&frame[3], apdu, apdu_len);
    if (nci_write(&s_nci, frame, 3 + apdu_len) != ESP_OK)
        ESP_LOGW(TAG, "APDU response write failed");
}

// -------------------------------------------------------------------------
// NFC task
// -------------------------------------------------------------------------

struct NfcRequestParams {
    int amount;
    std::string unit;
    std::string mint_url;
};

static void nfc_task(void *arg)
{
    auto *params = static_cast<NfcRequestParams *>(arg);

    // Build payment request and load into NDEF layer. NUT-18: `u` MUST be
    // set when an amount is set.
    cashu::PaymentRequest req;
    req.amount     = params->amount;
    req.unit       = params->unit;
    req.single_use = true;
    if (!params->mint_url.empty())
        req.mints = std::vector<std::string>{params->mint_url};

    // Offline-receive: ask the sender to lock the proofs to our P2PK pubkey
    // so we can swap them once WiFi returns. Online we skip the lock for
    // privacy (single static key would link receives).
    if (!wifi_is_connected() && cashu::Wallet::ensure_p2pk_keypair(wallet_store_ctx())) {
        cashu::NUT10Option opt;
        opt.kind = "P2PK";
        opt.data = cashu::Wallet::p2pk_pubkey_hex();
        req.nut10 = std::move(opt);
        ESP_LOGI(TAG, "offline: requesting P2PK lock to %s",
                 cashu::Wallet::p2pk_pubkey_hex());
    }

    std::string creq = cashu::serialize_payment_request(req);
    ESP_LOGI(TAG, "creq: %s", creq.c_str());

    if (creq.empty() || !ndef_set_message(creq.c_str())) {
        ESP_LOGE(TAG, "payment request encode/NDEF failed");
        s_state.store(NfcState::error);
        display_nfc_status("nfc error", "request too large");
        delete params;
        s_task_handle = nullptr;
        vTaskDelete(nullptr);
        return;
    }

    ndef_set_receive_callback(on_ndef_written);

    // Full radio responsiveness while a payment is in flight; restored on
    // every exit path below.
    wifi_set_low_latency(true);

    // Prime the TLS connection to the expected mint while the user is
    // still tapping: the post-tap swap then reuses it.
    if (wifi_is_connected()) {
        if (!params->mint_url.empty()) {
            http_prewarm(params->mint_url.c_str());
        } else {
            wallet_store_guard guard;
            for (int i = 0; i < MAX_MINTS; i++) {
                auto *w = wallet_store_get(i);
                if (w) { http_prewarm(w->mint_url().c_str()); break; }
            }
        }
    }

    int64_t start = esp_timer_get_time();
    char amt_str[24];
    cashu::format_amount(amt_str, sizeof(amt_str), params->amount,
                         params->unit.c_str());

    s_state.store(NfcState::waiting);
    display_nfc_status("tap to pay", amt_str);

    while (!s_stop_flag.load()) {
        // Timeout check
        if ((esp_timer_get_time() - start) > (int64_t)PAYMENT_TIMEOUT_MS * 1000) {
            ESP_LOGW(TAG, "payment timeout");
            s_state.store(NfcState::error);
            display_nfc_status("nfc timeout", "");
            break;
        }

        // Poll IRQ with 100 ms window so we can also check stop flag / timeout
        if (!nci_wait_for_irq(100)) continue;

        s_nci.rx_len = 0;
        if (nci_read(&s_nci, s_nci.rx_buf, &s_nci.rx_len) != ESP_OK || s_nci.rx_len == 0)
            continue;

        uint8_t mt  = s_nci.rx_buf[0];
        uint8_t oid = s_nci.rx_buf[1];

        // Credits NTF — flow control, ignore
        if (mt == 0x60 && oid == 0x06) continue;

        // RF_INTF_ACTIVATED_NTF — reader detected
        if (mt == 0x61 && oid == 0x05) {
            ESP_LOGI(TAG, "reader detected");
            s_state.store(NfcState::active);
            ndef_reset_receive();
            continue;
        }

        // RF_DEACTIVATE_NTF — reader removed
        if (mt == 0x61 && oid == 0x06) {
            uint8_t dtype = s_nci.rx_len > 3 ? s_nci.rx_buf[3] : 0xFF;
            ESP_LOGI(TAG, "reader removed (type=%d)", dtype);
            if (dtype != 3) restart_discovery();
            ndef_reset_receive();
            if (!s_token_received) {
                s_state.store(NfcState::waiting);
                display_nfc_status("tap to pay", amt_str);
            }
            continue;
        }

        // DATA packet — APDU from reader
        if (mt == 0x00 && oid == 0x00) {
            uint8_t apdu_len = s_nci.rx_buf[2];
            static uint8_t rsp_buf[NCI_MAX_FRAME_SIZE];
            size_t rsp_len = 0;

            ndef_handle_apdu(&s_nci.rx_buf[3], apdu_len, rsp_buf, &rsp_len);
            send_nci_response(rsp_buf, rsp_len);

            // Check if a token arrived via the callback
            if (s_token_received) {
                s_state.store(NfcState::redeeming);
                display_nfc_status("redeeming...", amt_str);

                // Show what was actually received (unit may differ from
                // the request); fall back to the requested amount.
                char recv_str[32];
                snprintf(recv_str, sizeof(recv_str), "%s", amt_str);
                int rc = redeem_or_stash_token(s_received_token,
                                               params->unit.c_str(),
                                               recv_str, sizeof(recv_str));
                if (rc == 1) {
                    s_state.store(NfcState::success);
                    display_nfc_status("paid!", recv_str);
                    display_refresh();
                } else if (rc == 0) {
                    s_state.store(NfcState::success);
                    display_nfc_status("queued", recv_str);
                    display_refresh();
                } else {
                    s_state.store(NfcState::error);
                    display_nfc_status("redeem failed", "");
                }
                break;
            }
            continue;
        }

        // Discovery RSP / NTF after restart — ignore
        if ((mt == 0x41 && oid == 0x03) ||
            (mt == 0x61 && oid == 0x03) ||
            (mt == 0x60 && oid == 0x07) ||
            (mt == 0x60 && oid == 0x08)) continue;

        ESP_LOGD(TAG, "unhandled NCI: %02X %02X", mt, oid);
    }

    wifi_set_low_latency(false);
    ndef_set_receive_callback(nullptr);
    ndef_clear_message();
    delete params;
    s_task_handle = nullptr;
    vTaskDelete(nullptr);
}

// -------------------------------------------------------------------------
// Public API
// -------------------------------------------------------------------------

bool nfc_init(i2c_master_bus_handle_t bus)
{
    ndef_init();
    memset(&s_nci, 0, sizeof(s_nci));

    int retries = 3;
    while (retries-- > 0) {
        esp_err_t err = nci_setup_cardemu(&s_nci, bus);
        if (err == ESP_OK) {
            s_hw_init = true;
            s_state.store(NfcState::idle);
            ESP_LOGI(TAG, "PN7160 ready");
            return true;
        }
        if (err == ESP_ERR_NOT_FOUND || err == ESP_ERR_INVALID_ARG) {
            // Chip absent (or no bus) — retrying won't make it appear.
            break;
        }
        ESP_LOGW(TAG, "NCI setup failed, retrying... (%d left)", retries);
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    ESP_LOGW(TAG, "PN7160 unavailable, NFC disabled");
    s_state.store(NfcState::off);
    return false;
}

bool nfc_request_start(int amount, const char *unit, const char *mint_url)
{
    if (!s_hw_init) return false;
    if (s_task_handle) { ESP_LOGW(TAG, "already running"); return false; }

    auto *p = new NfcRequestParams();
    p->amount = amount;
    p->unit = (unit && unit[0]) ? unit : cashu::Wallet::default_unit();
    if (mint_url) p->mint_url = mint_url;

    s_stop_flag.store(false);
    s_token_received = false;
    if (xTaskCreate(nfc_task, "nfc", 16384, p, 5, &s_task_handle) != pdPASS) {
        delete p;
        return false;
    }
    return true;
}

void nfc_request_stop()
{
    s_stop_flag.store(true);
    for (int i = 0; i < 50 && s_task_handle; i++)
        vTaskDelay(pdMS_TO_TICKS(100));
    s_task_handle = nullptr;
    s_state.store(s_hw_init ? NfcState::idle : NfcState::off);
}

NfcState nfc_state() { return s_state.load(); }

const char *nfc_status_str()
{
    switch (s_state.load()) {
        case NfcState::off:       return "off";
        case NfcState::idle:      return "idle";
        case NfcState::waiting:   return "waiting";
        case NfcState::active:    return "active";
        case NfcState::redeeming: return "redeeming";
        case NfcState::success:   return "success";
        case NfcState::error:     return "error";
    }
    return "?";
}
