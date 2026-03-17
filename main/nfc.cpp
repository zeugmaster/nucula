#include "nfc.hpp"
#include "ndef.hpp"
#include "cashu.hpp"
#include "cashu_json.hpp"
#include "cashu_cbor.hpp"
#include "wallet.hpp"
#include "display.h"
#include "wifi.h"

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

extern cashu::Wallet *g_wallets[];
extern secp256k1_context *g_ctx;
extern void display_refresh();
extern void display_nfc_status(const char *line1, const char *line2);

// -------------------------------------------------------------------------
// Token redemption (unchanged from PN532 version)
// -------------------------------------------------------------------------

static cashu::Wallet *find_wallet_for(const char *mint_url)
{
    for (int i = 0; i < MAX_MINTS; i++)
        if (g_wallets[i] && g_wallets[i]->mint_url() == mint_url)
            return g_wallets[i];
    return nullptr;
}

static bool redeem_token(const std::string &token_str)
{
    if (!wifi_is_connected()) {
        ESP_LOGE(TAG, "WiFi not connected");
        return false;
    }

    cashu::Token token;
    bool decoded = false;
    if (token_str.compare(0, 6, "cashuB") == 0)
        decoded = cashu::deserialize_token_v4(token_str.c_str(), token);
    else if (token_str.compare(0, 6, "cashuA") == 0)
        decoded = cashu::deserialize_token_v3(token_str.c_str(), token);

    if (!decoded) {
        ESP_LOGE(TAG, "token decode failed");
        return false;
    }

    int input_total = 0;
    for (const auto &p : token.proofs) input_total += p.amount;
    ESP_LOGI(TAG, "token: %d sat, %d proofs from %s",
             input_total, (int)token.proofs.size(), token.mint.c_str());

    cashu::Wallet *w = find_wallet_for(token.mint.c_str());
    if (!w) {
        int slot = -1;
        for (int i = 0; i < MAX_MINTS; i++) if (!g_wallets[i]) { slot = i; break; }
        if (slot < 0) { ESP_LOGE(TAG, "no free mint slots"); return false; }
        w = new cashu::Wallet(token.mint, g_ctx, slot);
        g_wallets[slot] = w;
        w->save_mint_url();
        ESP_LOGI(TAG, "added mint [%d]: %s", slot, token.mint.c_str());
    }

    if (w->keysets().empty() || !w->active_keyset()) {
        if (!w->load_keysets()) { ESP_LOGE(TAG, "keyset load failed"); return false; }
    }

    std::vector<cashu::Proof> received;
    if (!w->receive(token, received)) { ESP_LOGE(TAG, "swap failed"); return false; }

    int total = 0;
    for (const auto &p : received) total += p.amount;
    ESP_LOGI(TAG, "redeemed %d sat (%d proofs)", total, (int)received.size());
    return true;
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
    nci_write(&s_nci, stop, sizeof(stop));
    // Drain responses
    for (int i = 0; i < 10; i++) {
        if (nci_wait_for_irq(200)) {
            nci_read(&s_nci, s_nci.rx_buf, &s_nci.rx_len);
            if (s_nci.rx_buf[0] == 0x41 && s_nci.rx_buf[1] == 0x06) break;
        } else break;
    }
    nci_write(&s_nci, s_nci.discovery_cmd, s_nci.discovery_cmd_len);
    if (nci_wait_for_irq(200))
        nci_read(&s_nci, s_nci.rx_buf, &s_nci.rx_len);
}

// Send APDU response wrapped in NCI DATA packet
static void send_nci_response(const uint8_t *apdu, size_t apdu_len)
{
    static uint8_t frame[NCI_MAX_FRAME_SIZE];
    frame[0] = 0x00;
    frame[1] = (apdu_len >> 8) & 0xFF;
    frame[2] = apdu_len & 0xFF;
    if (apdu_len > 0)
        memcpy(&frame[3], apdu, apdu_len);
    nci_write(&s_nci, frame, 3 + apdu_len);
}

// -------------------------------------------------------------------------
// NFC task
// -------------------------------------------------------------------------

struct NfcRequestParams {
    int amount;
    std::string mint_url;
};

static void nfc_task(void *arg)
{
    auto *params = static_cast<NfcRequestParams *>(arg);

    // Build payment request and load into NDEF layer
    cashu::PaymentRequest req;
    req.amount     = params->amount;
    req.unit       = std::string("sat");
    req.single_use = true;
    if (!params->mint_url.empty())
        req.mints = std::vector<std::string>{params->mint_url};

    std::string creq = cashu::serialize_payment_request(req);
    ESP_LOGI(TAG, "creq: %s", creq.c_str());

    if (!ndef_set_message(creq.c_str())) {
        ESP_LOGE(TAG, "NDEF message too large");
        s_state.store(NfcState::error);
        display_nfc_status("nfc error", "ndef too large");
        delete params;
        s_task_handle = nullptr;
        vTaskDelete(nullptr);
        return;
    }

    ndef_set_receive_callback(on_ndef_written);

    int64_t start = esp_timer_get_time();
    char amt_str[16];
    snprintf(amt_str, sizeof(amt_str), "%d sat", params->amount);

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
            vTaskDelay(pdMS_TO_TICKS(1)); // brief yield after write

            // Check if a token arrived via the callback
            if (s_token_received) {
                s_state.store(NfcState::redeeming);
                display_nfc_status("redeeming...", amt_str);

                if (redeem_token(s_received_token)) {
                    s_state.store(NfcState::success);
                    display_nfc_status("paid!", amt_str);
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

    ndef_set_receive_callback(nullptr);
    ndef_clear_message();
    delete params;
    s_task_handle = nullptr;
    vTaskDelete(nullptr);
}

// -------------------------------------------------------------------------
// Public API
// -------------------------------------------------------------------------

bool nfc_init()
{
    memset(&s_nci, 0, sizeof(s_nci));

    int retries = 3;
    while (retries-- > 0) {
        if (nci_setup_cardemu(&s_nci) == ESP_OK) {
            s_hw_init = true;
            s_state.store(NfcState::idle);
            ESP_LOGI(TAG, "PN7160 ready");
            return true;
        }
        ESP_LOGW(TAG, "NCI setup failed, retrying... (%d left)", retries);
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    ESP_LOGE(TAG, "PN7160 not responding");
    s_state.store(NfcState::off);
    return false;
}

bool nfc_request_start(int amount, const char *mint_url)
{
    if (!s_hw_init) return false;
    if (s_task_handle) { ESP_LOGW(TAG, "already running"); return false; }

    auto *p = new NfcRequestParams();
    p->amount = amount;
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
        case NfcState::received:  return "received";
        case NfcState::redeeming: return "redeeming";
        case NfcState::success:   return "success";
        case NfcState::error:     return "error";
    }
    return "?";
}

i2c_master_bus_handle_t nfc_get_i2c_bus()
{
    return s_nci.i2c_bus;
}
