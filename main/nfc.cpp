#include "nfc.hpp"
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

#include "pn532.h"

#define TAG "nfc"

// Hardware SPI pins -- same as proven esp-nfc project (XIAO ESP32-C6 right header)
#define NFC_SPI_SCK    19
#define NFC_SPI_MISO   20
#define NFC_SPI_MOSI   18
#define NFC_SPI_SS     17
#define NFC_SPI_FREQ   1000000

#define PAYMENT_TIMEOUT_MS 120000

static pn532_handle_t s_pn532;
static bool s_hw_init = false;
static std::atomic<NfcState> s_state{NfcState::off};
static std::atomic<bool> s_stop_flag{false};
static TaskHandle_t s_task_handle = nullptr;

extern cashu::Wallet *g_wallets[];
extern secp256k1_context *g_ctx;
extern void display_refresh();
extern void display_nfc_status(const char *line1, const char *line2);

// -------------------------------------------------------------------------
// NDEF parsing + cashu token extraction
// -------------------------------------------------------------------------

static std::string extract_text_from_ndef(const uint8_t *data, size_t len)
{
    size_t offset = 0;
    while (offset < len) {
        uint8_t header = data[offset++];
        if (offset >= len) break;
        bool sr = (header & 0x10) != 0;
        uint8_t tnf = header & 0x07;
        uint8_t type_len = data[offset++];

        uint32_t payload_len;
        if (sr) {
            if (offset >= len) break;
            payload_len = data[offset++];
        } else {
            if (offset + 4 > len) break;
            payload_len = (data[offset] << 24) | (data[offset+1] << 16) |
                          (data[offset+2] << 8) | data[offset+3];
            offset += 4;
        }
        if (offset + type_len + payload_len > len) break;
        const uint8_t *type = &data[offset];
        offset += type_len;
        const uint8_t *payload = &data[offset];
        offset += payload_len;

        if (tnf == 0x01 && type_len == 1 && type[0] == 'T' && payload_len > 0) {
            uint8_t lang_len = payload[0] & 0x3F;
            if (payload_len > (uint32_t)(1 + lang_len))
                return std::string((const char *)&payload[1 + lang_len],
                                   payload_len - 1 - lang_len);
        }
        if (tnf == 0x01 && type_len == 1 && type[0] == 'U' && payload_len > 0) {
            static const char *pfx[] = {"","http://www.","https://www.","http://","https://"};
            uint8_t id = payload[0];
            const char *p = (id < 5) ? pfx[id] : "";
            return std::string(p) + std::string((const char *)&payload[1], payload_len - 1);
        }
        if (header & 0x40) break;
    }
    return "";
}

static std::string extract_cashu_token(const std::string &text)
{
    if (text.compare(0, 6, "cashuA") == 0 || text.compare(0, 6, "cashuB") == 0)
        return text;
    size_t pos = text.find("#token=cashu");
    if (pos != std::string::npos) return text.substr(pos + 7);
    pos = text.find("token=cashu");
    if (pos != std::string::npos) {
        size_t end = text.find_first_of("&#", pos + 6);
        return text.substr(pos + 6, end == std::string::npos ? end : end - pos - 6);
    }
    for (const char *pfx : {"cashuA", "cashuB"}) {
        pos = text.find(pfx);
        if (pos != std::string::npos) {
            size_t end = pos;
            while (end < text.size() && text[end] != ' ' && text[end] != '\t' &&
                   text[end] != '\n' && text[end] != '"' && text[end] != '<' &&
                   text[end] != '>' && text[end] != '&' && text[end] != '#') end++;
            return text.substr(pos, end - pos);
        }
    }
    return "";
}

// -------------------------------------------------------------------------
// Token redemption
// -------------------------------------------------------------------------

static cashu::Wallet *find_wallet_for(const char *mint_url)
{
    for (int i = 0; i < MAX_MINTS; i++)
        if (g_wallets[i] && g_wallets[i]->mint_url() == mint_url)
            return g_wallets[i];
    return nullptr;
}

static int find_free_slot()
{
    for (int i = 0; i < MAX_MINTS; i++)
        if (!g_wallets[i]) return i;
    return -1;
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
        ESP_LOGE(TAG, "failed to decode token");
        return false;
    }

    int input_total = 0;
    for (const auto &p : token.proofs) input_total += p.amount;
    ESP_LOGI(TAG, "token: %d sat, %d proofs from %s",
             input_total, (int)token.proofs.size(), token.mint.c_str());

    cashu::Wallet *w = find_wallet_for(token.mint.c_str());
    if (!w) {
        int slot = find_free_slot();
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
// Write callback from pn532_emulate_tag_loop
// -------------------------------------------------------------------------

static volatile bool s_token_received = false;
static std::string s_received_token;

static void on_ndef_written(const uint8_t *data, size_t len)
{
    ESP_LOGI(TAG, "NDEF written (%d bytes)", (int)len);

    std::string text = extract_text_from_ndef(data, len);
    if (text.empty()) {
        ESP_LOGW(TAG, "no text content in NDEF");
        return;
    }

    std::string token = extract_cashu_token(text);
    if (token.empty()) {
        ESP_LOGW(TAG, "no cashu token in: %.60s", text.c_str());
        return;
    }

    ESP_LOGI(TAG, "cashu token (%d chars)", (int)token.size());
    s_received_token = std::move(token);
    s_token_received = true;
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

    // Build payment request
    cashu::PaymentRequest req;
    req.amount = params->amount;
    req.unit = std::string("sat");
    req.single_use = true;
    if (!params->mint_url.empty())
        req.mints = std::vector<std::string>{params->mint_url};

    std::string creq = cashu::serialize_payment_request(req);
    ESP_LOGI(TAG, "creq: %s", creq.c_str());

    // Build NDEF text record
    ndef_text_record_t text_rec = {
        .language_code = "en",
        .text = creq.c_str(),
    };
    static uint8_t ndef_msg[4096];
    size_t ndef_len = 0;
    if (ndef_create_text_record(&text_rec, ndef_msg, sizeof(ndef_msg), &ndef_len) != ESP_OK) {
        ESP_LOGE(TAG, "NDEF record creation failed");
        s_state.store(NfcState::error);
        display_nfc_status("nfc error", "ndef too large");
        delete params;
        s_task_handle = nullptr;
        vTaskDelete(nullptr);
        return;
    }

    pn532_set_write_callback(on_ndef_written);
    int64_t start = esp_timer_get_time();
    char amt_str[16];
    snprintf(amt_str, sizeof(amt_str), "%d sat", params->amount);

    while (!s_stop_flag.load()) {
        if ((esp_timer_get_time() - start) > (int64_t)PAYMENT_TIMEOUT_MS * 1000) {
            ESP_LOGW(TAG, "timeout");
            s_state.store(NfcState::error);
            display_nfc_status("nfc timeout", "");
            break;
        }

        s_state.store(NfcState::waiting);
        s_token_received = false;
        display_nfc_status("tap to pay", amt_str);

        esp_err_t ret = pn532_emulate_tag_loop(&s_pn532, ndef_msg, ndef_len);

        if (ret == ESP_ERR_TIMEOUT) continue;
        if (ret == ESP_OK) s_state.store(NfcState::active);

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

        vTaskDelay(pdMS_TO_TICKS(50));
    }

    pn532_set_write_callback(nullptr);
    delete params;
    s_task_handle = nullptr;
    vTaskDelete(nullptr);
}

// -------------------------------------------------------------------------
// Public API
// -------------------------------------------------------------------------

bool nfc_init()
{
    pn532_spi_config_t spi_cfg = {
        .sck_gpio = NFC_SPI_SCK,
        .miso_gpio = NFC_SPI_MISO,
        .mosi_gpio = NFC_SPI_MOSI,
        .ss_gpio = NFC_SPI_SS,
        .clk_speed_hz = NFC_SPI_FREQ,
    };

    esp_err_t err = pn532_init_spi(&s_pn532, &spi_cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "PN532 SPI init failed: %s", esp_err_to_name(err));
        s_state.store(NfcState::off);
        return false;
    }

    pn532_firmware_version_t fw;
    err = pn532_get_firmware_version(&s_pn532, &fw);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "PN532 not responding");
        s_state.store(NfcState::off);
        return false;
    }

    err = pn532_sam_configuration(&s_pn532, PN532_SAM_NORMAL_MODE, 0x14, false);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "SAM config failed");
        s_state.store(NfcState::off);
        return false;
    }

    s_hw_init = true;
    s_state.store(NfcState::idle);
    ESP_LOGI(TAG, "PN532 ready");
    return true;
}

bool nfc_request_start(int amount, const char *mint_url)
{
    if (!s_hw_init) return false;
    if (s_task_handle) { ESP_LOGW(TAG, "already running"); return false; }

    auto *p = new NfcRequestParams();
    p->amount = amount;
    if (mint_url) p->mint_url = mint_url;

    s_stop_flag.store(false);
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
