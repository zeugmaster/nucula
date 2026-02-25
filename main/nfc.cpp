#include "nfc.hpp"
#include "ndef.hpp"
#include "cashu.hpp"
#include "cashu_json.hpp"
#include "cashu_cbor.hpp"
#include "wallet.hpp"
#include "wifi.h"

#include <cstring>
#include <atomic>
#include <esp_log.h>
#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include "pn532.h"

#define TAG "nfc"

// PN532 pin assignments -- tries SPI first, then I2C
// SPI pins (display owns hardware SPI, so we bit-bang)
#define NFC_SPI_SCK    19
#define NFC_SPI_MISO   20
#define NFC_SPI_MOSI   18
#define NFC_SPI_SS     23
#define NFC_SPI_FREQ   1000000

// I2C pins (fallback if SPI fails -- module might have DIP switches set to I2C)
#define NFC_I2C_SDA    20
#define NFC_I2C_SCL    19
#define NFC_I2C_FREQ   100000
#define NFC_I2C_PORT   I2C_NUM_0

// RST pin -- hardware reset ensures PN532 is alive
#define NFC_RST_GPIO   3

#define PAYMENT_TIMEOUT_MS 60000

// -------------------------------------------------------------------------
// State
// -------------------------------------------------------------------------

static pn532_handle_t s_pn532;
static bool s_hw_init = false;

static std::atomic<NfcState> s_state{NfcState::off};
static std::atomic<bool> s_stop_flag{false};
static TaskHandle_t s_task_handle = nullptr;

extern cashu::Wallet *g_wallets[];
extern secp256k1_context *g_ctx;
extern void display_refresh();

// -------------------------------------------------------------------------
// Token processing (reused from previous implementation)
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
        if (!g_wallets[i])
            return i;
    return -1;
}

static bool process_received_token(const std::string &token_str)
{
    if (!wifi_is_connected()) {
        ESP_LOGE(TAG, "WiFi not connected, cannot redeem token");
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
    for (const auto &p : token.proofs)
        input_total += p.amount;
    ESP_LOGI(TAG, "token: %d sat in %d proofs from %s",
             input_total, (int)token.proofs.size(), token.mint.c_str());

    cashu::Wallet *w = find_wallet_for(token.mint.c_str());
    if (!w) {
        int slot = find_free_slot();
        if (slot < 0) {
            ESP_LOGE(TAG, "max %d mints reached", MAX_MINTS);
            return false;
        }
        w = new cashu::Wallet(token.mint, g_ctx, slot);
        g_wallets[slot] = w;
        w->save_mint_url();
        ESP_LOGI(TAG, "added mint [%d]: %s", slot, token.mint.c_str());
    }

    if (w->keysets().empty() || !w->active_keyset()) {
        ESP_LOGI(TAG, "loading keysets...");
        if (!w->load_keysets()) {
            ESP_LOGE(TAG, "failed to load keysets");
            return false;
        }
    }

    std::vector<cashu::Proof> received;
    if (!w->receive(token, received)) {
        ESP_LOGE(TAG, "receive (swap) failed");
        return false;
    }

    int output_total = 0;
    for (const auto &p : received)
        output_total += p.amount;
    ESP_LOGI(TAG, "received %d sat in %d proofs", output_total, (int)received.size());
    return true;
}

// -------------------------------------------------------------------------
// Write callback -- invoked by pn532_emulate_tag_loop when NDEF is written
// -------------------------------------------------------------------------

static volatile bool s_token_received = false;
static std::string s_received_token;

static void on_ndef_written(const uint8_t *data, size_t len)
{
    ESP_LOGI(TAG, "NDEF written (%d bytes), extracting token...", (int)len);

    // Parse the raw NDEF record bytes to extract text/URI content
    // The data here is the NDEF record (without the 2-byte NLEN prefix)
    // We need to prepend a dummy NLEN to use our parser
    std::string text;

    // Try to parse as NDEF records directly
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

        // Text record
        if (tnf == 0x01 && type_len == 1 && type[0] == 'T' && payload_len > 0) {
            uint8_t lang_len = payload[0] & 0x3F;
            if (payload_len > (uint32_t)(1 + lang_len)) {
                text.assign((const char *)&payload[1 + lang_len],
                            payload_len - 1 - lang_len);
            }
            break;
        }
        // URI record
        if (tnf == 0x01 && type_len == 1 && type[0] == 'U' && payload_len > 0) {
            static const char *prefixes[] = {
                "", "http://www.", "https://www.", "http://", "https://"
            };
            uint8_t id = payload[0];
            const char *pfx = (id < 5) ? prefixes[id] : "";
            text = std::string(pfx) +
                   std::string((const char *)&payload[1], payload_len - 1);
            break;
        }

        if (header & 0x40) break; // ME flag
    }

    if (text.empty()) {
        ESP_LOGW(TAG, "no text/URI content found in NDEF write");
        return;
    }

    std::string token = ndef_extract_cashu_token(text);
    if (token.empty()) {
        ESP_LOGW(TAG, "no cashu token found in: %.40s...", text.c_str());
        return;
    }

    ESP_LOGI(TAG, "cashu token extracted (%d chars)", (int)token.size());
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
    ESP_LOGI(TAG, "payment request: %s (%d chars)", creq.c_str(), (int)creq.size());

    // Build NDEF Text record for the payment request
    ndef_text_record_t text_rec = {
        .language_code = "en",
        .text = creq.c_str(),
    };
    uint8_t ndef_msg[1024];
    size_t ndef_len = 0;
    esp_err_t ret = ndef_create_text_record(&text_rec, ndef_msg, sizeof(ndef_msg), &ndef_len);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "failed to create NDEF record");
        s_state.store(NfcState::error);
        delete params;
        s_task_handle = nullptr;
        vTaskDelete(nullptr);
        return;
    }

    // Register write callback
    pn532_set_write_callback(on_ndef_written);

    int64_t start_time = esp_timer_get_time();

    while (!s_stop_flag.load()) {
        if ((esp_timer_get_time() - start_time) > (int64_t)PAYMENT_TIMEOUT_MS * 1000) {
            ESP_LOGW(TAG, "payment request timeout");
            s_state.store(NfcState::error);
            break;
        }

        s_state.store(NfcState::waiting);
        s_token_received = false;

        ret = pn532_emulate_tag_loop(&s_pn532, ndef_msg, ndef_len);

        if (ret == ESP_ERR_TIMEOUT) {
            continue; // No reader, try again
        }

        if (ret == ESP_OK) {
            ESP_LOGI(TAG, "tag cycle complete");
            s_state.store(NfcState::active);
        }

        if (s_token_received) {
            ESP_LOGI(TAG, "processing token...");
            s_state.store(NfcState::received);

            if (process_received_token(s_received_token)) {
                ESP_LOGI(TAG, "payment successful!");
                s_state.store(NfcState::success);
                display_refresh();
            } else {
                ESP_LOGE(TAG, "token redemption failed");
                s_state.store(NfcState::error);
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

static bool try_firmware_version(const char *transport_name)
{
    pn532_firmware_version_t fw;
    for (int attempt = 0; attempt < 3; attempt++) {
        esp_err_t err = pn532_get_firmware_version(&s_pn532, &fw);
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "PN532 found via %s", transport_name);
            return true;
        }
        ESP_LOGW(TAG, "%s firmware version attempt %d: %s",
                 transport_name, attempt + 1, esp_err_to_name(err));
        vTaskDelay(pdMS_TO_TICKS(200));
    }
    return false;
}

bool nfc_init()
{
    // Hardware reset: drive RST LOW then HIGH to ensure PN532 is in a clean state
    gpio_config_t rst_cfg = {
        .pin_bit_mask = (1ULL << NFC_RST_GPIO),
        .mode = GPIO_MODE_OUTPUT,
    };
    gpio_config(&rst_cfg);
    gpio_set_level((gpio_num_t)NFC_RST_GPIO, 0);
    vTaskDelay(pdMS_TO_TICKS(100));
    gpio_set_level((gpio_num_t)NFC_RST_GPIO, 1);
    vTaskDelay(pdMS_TO_TICKS(500)); // PN532 needs ~400ms after reset
    ESP_LOGI(TAG, "PN532 hardware reset complete (RST=GPIO%d)", NFC_RST_GPIO);

    bool found = false;

    // --- Try SPI first ---
    ESP_LOGI(TAG, "Trying SPI (SCK=%d MOSI=%d MISO=%d SS=%d)...",
             NFC_SPI_SCK, NFC_SPI_MOSI, NFC_SPI_MISO, NFC_SPI_SS);
    {
        pn532_spi_config_t spi_cfg = {
            .sck_gpio = NFC_SPI_SCK,
            .miso_gpio = NFC_SPI_MISO,
            .mosi_gpio = NFC_SPI_MOSI,
            .ss_gpio = NFC_SPI_SS,
            .clk_speed_hz = NFC_SPI_FREQ,
        };
        if (pn532_init_spi(&s_pn532, &spi_cfg) == ESP_OK) {
            found = try_firmware_version("SPI");
            if (!found)
                pn532_spi_deinit(&s_pn532);
        }
    }

    // --- Try I2C if SPI failed ---
    if (!found) {
        ESP_LOGI(TAG, "SPI failed. Trying I2C (SDA=%d SCL=%d)...",
                 NFC_I2C_SDA, NFC_I2C_SCL);

        // Reset GPIO pins from SPI config before I2C takes over
        gpio_reset_pin((gpio_num_t)NFC_SPI_SCK);
        gpio_reset_pin((gpio_num_t)NFC_SPI_MISO);
        gpio_reset_pin((gpio_num_t)NFC_SPI_MOSI);
        gpio_reset_pin((gpio_num_t)NFC_SPI_SS);

        // Hardware reset again to ensure clean state for I2C
        gpio_set_level((gpio_num_t)NFC_RST_GPIO, 0);
        vTaskDelay(pdMS_TO_TICKS(100));
        gpio_set_level((gpio_num_t)NFC_RST_GPIO, 1);
        vTaskDelay(pdMS_TO_TICKS(500));

        pn532_i2c_config_t i2c_cfg = {
            .sda_gpio = NFC_I2C_SDA,
            .scl_gpio = NFC_I2C_SCL,
            .clk_speed_hz = NFC_I2C_FREQ,
            .i2c_port = NFC_I2C_PORT,
        };
        esp_err_t i2c_err = pn532_init(&s_pn532, &i2c_cfg);
        if (i2c_err == ESP_OK) {
            found = try_firmware_version("I2C");
            if (!found)
                pn532_i2c_deinit(&s_pn532);
        } else {
            ESP_LOGE(TAG, "I2C init failed: %s", esp_err_to_name(i2c_err));
        }
    }

    if (!found) {
        ESP_LOGE(TAG, "PN532 not found on SPI or I2C - check wiring");
        s_state.store(NfcState::off);
        return false;
    }

    esp_err_t err = pn532_sam_configuration(&s_pn532, PN532_SAM_NORMAL_MODE, 0x14, false);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "SAM config failed");
        s_state.store(NfcState::off);
        return false;
    }

    s_hw_init = true;
    s_state.store(NfcState::idle);
    return true;
}

bool nfc_request_start(int amount, const char *mint_url)
{
    if (!s_hw_init) {
        ESP_LOGE(TAG, "PN532 not initialized");
        return false;
    }
    if (s_task_handle) {
        ESP_LOGW(TAG, "NFC task already running");
        return false;
    }

    auto *params = new NfcRequestParams();
    params->amount = amount;
    if (mint_url)
        params->mint_url = mint_url;

    s_stop_flag.store(false);
    s_state.store(NfcState::waiting);

    BaseType_t ret = xTaskCreate(nfc_task, "nfc", 8192, params, 5, &s_task_handle);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "failed to create NFC task");
        delete params;
        s_state.store(NfcState::error);
        return false;
    }

    return true;
}

void nfc_request_stop()
{
    s_stop_flag.store(true);
    for (int i = 0; i < 30 && s_task_handle; i++)
        vTaskDelay(pdMS_TO_TICKS(100));

    if (s_task_handle) {
        ESP_LOGW(TAG, "NFC task did not exit cleanly");
        s_task_handle = nullptr;
    }

    s_state.store(s_hw_init ? NfcState::idle : NfcState::off);
}

NfcState nfc_state()
{
    return s_state.load();
}

const char *nfc_status_str()
{
    switch (s_state.load()) {
        case NfcState::off:      return "off";
        case NfcState::idle:     return "idle";
        case NfcState::waiting:  return "waiting...";
        case NfcState::active:   return "reading...";
        case NfcState::received: return "received";
        case NfcState::success:  return "success";
        case NfcState::error:    return "error";
    }
    return "?";
}
