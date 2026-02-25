/**
 * @file pn532.c
 * @brief PN532 NFC Controller Driver - Tag Emulation Mode
 * 
 * Implements NFC Forum Type 4 Tag emulation with NDEF support.
 * Optimized for iOS compatibility.
 */

#include "pn532.h"
#include "esp_log.h"
#include "esp_rom_sys.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>

static const char *TAG = "PN532";

// ==================== Type 4 Tag Constants ====================

// Capability Container - matches Numo POS HCE protocol
static const uint8_t capability_container[] = {
    0x00, 0x0F,             // CCLEN (15 bytes)
    0x20,                   // Mapping Version 2.0
    0x00, 0x3B,             // MLe (max R-APDU data = 59 bytes)
    0x00, 0x34,             // MLc (max C-APDU data = 52 bytes)
    0x04,                   // NDEF File Control TLV - Type
    0x06,                   // NDEF File Control TLV - Length
    0xE1, 0x04,             // NDEF File ID
    0x70, 0xFF,             // Max NDEF size (28,671 bytes)
    0x00,                   // Read access: granted
    0x00,                   // Write access: granted
};

// Callback for when NDEF data is written
static void (*ndef_write_callback)(const uint8_t *data, size_t len) = NULL;

// NDEF Application ID (D2760000850101)
static const uint8_t ndef_aid[] = {0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01};
static const uint8_t cc_file_id[] = {0xE1, 0x03};
static const uint8_t ndef_file_id[] = {0xE1, 0x04};

// Tag emulation state machine
typedef enum {
    TAG_STATE_IDLE,
    TAG_STATE_APP_SELECTED,
    TAG_STATE_CC_SELECTED,
    TAG_STATE_NDEF_SELECTED,
} tag_state_t;

// ==================== Helper Functions ====================

static uint8_t calculate_dcs(const uint8_t *data, size_t len)
{
    uint8_t sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum += data[i];
    }
    return (~sum) + 1;
}

static esp_err_t build_command_frame(pn532_handle_t *handle, uint8_t cmd, 
                                      const uint8_t *params, size_t params_len,
                                      size_t *frame_len)
{
    uint8_t *buf = handle->command_buffer;
    size_t data_len = 2 + params_len;

    buf[0] = PN532_PREAMBLE;
    buf[1] = PN532_STARTCODE1;
    buf[2] = PN532_STARTCODE2;
    buf[3] = data_len;
    buf[4] = (~data_len) + 1;
    buf[5] = PN532_HOSTTOPN532;
    buf[6] = cmd;

    if (params && params_len > 0) {
        memcpy(&buf[7], params, params_len);
    }

    buf[7 + params_len] = calculate_dcs(&buf[5], data_len);
    buf[8 + params_len] = PN532_POSTAMBLE;

    *frame_len = 9 + params_len;
    return ESP_OK;
}

static void build_rapdu(uint8_t *buf, size_t *len, const uint8_t *data, size_t data_len, 
                        uint8_t sw1, uint8_t sw2)
{
    if (data && data_len > 0) {
        memcpy(buf, data, data_len);
    }
    buf[data_len] = sw1;
    buf[data_len + 1] = sw2;
    *len = data_len + 2;
}

// ==================== Core Functions ====================

esp_err_t pn532_init_spi(pn532_handle_t *handle, const pn532_spi_config_t *config)
{
    if (handle == NULL || config == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(handle, 0, sizeof(pn532_handle_t));

    esp_err_t ret = pn532_spi_init(handle, config);
    if (ret != ESP_OK) {
        return ret;
    }

    vTaskDelay(pdMS_TO_TICKS(100));

    ret = pn532_spi_wakeup(handle);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "PN532 wakeup failed");
        pn532_spi_deinit(handle);
        return ret;
    }

    vTaskDelay(pdMS_TO_TICKS(50));
    
    ESP_LOGI(TAG, "PN532 initialized (SPI)");
    return ESP_OK;
}

esp_err_t pn532_init(pn532_handle_t *handle, const pn532_i2c_config_t *config)
{
    if (handle == NULL || config == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(handle, 0, sizeof(pn532_handle_t));

    esp_err_t ret = pn532_i2c_init(handle, config);
    if (ret != ESP_OK) {
        return ret;
    }

    vTaskDelay(pdMS_TO_TICKS(50));

    uint8_t wakeup[] = {0x55, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    ret = pn532_i2c_write_command(handle, wakeup, sizeof(wakeup));
    if (ret != ESP_OK) {
        pn532_i2c_deinit(handle);
        return ret;
    }
    
    vTaskDelay(pdMS_TO_TICKS(50));
    ESP_LOGI(TAG, "PN532 initialized (I2C)");
    return ESP_OK;
}

esp_err_t pn532_init_uart(pn532_handle_t *handle, const pn532_uart_config_t *config)
{
    if (handle == NULL || config == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(handle, 0, sizeof(pn532_handle_t));

    esp_err_t ret = pn532_uart_init(handle, config->tx_gpio, config->rx_gpio, config->baud_rate);
    if (ret != ESP_OK) {
        return ret;
    }

    vTaskDelay(pdMS_TO_TICKS(50));

    ret = pn532_uart_wakeup(handle);
    if (ret != ESP_OK) {
        pn532_uart_deinit(handle);
        return ret;
    }

    vTaskDelay(pdMS_TO_TICKS(50));
    ESP_LOGI(TAG, "PN532 initialized (UART)");
    return ESP_OK;
}

esp_err_t pn532_deinit(pn532_handle_t *handle)
{
    if (handle == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    switch (handle->transport) {
        case PN532_TRANSPORT_SPI:
            return pn532_spi_deinit(handle);
        case PN532_TRANSPORT_UART:
            return pn532_uart_deinit(handle);
        case PN532_TRANSPORT_I2C:
        default:
            return pn532_i2c_deinit(handle);
    }
}

esp_err_t pn532_send_command(pn532_handle_t *handle, uint8_t cmd, 
                              const uint8_t *params, size_t params_len,
                              uint8_t *response, size_t *response_len,
                              uint32_t timeout_ms)
{
    if (handle == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t ret;
    size_t frame_len;

    if (handle->transport == PN532_TRANSPORT_UART) {
        ret = pn532_uart_write_command(handle, cmd, params, params_len);
        if (ret != ESP_OK) return ret;

        if (response && response_len && *response_len > 0) {
            size_t buffer_len = PN532_MAX_FRAME_LEN;
            ret = pn532_uart_read_response(handle, handle->response_buffer, &buffer_len, timeout_ms);
            if (ret != ESP_OK) return ret;
            
            size_t copy_len = (buffer_len <= *response_len) ? buffer_len : *response_len;
            memcpy(response, handle->response_buffer, copy_len);
            *response_len = buffer_len;
        }
    } else if (handle->transport == PN532_TRANSPORT_SPI) {
        ret = build_command_frame(handle, cmd, params, params_len, &frame_len);
        if (ret != ESP_OK) return ret;

        ret = pn532_spi_write_command(handle, handle->command_buffer, frame_len);
        if (ret != ESP_OK) return ret;

        // Quick wait then read ACK - don't wait too long
        pn532_spi_wait_ready(handle, 50);
        
        ret = pn532_spi_read_ack(handle);
        if (ret != ESP_OK) {
            ESP_LOGD(TAG, "No ACK for cmd 0x%02X", cmd);
            return ret;
        }

        if (response && response_len && *response_len > 0) {
            size_t buffer_len = PN532_MAX_FRAME_LEN;
            ret = pn532_spi_read_response(handle, handle->response_buffer, &buffer_len, timeout_ms);
            if (ret != ESP_OK) return ret;

            if (handle->response_buffer[0] != PN532_PN532TOHOST ||
                handle->response_buffer[1] != (cmd + 1)) {
                return ESP_ERR_INVALID_RESPONSE;
            }

            size_t data_len = buffer_len - 2;
            if (data_len > 0) {
                memcpy(response, &handle->response_buffer[2], data_len);
            }
            *response_len = data_len;
        }
    } else {
        // I2C transport
        ret = build_command_frame(handle, cmd, params, params_len, &frame_len);
        if (ret != ESP_OK) return ret;

        ret = pn532_i2c_write_command(handle, handle->command_buffer, frame_len);
        if (ret != ESP_OK) return ret;

        vTaskDelay(pdMS_TO_TICKS(10));

        ret = pn532_i2c_read_ack(handle);
        if (ret != ESP_OK) return ret;

        if (response && response_len && *response_len > 0) {
            size_t buffer_len = PN532_MAX_FRAME_LEN;
            ret = pn532_i2c_read_response(handle, handle->response_buffer, &buffer_len, timeout_ms);
            if (ret != ESP_OK) return ret;

            if (handle->response_buffer[0] != PN532_PN532TOHOST ||
                handle->response_buffer[1] != (cmd + 1)) {
                return ESP_ERR_INVALID_RESPONSE;
            }

            size_t data_len = buffer_len - 2;
            if (data_len > 0) {
                memcpy(response, &handle->response_buffer[2], data_len);
            }
            *response_len = data_len;
        }
    }

    return ESP_OK;
}

esp_err_t pn532_get_firmware_version(pn532_handle_t *handle, pn532_firmware_version_t *version)
{
    if (handle == NULL || version == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t response[4];
    size_t response_len = sizeof(response);

    esp_err_t ret = pn532_send_command(handle, PN532_COMMAND_GETFIRMWAREVERSION,
                                        NULL, 0, response, &response_len, PN532_TIMEOUT_MS);
    if (ret != ESP_OK) return ret;

    if (response_len < 4) {
        return ESP_ERR_INVALID_RESPONSE;
    }

    version->ic = response[0];
    version->ver = response[1];
    version->rev = response[2];
    version->support = response[3];

    ESP_LOGI(TAG, "Firmware: PN5%02X v%d.%d", version->ic, version->ver, version->rev);
    return ESP_OK;
}

esp_err_t pn532_sam_configuration(pn532_handle_t *handle, uint8_t mode, uint8_t timeout, bool use_irq)
{
    if (handle == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t params[] = {mode, timeout, use_irq ? 0x01 : 0x00};
    size_t response_len = 0;

    esp_err_t ret = pn532_send_command(handle, PN532_COMMAND_SAMCONFIGURATION,
                                        params, sizeof(params), NULL, &response_len, PN532_TIMEOUT_MS);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "SAM configuration failed");
    }
    return ret;
}

// ==================== Tag Emulation ====================

static esp_err_t tg_init_as_target(pn532_handle_t *handle, uint8_t *atr_res, size_t *atr_res_len)
{
    // Parameters matching Seeed reference for best compatibility
    uint8_t params[] = {
        5,                      // MODE: PICC only, Passive only
        0x04, 0x00,             // SENS_RES (ATQA)
        0x00, 0x00, 0x00,       // NFCID1 (auto-generated)
        0x20,                   // SEL_RES (SAK) - ISO-DEP capable
        0, 0, 0, 0, 0, 0, 0, 0, // FeliCa params (unused)
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // NFCID3t
        0,                      // General bytes length
        0                       // Historical bytes length
    };

    size_t response_len = *atr_res_len;
    esp_err_t ret = pn532_send_command(handle, PN532_COMMAND_TGINITASTARGET,
                                        params, sizeof(params), 
                                        atr_res, &response_len, 30000);
    if (ret == ESP_OK) {
        *atr_res_len = response_len;
    }
    return ret;
}

static esp_err_t tg_get_data(pn532_handle_t *handle, uint8_t *data, size_t *len)
{
    size_t response_len = *len;
    esp_err_t ret = pn532_send_command(handle, PN532_COMMAND_TGGETDATA,
                                        NULL, 0, data, &response_len, 5000);
    if (ret != ESP_OK) return ret;

    if (response_len == 0) {
        *len = 0;
        return ESP_OK;
    }

    uint8_t status = data[0];
    if (status != 0x00) {
        // 0x13/0x29 = reader disconnected (normal), others = error
        return ESP_ERR_INVALID_STATE;
    }

    // Remove status byte
    size_t data_len = response_len - 1;
    memmove(data, data + 1, data_len);
    *len = data_len;
    return ESP_OK;
}

static esp_err_t tg_set_data(pn532_handle_t *handle, const uint8_t *data, size_t len)
{
    uint8_t response[1];
    size_t response_len = sizeof(response);

    esp_err_t ret = pn532_send_command(handle, PN532_COMMAND_TGSETDATA,
                                        data, len, response, &response_len, PN532_TIMEOUT_MS);
    if (ret != ESP_OK) return ret;

    if (response_len > 0 && response[0] != 0x00) {
        return ESP_ERR_INVALID_STATE;
    }
    return ESP_OK;
}

static void in_release(pn532_handle_t *handle)
{
    uint8_t param = 0x00;
    uint8_t response[1];
    size_t response_len = sizeof(response);
    pn532_send_command(handle, PN532_COMMAND_INRELEASE, &param, 1, response, &response_len, 100);
}

// Set callback for NDEF write events
void pn532_set_write_callback(void (*callback)(const uint8_t *data, size_t len))
{
    ndef_write_callback = callback;
}

// Parse and handle written NDEF data
static void process_written_ndef(const uint8_t *ndef_file, size_t file_len)
{
    if (file_len < 2) return;
    
    // Get NDEF message length from first 2 bytes
    uint16_t ndef_len = (ndef_file[0] << 8) | ndef_file[1];
    if (ndef_len == 0 || ndef_len + 2 > file_len) {
        ESP_LOGW(TAG, "Invalid NDEF length: %d", ndef_len);
        return;
    }
    
    const uint8_t *ndef_msg = &ndef_file[2];
    ESP_LOGI(TAG, "Received NDEF message (%d bytes)", ndef_len);

    if (ndef_write_callback) {
        ndef_write_callback(ndef_msg, ndef_len);
    }
}

#define NDEF_FILE_BUF_SIZE 8192

esp_err_t pn532_emulate_tag_loop(pn532_handle_t *handle, const uint8_t *ndef_message, size_t ndef_len)
{
    if (handle == NULL || ndef_message == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t atr_res[64];
    size_t atr_len = sizeof(atr_res);
    esp_err_t ret = tg_init_as_target(handle, atr_res, &atr_len);
    if (ret != ESP_OK) return ret;

    vTaskDelay(pdMS_TO_TICKS(5));
    ESP_LOGI(TAG, "Reader detected, emulating tag");

    static uint8_t ndef_file[NDEF_FILE_BUF_SIZE];
    ndef_file[0] = (ndef_len >> 8) & 0xFF;
    ndef_file[1] = ndef_len & 0xFF;
    memcpy(&ndef_file[2], ndef_message, ndef_len);
    size_t ndef_file_len = ndef_len + 2;

    static uint8_t write_buf[NDEF_FILE_BUF_SIZE];
    memset(write_buf, 0, sizeof(write_buf));
    int32_t expected_ndef_length = -1;
    bool write_occurred = false;
    bool write_processed = false;

    tag_state_t state = TAG_STATE_IDLE;

    while (true) {
        uint8_t capdu[256];
        size_t capdu_len = sizeof(capdu);

        ret = tg_get_data(handle, capdu, &capdu_len);
        if (ret != ESP_OK) {
            if (write_occurred && !write_processed) {
                process_written_ndef(write_buf, expected_ndef_length > 0 ? expected_ndef_length + 2 : NDEF_FILE_BUF_SIZE);
            }
            in_release(handle);
            return ESP_OK;
        }

        if (capdu_len < 4) continue;

        uint8_t ins = capdu[1];
        uint8_t p1 = capdu[2];
        uint8_t p2 = capdu[3];
        uint8_t lc = (capdu_len > 4) ? capdu[4] : 0;
        uint8_t *data = (capdu_len > 5) ? &capdu[5] : NULL;

        uint8_t rapdu[256];
        size_t rapdu_len = 0;

        if (ins == 0xA4) {
            if (p1 == 0x04 && lc == 7 && data && memcmp(data, ndef_aid, 7) == 0) {
                state = TAG_STATE_APP_SELECTED;
                build_rapdu(rapdu, &rapdu_len, NULL, 0, 0x90, 0x00);
            } else if (p1 == 0x00 && lc == 2 && data) {
                if (memcmp(data, cc_file_id, 2) == 0) {
                    state = TAG_STATE_CC_SELECTED;
                    build_rapdu(rapdu, &rapdu_len, NULL, 0, 0x90, 0x00);
                } else if (memcmp(data, ndef_file_id, 2) == 0) {
                    state = TAG_STATE_NDEF_SELECTED;
                    build_rapdu(rapdu, &rapdu_len, NULL, 0, 0x90, 0x00);
                } else {
                    build_rapdu(rapdu, &rapdu_len, NULL, 0, 0x6A, 0x82);
                }
            } else {
                build_rapdu(rapdu, &rapdu_len, NULL, 0, 0x6A, 0x82);
            }
        } else if (ins == 0xB0) {
            uint16_t offset = (p1 << 8) | p2;
            uint8_t le = (capdu_len > 4) ? capdu[capdu_len - 1] : 0;
            if (le == 0) le = 255;

            if (state == TAG_STATE_CC_SELECTED) {
                size_t avail = (offset < sizeof(capability_container)) ?
                               sizeof(capability_container) - offset : 0;
                size_t read_len = (avail < le) ? avail : le;
                if (read_len > 0) {
                    build_rapdu(rapdu, &rapdu_len, &capability_container[offset], read_len, 0x90, 0x00);
                } else {
                    build_rapdu(rapdu, &rapdu_len, NULL, 0, 0x6B, 0x00);
                }
            } else if (state == TAG_STATE_NDEF_SELECTED) {
                size_t avail = (offset < ndef_file_len) ? ndef_file_len - offset : 0;
                size_t read_len = (avail < le) ? avail : le;
                if (read_len > 0) {
                    build_rapdu(rapdu, &rapdu_len, &ndef_file[offset], read_len, 0x90, 0x00);
                } else {
                    build_rapdu(rapdu, &rapdu_len, NULL, 0, 0x90, 0x00);
                }
            } else {
                build_rapdu(rapdu, &rapdu_len, NULL, 0, 0x69, 0x86);
            }
        } else if (ins == 0xD6) {
            uint16_t offset = (p1 << 8) | p2;

            if (state == TAG_STATE_NDEF_SELECTED && lc > 0 && data) {
                if (offset + lc <= sizeof(write_buf)) {
                    memcpy(&write_buf[offset], data, lc);
                    write_occurred = true;

                    if (offset == 0 && lc >= 2) {
                        uint16_t new_len = (data[0] << 8) | data[1];
                        if (new_len == 0) {
                            expected_ndef_length = 0;
                        } else {
                            expected_ndef_length = new_len;
                            bool has_body = false;
                            size_t check_end = (new_len + 2 <= sizeof(write_buf)) ? new_len + 2 : sizeof(write_buf);
                            for (size_t i = 2; i < check_end; i++) {
                                if (write_buf[i] != 0) { has_body = true; break; }
                            }
                            if (has_body || (offset + lc >= new_len + 2)) {
                                ESP_LOGI(TAG, "NDEF write complete (length=%d)", new_len);
                                process_written_ndef(write_buf, new_len + 2);
                                write_processed = true;
                            }
                        }
                    } else if (expected_ndef_length > 0) {
                        if ((int32_t)(offset + lc) >= expected_ndef_length + 2) {
                            ESP_LOGI(TAG, "NDEF write complete (length=%d)", expected_ndef_length);
                            process_written_ndef(write_buf, expected_ndef_length + 2);
                            write_processed = true;
                        }
                    }

                    build_rapdu(rapdu, &rapdu_len, NULL, 0, 0x90, 0x00);
                } else {
                    ESP_LOGW(TAG, "Write out of bounds: offset=%d, len=%d", offset, lc);
                    build_rapdu(rapdu, &rapdu_len, NULL, 0, 0x6A, 0x82);
                }
            } else {
                build_rapdu(rapdu, &rapdu_len, NULL, 0, 0x69, 0x86);
            }
        } else {
            build_rapdu(rapdu, &rapdu_len, NULL, 0, 0x6D, 0x00);
        }

        ret = tg_set_data(handle, rapdu, rapdu_len);
        if (ret != ESP_OK) {
            if (write_occurred && !write_processed) {
                process_written_ndef(write_buf, expected_ndef_length > 0 ? expected_ndef_length + 2 : NDEF_FILE_BUF_SIZE);
            }
            in_release(handle);
            return ESP_OK;
        }

        vTaskDelay(1);
    }
}

// ==================== NDEF Record Creation ====================

esp_err_t ndef_create_text_record(const ndef_text_record_t *record, 
                                   uint8_t *buffer, size_t buffer_size, 
                                   size_t *message_len)
{
    if (record == NULL || buffer == NULL || message_len == NULL ||
        record->language_code == NULL || record->text == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    size_t lang_len = strlen(record->language_code);
    size_t text_len = strlen(record->text);
    size_t payload_len = 1 + lang_len + text_len;
    bool short_record = (payload_len <= 255);
    size_t header_size = short_record ? 4 : 7;
    size_t ndef_len = header_size + payload_len;

    if (ndef_len > buffer_size) {
        return ESP_ERR_INVALID_SIZE;
    }

    size_t idx = 0;
    if (short_record) {
        buffer[idx++] = 0xD1;  // MB=1, ME=1, SR=1, TNF=1
        buffer[idx++] = 0x01;
        buffer[idx++] = (uint8_t)payload_len;
    } else {
        buffer[idx++] = 0xC1;  // MB=1, ME=1, SR=0, TNF=1
        buffer[idx++] = 0x01;
        buffer[idx++] = (payload_len >> 24) & 0xFF;
        buffer[idx++] = (payload_len >> 16) & 0xFF;
        buffer[idx++] = (payload_len >> 8) & 0xFF;
        buffer[idx++] = payload_len & 0xFF;
    }
    buffer[idx++] = 'T';
    buffer[idx++] = (uint8_t)(lang_len & 0x3F);
    memcpy(&buffer[idx], record->language_code, lang_len);
    idx += lang_len;
    memcpy(&buffer[idx], record->text, text_len);
    idx += text_len;

    *message_len = idx;
    ESP_LOGI(TAG, "NDEF Text record (%zu bytes, %s)", *message_len,
             short_record ? "short" : "long");
    return ESP_OK;
}

esp_err_t ndef_create_url_record(uint8_t prefix_code, const char *url,
                                  uint8_t *buffer, size_t buffer_size,
                                  size_t *message_len)
{
    if (url == NULL || buffer == NULL || message_len == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    
    size_t url_len = strlen(url);
    size_t payload_len = 1 + url_len;
    size_t ndef_len = 4 + payload_len;
    
    if (ndef_len > buffer_size) {
        return ESP_ERR_INVALID_SIZE;
    }
    
    size_t idx = 0;
    buffer[idx++] = 0xD1;  // MB=1, ME=1, SR=1, TNF=1 (Well-Known)
    buffer[idx++] = 0x01;  // Type length = 1
    buffer[idx++] = payload_len;
    buffer[idx++] = 'U';   // Type = URI
    buffer[idx++] = prefix_code;
    memcpy(&buffer[idx], url, url_len);
    idx += url_len;
    
    *message_len = idx;
    
    const char *prefix_str = "";
    switch (prefix_code) {
        case 0x01: prefix_str = "http://www."; break;
        case 0x02: prefix_str = "https://www."; break;
        case 0x03: prefix_str = "http://"; break;
        case 0x04: prefix_str = "https://"; break;
    }
    ESP_LOGI(TAG, "NDEF URL: %s%s (%zu bytes)", prefix_str, url, *message_len);
    return ESP_OK;
}
