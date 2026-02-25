/**
 * @file pn532_spi.c
 * @brief Software (bit-bang) SPI transport for PN532 NFC controller
 *
 * Uses GPIO bit-banging instead of the hardware SPI peripheral,
 * allowing PN532 to coexist with a display that owns SPI2_HOST.
 *
 * PN532 SPI Protocol:
 * - SPI Mode 0 (CPOL=0, CPHA=0)
 * - LSB First (handled natively by bit-bang)
 * - Target clock ~1MHz (each half-period ~500ns)
 */

#include "pn532.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_rom_sys.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>

static const char *TAG = "PN532_SPI";

#define SPI_STATUS_READ  0x02
#define SPI_DATA_WRITE   0x01
#define SPI_DATA_READ    0x03

// Half-period delay in microseconds (~100kHz clock -- conservative for reliability)
#define SPI_HALF_PERIOD_US  5

static int s_sck, s_mosi, s_miso, s_ss;

// Bit-bang one byte LSB-first, Mode 0 (CPOL=0, CPHA=0)
// Data set before rising edge, sampled on rising edge
static uint8_t spi_xfer_byte(uint8_t tx)
{
    uint8_t rx = 0;
    for (int i = 0; i < 8; i++) {
        gpio_set_level(s_mosi, (tx >> i) & 1);
        esp_rom_delay_us(SPI_HALF_PERIOD_US);

        gpio_set_level(s_sck, 1);
        esp_rom_delay_us(SPI_HALF_PERIOD_US);
        if (gpio_get_level(s_miso))
            rx |= (1 << i);

        gpio_set_level(s_sck, 0);
    }
    return rx;
}

static void spi_write_bytes(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
        spi_xfer_byte(data[i]);
}

static void spi_read_bytes(uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
        data[i] = spi_xfer_byte(0xFF);
}

static void ss_low(void)  { gpio_set_level(s_ss, 0); esp_rom_delay_us(2); }
static void ss_high(void) { gpio_set_level(s_ss, 1); }

// ==================== Public API ====================

esp_err_t pn532_spi_init(pn532_handle_t *handle, const pn532_spi_config_t *config)
{
    if (!handle || !config) return ESP_ERR_INVALID_ARG;

    s_sck  = config->sck_gpio;
    s_mosi = config->mosi_gpio;
    s_miso = config->miso_gpio;
    s_ss   = config->ss_gpio;

    gpio_config_t out_cfg = {
        .pin_bit_mask = (1ULL << s_sck) | (1ULL << s_mosi) | (1ULL << s_ss),
        .mode = GPIO_MODE_OUTPUT,
    };
    gpio_config(&out_cfg);

    gpio_config_t in_cfg = {
        .pin_bit_mask = (1ULL << s_miso),
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
    };
    gpio_config(&in_cfg);

    gpio_set_level(s_sck, 0);
    gpio_set_level(s_ss, 1);

    handle->transport = PN532_TRANSPORT_SPI;
    handle->spi_ss_gpio = s_ss;

    ESP_LOGI(TAG, "Software SPI: SCK=%d MOSI=%d MISO=%d SS=%d",
             s_sck, s_mosi, s_miso, s_ss);
    return ESP_OK;
}

esp_err_t pn532_spi_deinit(pn532_handle_t *handle)
{
    if (!handle || handle->transport != PN532_TRANSPORT_SPI) return ESP_ERR_INVALID_ARG;
    gpio_set_level(s_ss, 1);
    return ESP_OK;
}

esp_err_t pn532_spi_wakeup(pn532_handle_t *handle)
{
    if (!handle || handle->transport != PN532_TRANSPORT_SPI) return ESP_ERR_INVALID_ARG;

    // Try wakeup sequence up to 3 times
    for (int attempt = 0; attempt < 3; attempt++) {
        ESP_LOGI(TAG, "Wakeup attempt %d", attempt + 1);

        // Long SS low pulse to wake from any low-power state
        gpio_set_level(s_ss, 0);
        vTaskDelay(pdMS_TO_TICKS(80));
        gpio_set_level(s_ss, 1);
        vTaskDelay(pdMS_TO_TICKS(100));

        // Send wake-up pattern
        ss_low();
        vTaskDelay(pdMS_TO_TICKS(2));
        uint8_t pattern[] = {0x55, 0x55, 0x00, 0x00, 0x00};
        spi_write_bytes(pattern, sizeof(pattern));
        ss_high();
        vTaskDelay(pdMS_TO_TICKS(150));

        // Poll for ready status
        for (int i = 0; i < 40; i++) {
            ss_low();
            spi_xfer_byte(SPI_STATUS_READ);
            uint8_t status = spi_xfer_byte(0xFF);
            ss_high();

            ESP_LOGI(TAG, "Ready poll %d: raw status=0x%02X", i, status);

            if (status == 0xFF) {
                // 0xFF means MISO is floating (not connected or MISO/MOSI swapped)
                if (i == 0) {
                    ESP_LOGW(TAG, "MISO reads 0xFF - check if MISO/MOSI wires are swapped on your module");
                }
                vTaskDelay(pdMS_TO_TICKS(50));
                continue;
            }

            if (status & 0x01) {
                ESP_LOGI(TAG, "PN532 ready after %d polls (attempt %d)", i + 1, attempt + 1);
                // Flush any stale data by reading it
                ss_low();
                spi_xfer_byte(SPI_DATA_READ);
                uint8_t discard[32];
                spi_read_bytes(discard, sizeof(discard));
                ss_high();
                vTaskDelay(pdMS_TO_TICKS(10));
                return ESP_OK;
            }
            vTaskDelay(pdMS_TO_TICKS(50));
        }
    }

    ESP_LOGW(TAG, "PN532 wakeup: never got ready status (continuing anyway)");
    return ESP_OK;
}

esp_err_t pn532_spi_wait_ready(pn532_handle_t *handle, uint32_t timeout_ms)
{
    if (!handle || handle->transport != PN532_TRANSPORT_SPI) return ESP_ERR_INVALID_ARG;

    uint32_t start = xTaskGetTickCount();
    int polls = 0;

    while ((xTaskGetTickCount() - start) < pdMS_TO_TICKS(timeout_ms)) {
        ss_low();
        spi_xfer_byte(SPI_STATUS_READ);
        uint8_t status = spi_xfer_byte(0xFF);
        ss_high();

        if (status & 0x01) return ESP_OK;

        if (++polls < 10) {
            esp_rom_delay_us(100);
        } else {
            vTaskDelay(pdMS_TO_TICKS(1));
        }
    }

    return ESP_ERR_TIMEOUT;
}

esp_err_t pn532_spi_write_command(pn532_handle_t *handle, const uint8_t *data, size_t len)
{
    if (!handle || handle->transport != PN532_TRANSPORT_SPI || !data) return ESP_ERR_INVALID_ARG;

    ss_low();
    spi_xfer_byte(SPI_DATA_WRITE);
    spi_write_bytes(data, len);
    ss_high();

    return ESP_OK;
}

esp_err_t pn532_spi_read_ack(pn532_handle_t *handle)
{
    if (!handle || handle->transport != PN532_TRANSPORT_SPI) return ESP_ERR_INVALID_ARG;

    static const uint8_t ACK[] = {0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00};
    uint8_t buf[6];

    // Wait for PN532 to have ACK ready
    esp_err_t ret = pn532_spi_wait_ready(handle, 100);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "ACK not ready within 100ms");
    }

    ss_low();
    spi_xfer_byte(SPI_DATA_READ);
    spi_read_bytes(buf, 6);
    ss_high();

    ESP_LOGI(TAG, "ACK bytes: %02X %02X %02X %02X %02X %02X",
             buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);

    if (memcmp(buf, ACK, 6) != 0) {
        return ESP_ERR_INVALID_RESPONSE;
    }
    return ESP_OK;
}

esp_err_t pn532_spi_read_response(pn532_handle_t *handle, uint8_t *data, size_t *len, uint32_t timeout_ms)
{
    if (!handle || handle->transport != PN532_TRANSPORT_SPI || !data || !len) return ESP_ERR_INVALID_ARG;

    size_t max_len = *len;
    *len = 0;

    esp_err_t ret = pn532_spi_wait_ready(handle, timeout_ms);
    if (ret != ESP_OK) return ret;

    ss_low();
    spi_xfer_byte(SPI_DATA_READ);

    // Read preamble + start codes
    uint8_t header[3];
    spi_read_bytes(header, 3);

    ESP_LOGI(TAG, "Response header: %02X %02X %02X", header[0], header[1], header[2]);

    if (header[0] != 0x00 || header[1] != 0x00 || header[2] != 0xFF) {
        ss_high();
        return ESP_ERR_INVALID_RESPONSE;
    }

    // Read length + LCS
    uint8_t len_buf[2];
    spi_read_bytes(len_buf, 2);
    uint8_t frame_len = len_buf[0];

    if ((uint8_t)(len_buf[0] + len_buf[1]) != 0 || frame_len > max_len) {
        ss_high();
        return ESP_ERR_INVALID_RESPONSE;
    }

    // Read data + DCS + postamble
    uint8_t frame[PN532_MAX_FRAME_LEN];
    spi_read_bytes(frame, frame_len + 2);

    ss_high();

    // Verify checksum
    uint8_t sum = 0;
    for (int i = 0; i < frame_len; i++) sum += frame[i];
    if ((uint8_t)(sum + frame[frame_len]) != 0) {
        return ESP_ERR_INVALID_RESPONSE;
    }

    memcpy(data, frame, frame_len);
    *len = frame_len;
    return ESP_OK;
}
