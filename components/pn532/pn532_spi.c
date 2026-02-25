/**
 * @file pn532_spi.c
 * @brief SPI transport layer for PN532 NFC controller
 * 
 * PN532 SPI Protocol:
 * - SPI Mode 0 (CPOL=0, CPHA=0)
 * - LSB First (handled via bit reversal)
 * - Max 5MHz clock, recommended 1MHz for reliability
 */

#include "pn532.h"
#include "driver/spi_master.h"
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
#define SPI_HOST_ID      SPI2_HOST

// Bit reversal lookup table for LSB-first conversion
static const uint8_t bit_reverse[256] = {
    0x00,0x80,0x40,0xc0,0x20,0xa0,0x60,0xe0,0x10,0x90,0x50,0xd0,0x30,0xb0,0x70,0xf0,
    0x08,0x88,0x48,0xc8,0x28,0xa8,0x68,0xe8,0x18,0x98,0x58,0xd8,0x38,0xb8,0x78,0xf8,
    0x04,0x84,0x44,0xc4,0x24,0xa4,0x64,0xe4,0x14,0x94,0x54,0xd4,0x34,0xb4,0x74,0xf4,
    0x0c,0x8c,0x4c,0xcc,0x2c,0xac,0x6c,0xec,0x1c,0x9c,0x5c,0xdc,0x3c,0xbc,0x7c,0xfc,
    0x02,0x82,0x42,0xc2,0x22,0xa2,0x62,0xe2,0x12,0x92,0x52,0xd2,0x32,0xb2,0x72,0xf2,
    0x0a,0x8a,0x4a,0xca,0x2a,0xaa,0x6a,0xea,0x1a,0x9a,0x5a,0xda,0x3a,0xba,0x7a,0xfa,
    0x06,0x86,0x46,0xc6,0x26,0xa6,0x66,0xe6,0x16,0x96,0x56,0xd6,0x36,0xb6,0x76,0xf6,
    0x0e,0x8e,0x4e,0xce,0x2e,0xae,0x6e,0xee,0x1e,0x9e,0x5e,0xde,0x3e,0xbe,0x7e,0xfe,
    0x01,0x81,0x41,0xc1,0x21,0xa1,0x61,0xe1,0x11,0x91,0x51,0xd1,0x31,0xb1,0x71,0xf1,
    0x09,0x89,0x49,0xc9,0x29,0xa9,0x69,0xe9,0x19,0x99,0x59,0xd9,0x39,0xb9,0x79,0xf9,
    0x05,0x85,0x45,0xc5,0x25,0xa5,0x65,0xe5,0x15,0x95,0x55,0xd5,0x35,0xb5,0x75,0xf5,
    0x0d,0x8d,0x4d,0xcd,0x2d,0xad,0x6d,0xed,0x1d,0x9d,0x5d,0xdd,0x3d,0xbd,0x7d,0xfd,
    0x03,0x83,0x43,0xc3,0x23,0xa3,0x63,0xe3,0x13,0x93,0x53,0xd3,0x33,0xb3,0x73,0xf3,
    0x0b,0x8b,0x4b,0xcb,0x2b,0xab,0x6b,0xeb,0x1b,0x9b,0x5b,0xdb,0x3b,0xbb,0x7b,0xfb,
    0x07,0x87,0x47,0xc7,0x27,0xa7,0x67,0xe7,0x17,0x97,0x57,0xd7,0x37,0xb7,0x77,0xf7,
    0x0f,0x8f,0x4f,0xcf,0x2f,0xaf,0x6f,0xef,0x1f,0x9f,0x5f,0xdf,0x3f,0xbf,0x7f,0xff,
};

// Low-level SPI transfer with LSB-first bit reversal
static esp_err_t spi_transfer(pn532_handle_t *handle, uint8_t *tx, uint8_t *rx, size_t len)
{
    if (len == 0) return ESP_OK;
    
    uint8_t tx_buf[64], rx_buf[64];
    uint8_t *tx_heap = NULL, *rx_heap = NULL;
    uint8_t *tx_ptr, *rx_ptr;
    
    if (len <= sizeof(tx_buf)) {
        tx_ptr = tx_buf;
        rx_ptr = rx_buf;
    } else {
        tx_heap = malloc(len);
        rx_heap = malloc(len);
        if (!tx_heap || !rx_heap) {
            free(tx_heap);
            free(rx_heap);
            return ESP_ERR_NO_MEM;
        }
        tx_ptr = tx_heap;
        rx_ptr = rx_heap;
    }
    
    // Reverse bits for transmission (LSB-first)
    if (tx) {
        for (size_t i = 0; i < len; i++) tx_ptr[i] = bit_reverse[tx[i]];
    } else {
        memset(tx_ptr, 0xFF, len);
    }
    
    spi_transaction_t t = {
        .length = len * 8,
        .tx_buffer = tx_ptr,
        .rx_buffer = rx_ptr,
    };
    
    esp_err_t ret = spi_device_polling_transmit(handle->spi_handle, &t);
    
    // Reverse received bits back
    if (ret == ESP_OK && rx) {
        for (size_t i = 0; i < len; i++) rx[i] = bit_reverse[rx_ptr[i]];
    }
    
    free(tx_heap);
    free(rx_heap);
    return ret;
}

esp_err_t pn532_spi_init(pn532_handle_t *handle, const pn532_spi_config_t *config)
{
    if (!handle || !config) return ESP_ERR_INVALID_ARG;
    
    // Configure SS pin
    gpio_config_t ss_conf = {
        .pin_bit_mask = (1ULL << config->ss_gpio),
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
    };
    gpio_config(&ss_conf);
    gpio_set_level(config->ss_gpio, 1);
    
    spi_bus_config_t bus = {
        .mosi_io_num = config->mosi_gpio,
        .miso_io_num = config->miso_gpio,
        .sclk_io_num = config->sck_gpio,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = PN532_MAX_FRAME_LEN + 10,
    };
    
    esp_err_t ret = spi_bus_initialize(SPI_HOST_ID, &bus, SPI_DMA_CH_AUTO);
    if (ret != ESP_OK) return ret;
    
    spi_device_interface_config_t dev = {
        .clock_speed_hz = config->clk_speed_hz,
        .mode = 0,
        .spics_io_num = -1,  // Manual CS control
        .queue_size = 1,
    };
    
    ret = spi_bus_add_device(SPI_HOST_ID, &dev, &handle->spi_handle);
    if (ret != ESP_OK) {
        spi_bus_free(SPI_HOST_ID);
        return ret;
    }
    
    handle->transport = PN532_TRANSPORT_SPI;
    handle->spi_ss_gpio = config->ss_gpio;
    
    ESP_LOGI(TAG, "SPI initialized (SCK:%d MISO:%d MOSI:%d SS:%d @ %luHz)",
             config->sck_gpio, config->miso_gpio, config->mosi_gpio, 
             config->ss_gpio, config->clk_speed_hz);
    return ESP_OK;
}

esp_err_t pn532_spi_deinit(pn532_handle_t *handle)
{
    if (!handle || handle->transport != PN532_TRANSPORT_SPI) return ESP_ERR_INVALID_ARG;
    spi_bus_remove_device(handle->spi_handle);
    spi_bus_free(SPI_HOST_ID);
    return ESP_OK;
}

esp_err_t pn532_spi_wakeup(pn532_handle_t *handle)
{
    if (!handle || handle->transport != PN532_TRANSPORT_SPI) return ESP_ERR_INVALID_ARG;
    
    // Long SS low pulse to wake from any low-power state
    gpio_set_level(handle->spi_ss_gpio, 0);
    vTaskDelay(pdMS_TO_TICKS(50));
    gpio_set_level(handle->spi_ss_gpio, 1);
    vTaskDelay(pdMS_TO_TICKS(100));
    
    // Send wake-up pattern (required by some PN532 boards)
    gpio_set_level(handle->spi_ss_gpio, 0);
    vTaskDelay(pdMS_TO_TICKS(2));
    uint8_t wakeup_pattern[] = {0x55, 0x55, 0x00, 0x00, 0x00};
    for (int i = 0; i < sizeof(wakeup_pattern); i++) {
        spi_transfer(handle, &wakeup_pattern[i], NULL, 1);
    }
    gpio_set_level(handle->spi_ss_gpio, 1);
    vTaskDelay(pdMS_TO_TICKS(100));
    
    // Poll for ready status
    for (int i = 0; i < 30; i++) {
        gpio_set_level(handle->spi_ss_gpio, 0);
        vTaskDelay(pdMS_TO_TICKS(2));
        
        uint8_t cmd = SPI_STATUS_READ;
        uint8_t status = 0;
        spi_transfer(handle, &cmd, NULL, 1);
        spi_transfer(handle, NULL, &status, 1);
        
        gpio_set_level(handle->spi_ss_gpio, 1);
        
        if (status & 0x01) {
            ESP_LOGD(TAG, "PN532 ready after %d polls", i + 1);
            return ESP_OK;
        }
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    
    // Continue anyway - firmware read will confirm if PN532 responds
    return ESP_OK;
}

esp_err_t pn532_spi_wait_ready(pn532_handle_t *handle, uint32_t timeout_ms)
{
    if (!handle || handle->transport != PN532_TRANSPORT_SPI) return ESP_ERR_INVALID_ARG;

    uint32_t start = xTaskGetTickCount();

    while ((xTaskGetTickCount() - start) < pdMS_TO_TICKS(timeout_ms)) {
        gpio_set_level(handle->spi_ss_gpio, 0);

        uint8_t cmd = SPI_STATUS_READ;
        uint8_t status;
        spi_transfer(handle, &cmd, NULL, 1);
        spi_transfer(handle, NULL, &status, 1);

        gpio_set_level(handle->spi_ss_gpio, 1);

        if (status & 0x01) return ESP_OK;

        // Always yield to let IDLE task and other tasks run
        vTaskDelay(pdMS_TO_TICKS(20));
    }

    return ESP_ERR_TIMEOUT;
}

esp_err_t pn532_spi_write_command(pn532_handle_t *handle, const uint8_t *data, size_t len)
{
    if (!handle || handle->transport != PN532_TRANSPORT_SPI || !data) return ESP_ERR_INVALID_ARG;
    
    uint8_t *buf = malloc(len + 1);
    if (!buf) return ESP_ERR_NO_MEM;
    
    buf[0] = SPI_DATA_WRITE;
    memcpy(&buf[1], data, len);
    
    gpio_set_level(handle->spi_ss_gpio, 0);
    // Minimal delay - just enough for PN532 to notice SS
    esp_rom_delay_us(100);
    
    esp_err_t ret = spi_transfer(handle, buf, NULL, len + 1);
    
    gpio_set_level(handle->spi_ss_gpio, 1);
    free(buf);
    
    return ret;
}

esp_err_t pn532_spi_read_ack(pn532_handle_t *handle)
{
    if (!handle || handle->transport != PN532_TRANSPORT_SPI) return ESP_ERR_INVALID_ARG;
    
    static const uint8_t ACK[] = {0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00};
    uint8_t buf[6];
    uint8_t cmd = SPI_DATA_READ;

    pn532_spi_wait_ready(handle, 100);

    gpio_set_level(handle->spi_ss_gpio, 0);
    esp_rom_delay_us(100);
    
    spi_transfer(handle, &cmd, NULL, 1);
    spi_transfer(handle, NULL, buf, 6);
    
    gpio_set_level(handle->spi_ss_gpio, 1);
    
    if (memcmp(buf, ACK, 6) != 0) {
        ESP_LOGD(TAG, "ACK mismatch: %02X%02X%02X%02X%02X%02X", 
                 buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
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
    
    gpio_set_level(handle->spi_ss_gpio, 0);
    esp_rom_delay_us(100);
    
    uint8_t cmd = SPI_DATA_READ;
    spi_transfer(handle, &cmd, NULL, 1);
    
    // Read preamble + start codes
    uint8_t header[3];
    spi_transfer(handle, NULL, header, 3);
    
    if (header[0] != 0x00 || header[1] != 0x00 || header[2] != 0xFF) {
        gpio_set_level(handle->spi_ss_gpio, 1);
        return ESP_ERR_INVALID_RESPONSE;
    }
    
    // Read length + LCS
    uint8_t len_buf[2];
    spi_transfer(handle, NULL, len_buf, 2);
    uint8_t frame_len = len_buf[0];
    
    if ((uint8_t)(len_buf[0] + len_buf[1]) != 0 || frame_len > max_len) {
        gpio_set_level(handle->spi_ss_gpio, 1);
        return ESP_ERR_INVALID_RESPONSE;
    }
    
    // Read data + DCS + postamble
    uint8_t frame[PN532_MAX_FRAME_LEN];
    spi_transfer(handle, NULL, frame, frame_len + 2);
    
    gpio_set_level(handle->spi_ss_gpio, 1);
    
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
