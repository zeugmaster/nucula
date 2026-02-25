/**
 * @file pn532_uart.c
 * @brief PN532 UART (HSU) Transport Layer Implementation
 * 
 * Based on Seeed-Studio PN532 library HSU implementation.
 * UART is faster than I2C and better for tag emulation with strict timing.
 */

#include "pn532.h"
#include "esp_log.h"
#include "driver/uart.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>

static const char *TAG = "PN532_UART";

// UART configuration
#define PN532_UART_NUM      UART_NUM_1
#define PN532_UART_BUF_SIZE 256

// Frame markers
#define PN532_PREAMBLE      0x00
#define PN532_STARTCODE1    0x00
#define PN532_STARTCODE2    0xFF
#define PN532_POSTAMBLE     0x00
#define PN532_HOSTTOPN532   0xD4
#define PN532_PN532TOHOST   0xD5

// ACK frame
static const uint8_t PN532_ACK[] = {0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00};

// Store handle info
typedef struct {
    int tx_gpio;
    int rx_gpio;
    uint32_t baud_rate;
    bool initialized;
    uint8_t last_command;
} uart_handle_t;

static uart_handle_t uart_ctx = {0};

esp_err_t pn532_uart_init(pn532_handle_t *handle, int tx_gpio, int rx_gpio, uint32_t baud_rate)
{
    ESP_LOGI(TAG, "Initializing UART - TX: GPIO%d, RX: GPIO%d, Baud: %lu", 
             tx_gpio, rx_gpio, baud_rate);
    
    uart_config_t uart_config = {
        .baud_rate = baud_rate,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    
    esp_err_t ret = uart_param_config(PN532_UART_NUM, &uart_config);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "UART param config failed: %s", esp_err_to_name(ret));
        return ret;
    }
    
    ret = uart_set_pin(PN532_UART_NUM, tx_gpio, rx_gpio, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "UART set pin failed: %s", esp_err_to_name(ret));
        return ret;
    }
    
    ret = uart_driver_install(PN532_UART_NUM, PN532_UART_BUF_SIZE * 2, 0, 0, NULL, 0);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "UART driver install failed: %s", esp_err_to_name(ret));
        return ret;
    }
    
    uart_ctx.tx_gpio = tx_gpio;
    uart_ctx.rx_gpio = rx_gpio;
    uart_ctx.baud_rate = baud_rate;
    uart_ctx.initialized = true;
    
    handle->transport = PN532_TRANSPORT_UART;
    
    ESP_LOGI(TAG, "UART initialized successfully");
    return ESP_OK;
}

esp_err_t pn532_uart_deinit(pn532_handle_t *handle)
{
    if (uart_ctx.initialized) {
        uart_driver_delete(PN532_UART_NUM);
        uart_ctx.initialized = false;
        ESP_LOGI(TAG, "UART deinitialized");
    }
    return ESP_OK;
}

// Flush receive buffer
static void uart_flush_rx(void)
{
    uart_flush_input(PN532_UART_NUM);
}

// Read bytes with timeout
static int uart_read_bytes_timeout(uint8_t *buf, size_t len, uint32_t timeout_ms)
{
    return uart_read_bytes(PN532_UART_NUM, buf, len, pdMS_TO_TICKS(timeout_ms));
}

// Write bytes
static int uart_write_bytes_data(const uint8_t *buf, size_t len)
{
    return uart_write_bytes(PN532_UART_NUM, buf, len);
}

// Wait for ACK frame
static esp_err_t uart_read_ack(uint32_t timeout_ms)
{
    uint8_t ack_buf[6];
    
    int read = uart_read_bytes_timeout(ack_buf, 6, timeout_ms);
    if (read != 6) {
        ESP_LOGW(TAG, "ACK timeout (read %d bytes)", read);
        return ESP_ERR_TIMEOUT;
    }
    
    if (memcmp(ack_buf, PN532_ACK, 6) != 0) {
        ESP_LOGW(TAG, "Invalid ACK: %02X %02X %02X %02X %02X %02X",
                 ack_buf[0], ack_buf[1], ack_buf[2], 
                 ack_buf[3], ack_buf[4], ack_buf[5]);
        return ESP_ERR_INVALID_RESPONSE;
    }
    
    return ESP_OK;
}

esp_err_t pn532_uart_wakeup(pn532_handle_t *handle)
{
    // Send wakeup sequence: 0x55 0x55 0x00 0x00 0x00
    uint8_t wakeup[] = {0x55, 0x55, 0x00, 0x00, 0x00};
    
    // Flush any pending data
    uart_flush_rx();
    
    uart_write_bytes_data(wakeup, sizeof(wakeup));
    
    // Wait a bit for PN532 to wake up
    vTaskDelay(pdMS_TO_TICKS(50));
    
    // Flush any response from wakeup
    uart_flush_rx();
    
    ESP_LOGD(TAG, "Wakeup sequence sent");
    return ESP_OK;
}

esp_err_t pn532_uart_write_command(pn532_handle_t *handle, uint8_t command,
                                    const uint8_t *params, size_t params_len)
{
    // Flush RX buffer first
    uart_flush_rx();
    
    uint8_t frame[PN532_MAX_FRAME_LEN];
    size_t idx = 0;
    
    // Calculate lengths
    uint8_t data_len = 1 + params_len + 1;  // TFI + command + params
    
    // Build frame
    frame[idx++] = PN532_PREAMBLE;
    frame[idx++] = PN532_STARTCODE1;
    frame[idx++] = PN532_STARTCODE2;
    frame[idx++] = data_len;
    frame[idx++] = ~data_len + 1;  // LCS
    frame[idx++] = PN532_HOSTTOPN532;  // TFI
    frame[idx++] = command;
    
    // Calculate checksum
    uint8_t sum = PN532_HOSTTOPN532 + command;
    
    // Add parameters
    if (params && params_len > 0) {
        memcpy(&frame[idx], params, params_len);
        for (size_t i = 0; i < params_len; i++) {
            sum += params[i];
        }
        idx += params_len;
    }
    
    frame[idx++] = ~sum + 1;  // DCS
    frame[idx++] = PN532_POSTAMBLE;
    
    // Store command for response validation
    uart_ctx.last_command = command;
    
    // Send frame
    int written = uart_write_bytes_data(frame, idx);
    if (written != idx) {
        ESP_LOGE(TAG, "Write failed: wrote %d of %zu bytes", written, idx);
        return ESP_ERR_INVALID_SIZE;
    }
    
    ESP_LOGD(TAG, "Sent command 0x%02X with %zu params", command, params_len);
    
    // Wait for ACK
    esp_err_t ret = uart_read_ack(100);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "No ACK received for command 0x%02X", command);
        return ret;
    }
    
    return ESP_OK;
}

esp_err_t pn532_uart_read_response(pn532_handle_t *handle, uint8_t *response,
                                    size_t *response_len, uint32_t timeout_ms)
{
    uint8_t buf[3];
    
    // Read preamble and start code (0x00 0x00 0xFF)
    int read = uart_read_bytes_timeout(buf, 3, timeout_ms);
    if (read != 3) {
        ESP_LOGD(TAG, "Preamble timeout");
        return ESP_ERR_TIMEOUT;
    }
    
    if (buf[0] != 0x00 || buf[1] != 0x00 || buf[2] != 0xFF) {
        ESP_LOGW(TAG, "Invalid preamble: %02X %02X %02X", buf[0], buf[1], buf[2]);
        return ESP_ERR_INVALID_RESPONSE;
    }
    
    // Read length bytes
    uint8_t len_buf[2];
    read = uart_read_bytes_timeout(len_buf, 2, timeout_ms);
    if (read != 2) {
        ESP_LOGW(TAG, "Length timeout");
        return ESP_ERR_TIMEOUT;
    }
    
    uint8_t data_len = len_buf[0];
    uint8_t len_checksum = len_buf[1];
    
    // Verify length checksum
    if ((uint8_t)(data_len + len_checksum) != 0) {
        ESP_LOGW(TAG, "Invalid length checksum");
        return ESP_ERR_INVALID_CRC;
    }
    
    // Read TFI and command response
    uint8_t tfi_cmd[2];
    read = uart_read_bytes_timeout(tfi_cmd, 2, timeout_ms);
    if (read != 2) {
        ESP_LOGW(TAG, "TFI/CMD timeout");
        return ESP_ERR_TIMEOUT;
    }
    
    if (tfi_cmd[0] != PN532_PN532TOHOST) {
        ESP_LOGW(TAG, "Invalid TFI: 0x%02X", tfi_cmd[0]);
        return ESP_ERR_INVALID_RESPONSE;
    }
    
    uint8_t expected_cmd = uart_ctx.last_command + 1;
    if (tfi_cmd[1] != expected_cmd) {
        ESP_LOGW(TAG, "Unexpected response cmd: 0x%02X (expected 0x%02X)", 
                 tfi_cmd[1], expected_cmd);
        return ESP_ERR_INVALID_RESPONSE;
    }
    
    // Read data (excluding TFI and CMD which we already read)
    size_t payload_len = data_len - 2;  // Subtract TFI and CMD
    if (payload_len > *response_len) {
        ESP_LOGW(TAG, "Response too large: %zu > %zu", payload_len, *response_len);
        return ESP_ERR_INVALID_SIZE;
    }
    
    if (payload_len > 0) {
        read = uart_read_bytes_timeout(response, payload_len, timeout_ms);
        if (read != payload_len) {
            ESP_LOGW(TAG, "Data timeout: read %d of %zu", read, payload_len);
            return ESP_ERR_TIMEOUT;
        }
    }
    
    // Read checksum and postamble
    uint8_t tail[2];
    read = uart_read_bytes_timeout(tail, 2, timeout_ms);
    if (read != 2) {
        ESP_LOGW(TAG, "Tail timeout");
        return ESP_ERR_TIMEOUT;
    }
    
    // Verify data checksum
    uint8_t sum = tfi_cmd[0] + tfi_cmd[1];
    for (size_t i = 0; i < payload_len; i++) {
        sum += response[i];
    }
    if ((uint8_t)(sum + tail[0]) != 0) {
        ESP_LOGW(TAG, "Invalid data checksum");
        return ESP_ERR_INVALID_CRC;
    }
    
    *response_len = payload_len;
    
    ESP_LOGD(TAG, "Received response: %zu bytes", payload_len);
    
    return ESP_OK;
}

