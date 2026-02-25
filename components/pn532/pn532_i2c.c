/**
 * @file pn532_i2c.c
 * @brief PN532 I2C Transport Layer Implementation (Legacy I2C Driver)
 */

#include "pn532.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>

static const char *TAG = "PN532_I2C";

// I2C ready status byte
#define PN532_I2C_READY             0x01

esp_err_t pn532_i2c_init(pn532_handle_t *handle, const pn532_i2c_config_t *config)
{
    if (handle == NULL || config == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    ESP_LOGI(TAG, "Initializing I2C bus - SDA: GPIO%d, SCL: GPIO%d, Speed: %lu Hz",
             config->sda_gpio, config->scl_gpio, (unsigned long)config->clk_speed_hz);

    handle->i2c_port = config->i2c_port;

    // Configure I2C master
    i2c_config_t i2c_conf = {
        .mode = I2C_MODE_MASTER,
        .sda_io_num = config->sda_gpio,
        .scl_io_num = config->scl_gpio,
        .sda_pullup_en = GPIO_PULLUP_ENABLE,
        .scl_pullup_en = GPIO_PULLUP_ENABLE,
        .master.clk_speed = config->clk_speed_hz,
    };

    esp_err_t ret = i2c_param_config(handle->i2c_port, &i2c_conf);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to configure I2C: %s", esp_err_to_name(ret));
        return ret;
    }

    // Delete existing driver if any (in case of reconnect) - ignore errors
    i2c_driver_delete(handle->i2c_port);
    
    ret = i2c_driver_install(handle->i2c_port, I2C_MODE_MASTER, 0, 0, 0);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to install I2C driver: %s", esp_err_to_name(ret));
        return ret;
    }
    
    // Set timeout - use a reasonable value that works with ESP32-C6
    // The max timeout value varies by chip, use a safe value
    ret = i2c_set_timeout(handle->i2c_port, 0x1FFFF);  // ~1.6ms timeout
    if (ret != ESP_OK) {
        ESP_LOGD(TAG, "i2c_set_timeout returned %s (may be ignored)", esp_err_to_name(ret));
    }

    ESP_LOGI(TAG, "I2C bus initialized successfully");
    return ESP_OK;
}

esp_err_t pn532_i2c_deinit(pn532_handle_t *handle)
{
    if (handle == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t ret = i2c_driver_delete(handle->i2c_port);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to delete I2C driver: %s", esp_err_to_name(ret));
        return ret;
    }

    ESP_LOGI(TAG, "I2C bus deinitialized");
    return ESP_OK;
}

esp_err_t pn532_i2c_wait_ready(pn532_handle_t *handle, uint32_t timeout_ms)
{
    if (handle == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t status;
    uint32_t start_time = xTaskGetTickCount() * portTICK_PERIOD_MS;

    while (true) {
        i2c_cmd_handle_t cmd = i2c_cmd_link_create();
        i2c_master_start(cmd);
        i2c_master_write_byte(cmd, (PN532_I2C_ADDRESS << 1) | I2C_MASTER_READ, true);
        i2c_master_read_byte(cmd, &status, I2C_MASTER_NACK);
        i2c_master_stop(cmd);
        
        esp_err_t ret = i2c_master_cmd_begin(handle->i2c_port, cmd, pdMS_TO_TICKS(50));
        i2c_cmd_link_delete(cmd);

        if (ret == ESP_OK && (status & PN532_I2C_READY)) {
            return ESP_OK;
        }

        // Yield to other tasks
        vTaskDelay(pdMS_TO_TICKS(5));

        uint32_t elapsed = (xTaskGetTickCount() * portTICK_PERIOD_MS) - start_time;
        if (elapsed >= timeout_ms) {
            ESP_LOGD(TAG, "Timeout waiting for PN532 ready");
            return ESP_ERR_TIMEOUT;
        }
    }
}

esp_err_t pn532_i2c_write_command(pn532_handle_t *handle, const uint8_t *data, size_t len)
{
    if (handle == NULL || data == NULL || len == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    if (len > PN532_MAX_FRAME_LEN) {
        ESP_LOGE(TAG, "Command too long: %zu bytes", len);
        return ESP_ERR_INVALID_SIZE;
    }

    ESP_LOG_BUFFER_HEX_LEVEL(TAG, data, len, ESP_LOG_DEBUG);

    i2c_cmd_handle_t cmd = i2c_cmd_link_create();
    if (cmd == NULL) {
        ESP_LOGE(TAG, "Failed to create I2C cmd link");
        return ESP_ERR_NO_MEM;
    }
    
    i2c_master_start(cmd);
    i2c_master_write_byte(cmd, (PN532_I2C_ADDRESS << 1) | I2C_MASTER_WRITE, true);
    i2c_master_write(cmd, data, len, true);
    i2c_master_stop(cmd);

    esp_err_t ret = i2c_master_cmd_begin(handle->i2c_port, cmd, pdMS_TO_TICKS(100));
    i2c_cmd_link_delete(cmd);

    if (ret != ESP_OK) {
        ESP_LOGD(TAG, "I2C write failed: %s", esp_err_to_name(ret));
    }

    return ret;
}

esp_err_t pn532_i2c_read_response(pn532_handle_t *handle, uint8_t *data, size_t *len, uint32_t timeout_ms)
{
    if (handle == NULL || data == NULL || len == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    // Wait for PN532 to be ready
    esp_err_t ret = pn532_i2c_wait_ready(handle, timeout_ms);
    if (ret != ESP_OK) {
        return ret;
    }

    // Read response with ready byte prepended
    uint8_t buffer[PN532_MAX_FRAME_LEN + 1];
    size_t read_len = sizeof(buffer);
    if (read_len > PN532_MAX_FRAME_LEN) {
        read_len = PN532_MAX_FRAME_LEN;
    }

    i2c_cmd_handle_t cmd = i2c_cmd_link_create();
    i2c_master_start(cmd);
    i2c_master_write_byte(cmd, (PN532_I2C_ADDRESS << 1) | I2C_MASTER_READ, true);
    i2c_master_read(cmd, buffer, read_len - 1, I2C_MASTER_ACK);
    i2c_master_read_byte(cmd, &buffer[read_len - 1], I2C_MASTER_NACK);
    i2c_master_stop(cmd);

    ret = i2c_master_cmd_begin(handle->i2c_port, cmd, pdMS_TO_TICKS(PN532_TIMEOUT_MS));
    i2c_cmd_link_delete(cmd);

    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "I2C read failed: %s", esp_err_to_name(ret));
        return ret;
    }

    // Skip ready byte and find frame
    if (!(buffer[0] & PN532_I2C_READY)) {
        ESP_LOGE(TAG, "PN532 not ready");
        return ESP_ERR_INVALID_STATE;
    }

    // Find preamble and start codes
    size_t offset = 1;
    while (offset < read_len - 3) {
        if (buffer[offset] == PN532_PREAMBLE &&
            buffer[offset + 1] == PN532_STARTCODE1 &&
            buffer[offset + 2] == PN532_STARTCODE2) {
            break;
        }
        offset++;
    }

    if (offset >= read_len - 6) {
        ESP_LOGE(TAG, "Start code not found in response");
        return ESP_ERR_INVALID_RESPONSE;
    }

    // Parse frame length
    uint8_t frame_len = buffer[offset + 3];
    uint8_t frame_lcs = buffer[offset + 4];

    // Verify length checksum
    if (((frame_len + frame_lcs) & 0xFF) != 0) {
        ESP_LOGE(TAG, "Invalid length checksum");
        return ESP_ERR_INVALID_CRC;
    }

    // Copy data (TFI + data, excluding checksums)
    size_t data_len = frame_len;
    if (data_len > *len) {
        ESP_LOGE(TAG, "Response too long for buffer");
        return ESP_ERR_INVALID_SIZE;
    }

    memcpy(data, &buffer[offset + 5], data_len);
    *len = data_len;

    ESP_LOG_BUFFER_HEX_LEVEL(TAG, data, *len, ESP_LOG_DEBUG);

    return ESP_OK;
}

esp_err_t pn532_i2c_read_ack(pn532_handle_t *handle)
{
    if (handle == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    // Wait for ready
    esp_err_t ret = pn532_i2c_wait_ready(handle, PN532_READY_TIMEOUT_MS);
    if (ret != ESP_OK) {
        return ret;
    }

    // Read ACK frame (ready byte + 6 bytes ACK)
    uint8_t buffer[7];
    
    i2c_cmd_handle_t cmd = i2c_cmd_link_create();
    i2c_master_start(cmd);
    i2c_master_write_byte(cmd, (PN532_I2C_ADDRESS << 1) | I2C_MASTER_READ, true);
    i2c_master_read(cmd, buffer, sizeof(buffer) - 1, I2C_MASTER_ACK);
    i2c_master_read_byte(cmd, &buffer[sizeof(buffer) - 1], I2C_MASTER_NACK);
    i2c_master_stop(cmd);

    ret = i2c_master_cmd_begin(handle->i2c_port, cmd, pdMS_TO_TICKS(PN532_TIMEOUT_MS));
    i2c_cmd_link_delete(cmd);

    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to read ACK: %s", esp_err_to_name(ret));
        return ret;
    }

    // Verify ACK frame: 0x00 0x00 0xFF 0x00 0xFF 0x00
    const uint8_t expected_ack[] = {0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00};
    if (memcmp(&buffer[1], expected_ack, sizeof(expected_ack)) != 0) {
        ESP_LOGE(TAG, "Invalid ACK frame");
        ESP_LOG_BUFFER_HEX_LEVEL(TAG, buffer, sizeof(buffer), ESP_LOG_ERROR);
        return ESP_ERR_INVALID_RESPONSE;
    }

    ESP_LOGD(TAG, "ACK received");
    return ESP_OK;
}
