#include "keypad.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include <string.h>

static const char *TAG = "keypad";

static i2c_master_dev_handle_t s_dev    = NULL;
static QueueHandle_t            s_queue  = NULL;
static char                     s_held   = '\0'; // key currently held down

// Pin mapping derived from physical scan:
//   Columns (left→right): P4, P6, P2
//   Rows (top→bottom):    P5, P0, P1, P3
static const uint8_t s_col_pins[3] = {4, 6, 2};
static const uint8_t s_row_pins[4] = {5, 0, 1, 3};

static const char s_keymap[4][3] = {
    {'1', '2', '3'},
    {'4', '5', '6'},
    {'7', '8', '9'},
    {'*', '0', '#'},
};

// -------------------------------------------------------------------------
// Hardware access
// -------------------------------------------------------------------------

esp_err_t keypad_init(i2c_master_bus_handle_t bus)
{
    i2c_device_config_t dev_cfg = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address  = KEYPAD_I2C_ADDR,
        .scl_speed_hz    = 100000,
    };
    esp_err_t ret = i2c_master_bus_add_device(bus, &dev_cfg, &s_dev);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "PCF8574 add failed: %s", esp_err_to_name(ret));
        return ret;
    }
    uint8_t idle = 0xFF;
    i2c_master_transmit(s_dev, &idle, 1, 100);
    ESP_LOGI(TAG, "PCF8574 keypad ready (addr=0x%02X)", KEYPAD_I2C_ADDR);
    return ESP_OK;
}

esp_err_t keypad_raw_read(uint8_t *out)
{
    if (!s_dev) return ESP_ERR_INVALID_STATE;
    uint8_t high = 0xFF;
    esp_err_t ret = i2c_master_transmit(s_dev, &high, 1, 100);
    if (ret != ESP_OK) return ret;
    return i2c_master_receive(s_dev, out, 1, 100);
}

uint8_t keypad_probe_pin(uint8_t pin)
{
    if (!s_dev || pin > 6) return 0xFF;
    uint8_t drive = (uint8_t)(~(1u << pin)) | 0x80; // keep P7 high
    i2c_master_transmit(s_dev, &drive, 1, 100);
    vTaskDelay(pdMS_TO_TICKS(1));
    uint8_t result = 0xFF;
    i2c_master_receive(s_dev, &result, 1, 100);
    uint8_t idle = 0xFF;
    i2c_master_transmit(s_dev, &idle, 1, 100);
    return result;
}

// -------------------------------------------------------------------------
// Matrix scan — returns pressed key char or '\0'
// -------------------------------------------------------------------------

static char scan_matrix(void)
{
    if (!s_dev) return '\0';

    for (int c = 0; c < 3; c++) {
        uint8_t col_pin = s_col_pins[c];
        uint8_t drive   = (uint8_t)((~(1u << col_pin)) | 0x80);

        if (i2c_master_transmit(s_dev, &drive, 1, 50) != ESP_OK) continue;
        vTaskDelay(pdMS_TO_TICKS(1));

        uint8_t val = 0xFF;
        if (i2c_master_receive(s_dev, &val, 1, 50) != ESP_OK) continue;

        for (int r = 0; r < 4; r++) {
            if (!(val & (1u << s_row_pins[r]))) {
                uint8_t idle = 0xFF;
                i2c_master_transmit(s_dev, &idle, 1, 50);
                return s_keymap[r][c];
            }
        }
    }

    uint8_t idle = 0xFF;
    i2c_master_transmit(s_dev, &idle, 1, 50);
    return '\0';
}

// -------------------------------------------------------------------------
// Edge detection: report each key once per physical press
// -------------------------------------------------------------------------

char keypad_get_key(void)
{
    char current = scan_matrix();

    if (current && current != s_held) {
        // New key pressed (or different key while one is already held)
        s_held = current;
        return current;
    }

    if (!current) {
        // All keys released — ready for next press
        s_held = '\0';
    }

    return '\0';
}

// -------------------------------------------------------------------------
// Background task + queue
// -------------------------------------------------------------------------

static void keypad_task(void *arg)
{
    (void)arg;
    for (;;) {
        char k = keypad_get_key();
        if (k) {
            xQueueSend(s_queue, &k, 0); // don't block if queue full
        }
        vTaskDelay(pdMS_TO_TICKS(20)); // 20 ms poll = responsive + debounced
    }
}

esp_err_t keypad_start_task(void)
{
    if (s_queue) return ESP_OK; // already started

    s_queue = xQueueCreate(8, sizeof(char));
    if (!s_queue) {
        ESP_LOGE(TAG, "queue create failed");
        return ESP_ERR_NO_MEM;
    }

    if (xTaskCreate(keypad_task, "keypad", 2048, NULL, 4, NULL) != pdPASS) {
        ESP_LOGE(TAG, "task create failed");
        vQueueDelete(s_queue);
        s_queue = NULL;
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "keypad task started");
    return ESP_OK;
}

char keypad_wait_event(uint32_t timeout_ms)
{
    if (!s_queue) return '\0';
    char k = '\0';
    TickType_t ticks = timeout_ms ? pdMS_TO_TICKS(timeout_ms) : portMAX_DELAY;
    xQueueReceive(s_queue, &k, ticks);
    return k;
}
