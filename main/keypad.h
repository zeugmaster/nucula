#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "driver/i2c_master.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

// Probe for the PCF8574 on the shared I2C bus and add it as a device.
// Returns ESP_ERR_NOT_FOUND when the keypad is absent.
esp_err_t keypad_init(i2c_master_bus_handle_t bus);

// Start the background polling task and event queue.
// Must be called after keypad_init(). Safe to call once only.
esp_err_t keypad_start_task(void);

// Non-blocking edge-detected read.
// Returns the key character on the first scan after a new press,
// '\0' if nothing new since the last call.
char keypad_get_key(void);

// Block until a key is pressed (edge-triggered) or timeout elapses.
// timeout_ms == 0 waits forever. Returns '\0' on timeout.
// Consumes the event from the internal queue.
char keypad_wait_event(uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif
