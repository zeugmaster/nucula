#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "driver/i2c_master.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define KEYPAD_I2C_ADDR  0x20

// Add PCF8574 to the shared I2C bus (call after nfc_init).
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

// Raw PCF8574 read (all 8 pins). For diagnostics only.
esp_err_t keypad_raw_read(uint8_t *out);

// Drive one pin (0-6) low and read back — for wiring discovery.
uint8_t keypad_probe_pin(uint8_t pin);

#ifdef __cplusplus
}
#endif
