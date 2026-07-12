#pragma once

#include "driver/i2c_master.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

// Create the shared I2C master bus (pins from board.h). Idempotent.
esp_err_t i2c_bus_init(void);

// Handle of the shared bus, or NULL if i2c_bus_init failed / wasn't called.
i2c_master_bus_handle_t i2c_bus_get(void);

#ifdef __cplusplus
}
#endif
