#pragma once

#include "driver/gpio.h"

// Board definition: Seeed XIAO ESP32-C3
//
// One shared I2C bus carries all three peripherals. Each driver probes for
// its device at init and disables itself when absent, so a bare module
// still boots into a working console + wallet.
//
// PN7160-specific pins (IRQ/VEN/DWL) live with the driver in nci.h.

// Shared I2C bus
#define BOARD_I2C_SDA_PIN   GPIO_NUM_6   // D4
#define BOARD_I2C_SCL_PIN   GPIO_NUM_7   // D5

// SSD1309 OLED (SA0 low = 0x3C, SA0 high = 0x3D)
#define BOARD_OLED_ADDR     0x3C
// Optional hardware reset pin (D3). Set to -1 if not wired.
#define BOARD_OLED_RST_PIN  GPIO_NUM_5

// PCF8574 keypad I/O expander
#define BOARD_KEYPAD_ADDR   0x20
