#pragma once

#include "driver/gpio.h"

// Board definition: Nucula v2 (ESP32-C3-WROOM-02-N4)
//
// One shared I2C bus carries all three peripherals, with external pull-ups
// to 3.0 V. NFC and keypad probe at boot; the disconnected OLED is held off
// during prototype bring-up. Console + wallet work without peripherals.
//
// PN7160-specific pins (IRQ/VEN) live with the driver in nci.h.

// Shared I2C bus
#define BOARD_I2C_SDA_PIN   GPIO_NUM_4
#define BOARD_I2C_SCL_PIN   GPIO_NUM_5

// SSD1309 OLED (SA0 low = 0x3C, SA0 high = 0x3D)
#define BOARD_OLED_ADDR     0x3C
// Boost input power: high enables. Reset: high asserts through Q5.
#define BOARD_OLED_POWER_PIN GPIO_NUM_3
#define BOARD_OLED_RST_PIN  GPIO_NUM_10

// PCF8574 keypad I/O expander
#define BOARD_KEYPAD_ADDR   0x20
