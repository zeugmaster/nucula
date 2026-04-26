#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "driver/i2c_master.h"
#include "driver/gpio.h"

// PN7160 pin definitions (XIAO ESP32-C6, shared I2C bus)
#define PN7160_SDA_PIN   GPIO_NUM_22   // D4
#define PN7160_SCL_PIN   GPIO_NUM_23   // D5
#define PN7160_IRQ_PIN   GPIO_NUM_0    // D0
#define PN7160_VEN_PIN   GPIO_NUM_1    // D1
#define PN7160_DWL_PIN   GPIO_NUM_2    // D2

// PN7160 I2C address (both addr pins NC = default)
#define PN7160_I2C_ADDR  0x28

// NCI Message Type (bits 7-5 of byte 0)
#define NCI_MT_CMD       0x20
#define NCI_MT_RSP       0x40
#define NCI_MT_NTF       0x60
#define NCI_MT_DATA      0x00

// NCI Group IDs
#define NCI_GID_CORE     0x00
#define NCI_GID_RF       0x01
#define NCI_GID_NFCEE    0x02
#define NCI_GID_PROP     0x0F

// NCI Core OIDs
#define NCI_OID_CORE_RESET       0x00
#define NCI_OID_CORE_INIT        0x01
#define NCI_OID_CORE_SET_CONFIG  0x02
#define NCI_OID_CORE_GET_CONFIG  0x03

// NCI RF OIDs
#define NCI_OID_RF_DISCOVER_MAP  0x00
#define NCI_OID_RF_SET_ROUTING   0x01
#define NCI_OID_RF_DISCOVER      0x03
#define NCI_OID_RF_DISCOVER_SEL  0x04
#define NCI_OID_RF_DEACTIVATE    0x06

// NCI Notification OIDs
#define NCI_RF_INTF_ACTIVATED_NTF  0x05
#define NCI_RF_DEACTIVATE_NTF      0x06
#define NCI_RF_DISCOVER_NTF        0x03

// Protocols
#define NCI_PROTOCOL_ISO_DEP      0x04

// Interfaces
#define NCI_INTERFACE_ISO_DEP     0x02

// Modes / Technologies
#define NCI_MODE_LISTEN           0x80
#define NCI_TECH_PASSIVE_NFCA     0x00

// Max NCI frame size (3 header + 255 payload)
#define NCI_MAX_FRAME_SIZE        258

// NCI driver context — holds I2C handles and saved discovery command
typedef struct {
    i2c_master_bus_handle_t i2c_bus;
    i2c_master_dev_handle_t i2c_dev;
    uint8_t  rx_buf[NCI_MAX_FRAME_SIZE];
    uint32_t rx_len;
    uint8_t  discovery_cmd[30];
    uint8_t  discovery_cmd_len;
} nci_context_t;

#ifdef __cplusplus
extern "C" {
#endif

// Initialize I2C bus + GPIO, hardware-reset PN7160.
// If ctx->i2c_bus is already set only the HW reset is performed.
esp_err_t nci_init(nci_context_t *ctx);

// Low-level I2C primitives
esp_err_t nci_write(nci_context_t *ctx, const uint8_t *data, uint32_t len);
esp_err_t nci_read(nci_context_t *ctx, uint8_t *data, uint32_t *len);

// Poll IRQ pin until HIGH (data ready). Returns false on timeout (0 = forever).
bool nci_wait_for_irq(uint32_t timeout_ms);

// Write command, wait for IRQ, read response into ctx->rx_buf / ctx->rx_len.
esp_err_t nci_transceive(nci_context_t *ctx, const uint8_t *cmd, uint32_t cmd_len,
                         uint32_t timeout_ms);

// High-level NCI initialisation sequence
esp_err_t nci_core_reset(nci_context_t *ctx);
esp_err_t nci_core_init(nci_context_t *ctx);
esp_err_t nci_configure_settings(nci_context_t *ctx);
esp_err_t nci_configure_cardemu_mode(nci_context_t *ctx);
esp_err_t nci_start_discovery_cardemu(nci_context_t *ctx);

// Run the full init + card-emulation config sequence
esp_err_t nci_setup_cardemu(nci_context_t *ctx);

#ifdef __cplusplus
}
#endif
