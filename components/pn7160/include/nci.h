#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "driver/i2c_master.h"
#include "driver/gpio.h"

// PN7160 control pins (XIAO ESP32-C3). The I2C bus itself is owned by the
// application and passed into nci_init().
// VEN is on GPIO 2 (a boot strapping pin) — empirically OK at boot because
// the ESP weak internal pull-up wins over the PN7160 VEN input leakage.
// DWL is left on an unused output (no external wire); PN7160 defaults to
// NCI mode when DWL is undriven.
#define PN7160_IRQ_PIN   GPIO_NUM_3    // D1
#define PN7160_VEN_PIN   GPIO_NUM_2    // D0
#define PN7160_DWL_PIN   GPIO_NUM_4    // D2 (dangling)

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

// NCI Core NTF OIDs seen in the steady-state event loop
#define NCI_OID_CORE_CONN_CREDITS    0x06
#define NCI_OID_CORE_GENERIC_ERROR   0x07
#define NCI_OID_CORE_INTERFACE_ERROR 0x08

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

// Configure GPIOs, hardware-reset the PN7160, probe it on the given bus and
// add it as an I2C device. Returns ESP_ERR_NOT_FOUND when the chip does not
// respond to its address (absent hardware) — callers should not retry then.
// On repeat calls with an already-added device only the HW reset + probe run.
esp_err_t nci_init(nci_context_t *ctx, i2c_master_bus_handle_t bus);

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
esp_err_t nci_setup_cardemu(nci_context_t *ctx, i2c_master_bus_handle_t bus);

// --- Steady-state API for the card-emulation event loop -------------------
// The app should not touch nci_context_t fields; these cover the loop's
// needs: wait for a frame, inspect it, answer with DATA, restart discovery.

// Wait up to timeout_ms for IRQ, then read one frame into the context.
// False on timeout, I2C error, or an empty read.
bool nci_poll_frame(nci_context_t *ctx, uint32_t timeout_ms);

// The last frame read by nci_poll_frame/nci_transceive, and its length.
const uint8_t *nci_frame(const nci_context_t *ctx);
uint32_t       nci_frame_len(const nci_context_t *ctx);

// Build and send one NCI DATA frame on conn 0 carrying `payload`.
// ESP_ERR_INVALID_SIZE when the payload exceeds one frame.
esp_err_t nci_send_data(nci_context_t *ctx, const uint8_t *payload, size_t len);

// RF_DEACTIVATE (to idle), drain until its RSP arrives, then replay the
// discovery command stored by nci_start_discovery_cardemu. Called after a
// reader deactivates without finishing.
esp_err_t nci_restart_discovery(nci_context_t *ctx);

#ifdef __cplusplus
}
#endif
