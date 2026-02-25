/**
 * @file pn532.h
 * @brief PN532 NFC Controller Driver for ESP-IDF
 * 
 * This driver provides an interface for the NXP PN532 NFC controller
 * connected via I2C, SPI, or UART. Supports tag emulation mode with NDEF messages.
 */

#ifndef PN532_H
#define PN532_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"
#include "driver/i2c.h"
#include "driver/spi_master.h"

#ifdef __cplusplus
extern "C" {
#endif

// PN532 I2C Address
#define PN532_I2C_ADDRESS           0x24

// PN532 Commands
#define PN532_COMMAND_GETFIRMWAREVERSION    0x02
#define PN532_COMMAND_SAMCONFIGURATION      0x14
#define PN532_COMMAND_INRELEASE             0x52
#define PN532_COMMAND_TGINITASTARGET        0x8C
#define PN532_COMMAND_TGGETDATA             0x86
#define PN532_COMMAND_TGSETDATA             0x8E
#define PN532_COMMAND_TGGETINITIATORCOMMAND 0x88
#define PN532_COMMAND_TGRESPONSETOINITIATOR 0x90

// PN532 Frame markers
#define PN532_PREAMBLE              0x00
#define PN532_STARTCODE1            0x00
#define PN532_STARTCODE2            0xFF
#define PN532_POSTAMBLE             0x00

// PN532 Frame identifiers
#define PN532_HOSTTOPN532           0xD4
#define PN532_PN532TOHOST           0xD5

// SAM configuration modes
#define PN532_SAM_NORMAL_MODE       0x01
#define PN532_SAM_VIRTUAL_CARD      0x02
#define PN532_SAM_WIRED_CARD        0x03
#define PN532_SAM_DUAL_CARD         0x04

// Target modes for TgInitAsTarget
#define PN532_TGIT_MODE_PASSIVE_106     0x00
#define PN532_TGIT_MODE_DEP             0x01
#define PN532_TGIT_MODE_PICC            0x04

// NFC-A Commands
#define NFC_CMD_REQA                0x26
#define NFC_CMD_WUPA                0x52
#define NFC_CMD_ANTICOLL_CL1        0x93
#define NFC_CMD_ANTICOLL_CL2        0x95
#define NFC_CMD_SELECT_CL1          0x93
#define NFC_CMD_SELECT_CL2          0x95
#define NFC_CMD_RATS                0xE0
#define NFC_CMD_HLTA                0x50

// Type 4 Tag Commands (ISO-DEP)
#define T4T_CMD_SELECT              0xA4
#define T4T_CMD_READ_BINARY         0xB0

// NDEF Application
#define NDEF_AID_V2                 {0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01}
#define NDEF_CC_FILE_ID             {0xE1, 0x03}
#define NDEF_FILE_ID                {0xE1, 0x04}

// Buffer sizes
#define PN532_MAX_FRAME_LEN         265
#define PN532_ACK_FRAME_LEN         6

// Timeouts
#define PN532_TIMEOUT_MS            1000
#define PN532_READY_TIMEOUT_MS      1000
#define PN532_ACK_WAIT_TIME         100

// Default UART baud rate for PN532 HSU mode
#define PN532_UART_BAUD_RATE        115200

/**
 * @brief Transport type for PN532 communication
 */
typedef enum {
    PN532_TRANSPORT_I2C,
    PN532_TRANSPORT_SPI,
    PN532_TRANSPORT_UART,
} pn532_transport_t;

/**
 * @brief PN532 device handle
 */
typedef struct {
    pn532_transport_t transport;
    union {
        i2c_port_t i2c_port;
        struct {
            spi_device_handle_t spi_handle;
            int spi_ss_gpio;
        };
    };
    uint8_t command_buffer[PN532_MAX_FRAME_LEN];
    uint8_t response_buffer[PN532_MAX_FRAME_LEN];
} pn532_handle_t;

/**
 * @brief PN532 I2C configuration
 */
typedef struct {
    int sda_gpio;
    int scl_gpio;
    uint32_t clk_speed_hz;
    i2c_port_t i2c_port;
} pn532_i2c_config_t;

/**
 * @brief PN532 SPI configuration
 */
typedef struct {
    int sck_gpio;
    int miso_gpio;
    int mosi_gpio;
    int ss_gpio;
    uint32_t clk_speed_hz;
} pn532_spi_config_t;

/**
 * @brief PN532 UART configuration
 */
typedef struct {
    int tx_gpio;
    int rx_gpio;
    uint32_t baud_rate;
} pn532_uart_config_t;

/**
 * @brief PN532 firmware version information
 */
typedef struct {
    uint8_t ic;
    uint8_t ver;
    uint8_t rev;
    uint8_t support;
} pn532_firmware_version_t;

/**
 * @brief NDEF Text Record structure
 */
typedef struct {
    const char *language_code;
    const char *text;
} ndef_text_record_t;

// ==================== I2C Transport Functions ====================

/**
 * @brief Initialize I2C bus for PN532 communication
 */
esp_err_t pn532_i2c_init(pn532_handle_t *handle, const pn532_i2c_config_t *config);

/**
 * @brief Deinitialize I2C bus
 */
esp_err_t pn532_i2c_deinit(pn532_handle_t *handle);

/**
 * @brief Wait for PN532 to be ready (I2C)
 */
esp_err_t pn532_i2c_wait_ready(pn532_handle_t *handle, uint32_t timeout_ms);

/**
 * @brief Send command frame to PN532 (I2C)
 */
esp_err_t pn532_i2c_write_command(pn532_handle_t *handle, const uint8_t *data, size_t len);

/**
 * @brief Read response frame from PN532 (I2C)
 */
esp_err_t pn532_i2c_read_response(pn532_handle_t *handle, uint8_t *data, size_t *len, uint32_t timeout_ms);

/**
 * @brief Read ACK frame from PN532 (I2C)
 */
esp_err_t pn532_i2c_read_ack(pn532_handle_t *handle);

// ==================== SPI Transport Functions ====================

/**
 * @brief Initialize SPI bus for PN532 communication
 */
esp_err_t pn532_spi_init(pn532_handle_t *handle, const pn532_spi_config_t *config);

/**
 * @brief Deinitialize SPI bus
 */
esp_err_t pn532_spi_deinit(pn532_handle_t *handle);

/**
 * @brief Send wakeup sequence via SPI
 */
esp_err_t pn532_spi_wakeup(pn532_handle_t *handle);

/**
 * @brief Wait for PN532 to be ready (SPI)
 */
esp_err_t pn532_spi_wait_ready(pn532_handle_t *handle, uint32_t timeout_ms);

/**
 * @brief Send command frame to PN532 (SPI)
 */
esp_err_t pn532_spi_write_command(pn532_handle_t *handle, const uint8_t *data, size_t len);

/**
 * @brief Read response frame from PN532 (SPI)
 */
esp_err_t pn532_spi_read_response(pn532_handle_t *handle, uint8_t *data, size_t *len, uint32_t timeout_ms);

/**
 * @brief Read ACK frame from PN532 (SPI)
 */
esp_err_t pn532_spi_read_ack(pn532_handle_t *handle);

// ==================== UART Transport Functions ====================

/**
 * @brief Initialize UART for PN532 communication (HSU mode)
 */
esp_err_t pn532_uart_init(pn532_handle_t *handle, int tx_gpio, int rx_gpio, uint32_t baud_rate);

/**
 * @brief Deinitialize UART
 */
esp_err_t pn532_uart_deinit(pn532_handle_t *handle);

/**
 * @brief Send wakeup sequence via UART
 */
esp_err_t pn532_uart_wakeup(pn532_handle_t *handle);

/**
 * @brief Send command frame to PN532 via UART
 */
esp_err_t pn532_uart_write_command(pn532_handle_t *handle, uint8_t command,
                                    const uint8_t *params, size_t params_len);

/**
 * @brief Read response frame from PN532 via UART
 */
esp_err_t pn532_uart_read_response(pn532_handle_t *handle, uint8_t *response,
                                    size_t *response_len, uint32_t timeout_ms);

// ==================== PN532 Core Functions ====================

/**
 * @brief Initialize PN532 device using I2C
 */
esp_err_t pn532_init(pn532_handle_t *handle, const pn532_i2c_config_t *config);

/**
 * @brief Initialize PN532 device using SPI
 */
esp_err_t pn532_init_spi(pn532_handle_t *handle, const pn532_spi_config_t *config);

/**
 * @brief Initialize PN532 device using UART
 */
esp_err_t pn532_init_uart(pn532_handle_t *handle, const pn532_uart_config_t *config);

/**
 * @brief Deinitialize PN532 device
 */
esp_err_t pn532_deinit(pn532_handle_t *handle);

/**
 * @brief Send command and receive response
 */
esp_err_t pn532_send_command(pn532_handle_t *handle, uint8_t cmd, 
                              const uint8_t *params, size_t params_len,
                              uint8_t *response, size_t *response_len,
                              uint32_t timeout_ms);

/**
 * @brief Get PN532 firmware version
 */
esp_err_t pn532_get_firmware_version(pn532_handle_t *handle, pn532_firmware_version_t *version);

/**
 * @brief Configure SAM (Security Access Module)
 */
esp_err_t pn532_sam_configuration(pn532_handle_t *handle, uint8_t mode, uint8_t timeout, bool use_irq);

// ==================== Tag Emulation Functions ====================

/**
 * @brief Initialize as NFC target (tag emulation mode)
 * 
 * @param handle PN532 device handle
 * @param ndef_message NDEF message data to serve
 * @param ndef_len Length of NDEF message
 * @return esp_err_t ESP_OK on success
 */
esp_err_t pn532_emulate_tag(pn532_handle_t *handle, const uint8_t *ndef_message, size_t ndef_len);

/**
 * @brief Process a single tag emulation cycle
 * 
 * @param handle PN532 device handle
 * @param ndef_message NDEF message data to serve
 * @param ndef_len Length of NDEF message
 * @return esp_err_t ESP_OK if processed successfully, ESP_ERR_TIMEOUT if no reader present
 */
esp_err_t pn532_emulate_tag_loop(pn532_handle_t *handle, const uint8_t *ndef_message, size_t ndef_len);

/**
 * @brief Set callback for NDEF write events
 * 
 * The callback will be invoked when an NFC reader writes NDEF data to the tag.
 * 
 * @param callback Function to call with written NDEF data (data, length)
 */
void pn532_set_write_callback(void (*callback)(const uint8_t *data, size_t len));

// ==================== NDEF Functions ====================

/**
 * @brief Create NDEF Text Record
 * 
 * @param record Text record configuration
 * @param buffer Output buffer for NDEF message
 * @param buffer_size Size of output buffer
 * @param message_len Output: actual message length
 * @return esp_err_t ESP_OK on success
 */
esp_err_t ndef_create_text_record(const ndef_text_record_t *record, 
                                   uint8_t *buffer, size_t buffer_size, 
                                   size_t *message_len);

/**
 * @brief Create an NDEF URL record
 * 
 * URI Prefix Codes:
 *   0x00 = No prefix
 *   0x01 = http://www.
 *   0x02 = https://www.
 *   0x03 = http://
 *   0x04 = https://
 * 
 * @param prefix_code URI prefix code
 * @param url URL string (without the prefix)
 * @param buffer Output buffer
 * @param buffer_size Buffer size
 * @param message_len Output: actual message length
 * @return esp_err_t ESP_OK on success
 */
esp_err_t ndef_create_url_record(uint8_t prefix_code, const char *url,
                                  uint8_t *buffer, size_t buffer_size,
                                  size_t *message_len);

#ifdef __cplusplus
}
#endif

#endif // PN532_H
