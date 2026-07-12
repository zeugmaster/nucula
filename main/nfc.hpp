#pragma once

#include <cstdint>
#include "driver/i2c_master.h"

enum class NfcState {
    off,
    idle,
    waiting,
    active,
    received,
    redeeming,
    success,
    error,
};

// Bring up the PN7160 on the shared I2C bus. Returns false when the chip is
// absent or unresponsive; NFC commands are disabled then.
bool        nfc_init(i2c_master_bus_handle_t bus);
// Start a NUT-18 payment request for `amount` of `unit` (nullptr/"" means
// the wallet's default unit). Optional mint_url pins the request to a mint.
bool        nfc_request_start(int amount, const char *unit, const char *mint_url);
void        nfc_request_stop();
NfcState    nfc_state();
const char *nfc_status_str();

