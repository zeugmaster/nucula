#ifndef NFC_HPP
#define NFC_HPP

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

bool        nfc_init();
bool        nfc_request_start(int amount, const char *mint_url);
void        nfc_request_stop();
NfcState    nfc_state();
const char *nfc_status_str();

// Expose shared I2C bus handle so other drivers (keypad) can add devices
i2c_master_bus_handle_t nfc_get_i2c_bus();

#endif
