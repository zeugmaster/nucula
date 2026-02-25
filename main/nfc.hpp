#ifndef NFC_HPP
#define NFC_HPP

#include <cstdint>

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

bool nfc_init();
bool nfc_request_start(int amount, const char *mint_url);
void nfc_request_stop();
NfcState nfc_state();
const char *nfc_status_str();

#endif
