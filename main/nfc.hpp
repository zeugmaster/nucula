#ifndef NFC_HPP
#define NFC_HPP

#include <cstdint>

// NFC payment terminal using PN532 in tag emulation mode.
// Emulates an NFC Forum Type 4 NDEF tag that serves a cashu payment request
// and receives a cashu token written back by a smartphone wallet.

enum class NfcState {
    off,        // PN532 not initialized or init failed
    idle,       // initialized, no active request
    waiting,    // tag emulation active, waiting for a phone to tap
    active,     // reader connected, APDU exchange in progress
    received,   // token received, processing
    success,    // payment completed
    error,      // something went wrong
};

// Initialize the PN532 module over I2C. Call once from app_main().
// Returns true if PN532 responds and is configured.
bool nfc_init();

// Start a payment request cycle: build creqA NDEF, enter tag emulation.
// `amount` is in sats. `mint_url` may be null to accept any mint.
// Runs asynchronously in a FreeRTOS task.
bool nfc_request_start(int amount, const char *mint_url);

// Stop any active NFC operation and return to idle.
void nfc_request_stop();

// Get the current NFC state (for display/console).
NfcState nfc_state();

// Get a human-readable status string.
const char *nfc_status_str();

#endif
