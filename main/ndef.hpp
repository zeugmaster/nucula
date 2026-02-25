#ifndef NDEF_HPP
#define NDEF_HPP

#include <cstdint>
#include <cstddef>
#include <functional>
#include <string>

// NFC Forum Type 4 NDEF tag emulation layer.
// Handles APDU dispatch (SELECT / READ BINARY / UPDATE BINARY),
// NDEF Text record encoding/decoding, and cashu token extraction.

static const size_t NDEF_MAX_DATA_SIZE = 4096;

// Callback invoked when a complete NDEF message has been written by the reader.
// `data` points to the raw NDEF file bytes (NLEN + records), `len` is total length.
using ndef_message_cb_t = std::function<void(const uint8_t *data, size_t len)>;

// Initialize the NDEF handler state. Must be called once at startup.
void ndef_init();

// Load a payment request string as the NDEF Text record to serve on READ BINARY.
// Builds the full Type 4 NDEF file (NLEN + Text record) internally.
// Returns false if the message is too large.
bool ndef_set_message(const char *text);

// Clear the current NDEF message, preventing reads.
void ndef_clear_message();

// Register a callback for when a complete NDEF message is received via UPDATE BINARY.
void ndef_set_receive_callback(ndef_message_cb_t cb);

// Process one APDU from the reader and produce a response.
// Returns true if a response was generated, false on unrecoverable error.
bool ndef_handle_apdu(const uint8_t *apdu, size_t apdu_len,
                      uint8_t *response, size_t *response_len);

// Reset the receive buffer and write state (e.g. between payment cycles).
void ndef_reset_receive();

// Parse an NDEF Text or URI record from raw NDEF file bytes (NLEN + records).
// Extracts the UTF-8 text content into `text_out`.
bool ndef_parse_message(const uint8_t *data, size_t len, std::string &text_out);

// Extract a cashu token (cashuA.../cashuB...) from a text or URI string.
// Returns the bare token string, or empty string if not found.
std::string ndef_extract_cashu_token(const std::string &text);

#endif
