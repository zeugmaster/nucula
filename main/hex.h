#ifndef NUCULA_HEX_H
#define NUCULA_HEX_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Decode a hex string into bytes.
 * @param hex      hex string (must be exactly out_len * 2 characters)
 * @param out      output buffer
 * @param out_len  number of bytes to decode
 * @return 1 on success, 0 on failure
 */
int hex_to_bytes(const char *hex, unsigned char *out, size_t out_len);

/**
 * Encode bytes as a lowercase hex string.
 * @param bytes  input buffer
 * @param len    number of bytes
 * @param hex    output buffer (must hold at least len * 2 + 1 bytes)
 */
void bytes_to_hex(const unsigned char *bytes, size_t len, char *hex);

#ifdef __cplusplus
}
#endif

#endif
