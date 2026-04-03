#ifndef NUCULA_BIP39_H
#define NUCULA_BIP39_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Generate a 12-word BIP39 mnemonic from 128 bits of hardware entropy.
 *
 * @param mnemonic  output buffer (must hold at least 256 bytes)
 * @param size      size of output buffer
 * @return 1 on success, 0 on failure
 */
int bip39_generate(char *mnemonic, size_t size);

/**
 * Validate a 12-word BIP39 mnemonic checksum.
 *
 * @param mnemonic  space-separated 12-word mnemonic
 * @return 1 if valid, 0 if invalid
 */
int bip39_validate(const char *mnemonic);

/**
 * Derive a 64-byte seed from a BIP39 mnemonic using PBKDF2-HMAC-SHA512.
 * Uses empty passphrase (salt = "mnemonic").
 *
 * @param mnemonic  space-separated mnemonic string
 * @param seed      64-byte output buffer
 * @return 1 on success, 0 on failure
 */
int bip39_to_seed(const char *mnemonic, unsigned char seed[64]);

#ifdef __cplusplus
}
#endif

#endif
