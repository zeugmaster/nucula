#include "bip39.h"
#include "bip39_english.h"

#include <string.h>
#include <esp_random.h>
#include <mbedtls/sha256.h>
#include <mbedtls/pkcs5.h>

static int word_index(const char *word, size_t len)
{
    for (int i = 0; i < 2048; i++) {
        if (strlen(bip39_wordlist[i]) == len &&
            memcmp(bip39_wordlist[i], word, len) == 0)
            return i;
    }
    return -1;
}

int bip39_generate(char *mnemonic, size_t size)
{
    if (!mnemonic || size < 256)
        return 0;

    /* 128 bits of entropy */
    unsigned char entropy[16];
    esp_fill_random(entropy, sizeof(entropy));

    /* SHA-256 checksum */
    unsigned char hash[32];
    mbedtls_sha256(entropy, sizeof(entropy), hash, 0);

    /* Combine entropy (128 bits) + checksum (4 bits) = 132 bits.
     * We work with the first 17 bytes (136 bits), using only 132. */
    unsigned char data[17];
    memcpy(data, entropy, 16);
    data[16] = hash[0]; /* first byte of hash contains checksum bits */

    /* Extract 12 groups of 11 bits */
    char *out = mnemonic;
    size_t remaining = size;
    for (int i = 0; i < 12; i++) {
        int bit_offset = i * 11;
        int byte_idx = bit_offset / 8;
        int bit_idx  = bit_offset % 8;

        /* Extract 11 bits spanning up to 3 bytes */
        uint32_t val = ((uint32_t)data[byte_idx] << 16) |
                       ((uint32_t)data[byte_idx + 1] << 8);
        if (byte_idx + 2 < (int)sizeof(data))
            val |= data[byte_idx + 2];
        int index = (val >> (24 - 11 - bit_idx)) & 0x7FF;

        const char *word = bip39_wordlist[index];
        size_t wlen = strlen(word);

        if (i > 0) {
            if (remaining < 2) return 0;
            *out++ = ' ';
            remaining--;
        }
        if (remaining <= wlen) return 0;
        memcpy(out, word, wlen);
        out += wlen;
        remaining -= wlen;
    }
    *out = '\0';
    return 1;
}

int bip39_validate(const char *mnemonic)
{
    if (!mnemonic)
        return 0;

    /* Parse 12 words into 11-bit indices */
    int indices[12];
    int count = 0;
    const char *p = mnemonic;

    while (*p && count < 12) {
        while (*p == ' ') p++;
        if (!*p) break;
        const char *start = p;
        while (*p && *p != ' ') p++;
        int idx = word_index(start, p - start);
        if (idx < 0)
            return 0;
        indices[count++] = idx;
    }

    if (count != 12)
        return 0;

    /* Reconstruct 132 bits from indices */
    unsigned char data[17];
    memset(data, 0, sizeof(data));
    for (int i = 0; i < 12; i++) {
        int bit_offset = i * 11;
        int byte_idx = bit_offset / 8;
        int bit_idx  = bit_offset % 8;

        /* Write 11-bit value into data at the right bit position */
        uint32_t val = (uint32_t)indices[i] << (24 - 11 - bit_idx);
        data[byte_idx]     |= (val >> 16) & 0xFF;
        data[byte_idx + 1] |= (val >> 8) & 0xFF;
        if (byte_idx + 2 < (int)sizeof(data))
            data[byte_idx + 2] |= val & 0xFF;
    }

    /* First 16 bytes = entropy, last 4 bits of byte 16 = checksum */
    unsigned char hash[32];
    mbedtls_sha256(data, 16, hash, 0);

    /* Compare top 4 bits (128-bit entropy → 4-bit checksum) */
    return (data[16] & 0xF0) == (hash[0] & 0xF0) ? 1 : 0;
}

int bip39_to_seed(const char *mnemonic, unsigned char seed[64])
{
    if (!mnemonic || !seed)
        return 0;

    int ret = mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA512,
        (const unsigned char *)mnemonic, strlen(mnemonic),
        (const unsigned char *)"mnemonic", 8,
        2048, 64, seed);

    return ret == 0 ? 1 : 0;
}
