#include "hex.h"
#include <string.h>

/* Table-driven: these run for every point/secret/DLEQ field of every
 * payment; the previous sscanf/sprintf-per-byte versions dominated keyset
 * validation time. */

static signed char nibble(char c)
{
    if (c >= '0' && c <= '9') return (signed char)(c - '0');
    if (c >= 'a' && c <= 'f') return (signed char)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return (signed char)(c - 'A' + 10);
    return -1;
}

int hex_to_bytes(const char *hex, unsigned char *out, size_t out_len)
{
    size_t hex_len = strlen(hex);
    if (hex_len != out_len * 2)
        return 0;
    for (size_t i = 0; i < out_len; i++) {
        signed char hi = nibble(hex[i * 2]);
        signed char lo = nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}

void bytes_to_hex(const unsigned char *bytes, size_t len, char *hex)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        hex[i * 2]     = digits[bytes[i] >> 4];
        hex[i * 2 + 1] = digits[bytes[i] & 0x0F];
    }
    hex[len * 2] = '\0';
}
