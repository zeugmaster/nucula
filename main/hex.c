#include "hex.h"
#include <stdint.h>
#include <string.h>

/* Table-driven hex codec: runs on every point/secret/DLEQ field. */

static const int8_t HEX_LUT[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
     0, 1, 2, 3, 4, 5, 6, 7, 8, 9,-1,-1,-1,-1,-1,-1,
    -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
};

int hex_to_bytes(const char *hex, unsigned char *out, size_t out_len)
{
    const unsigned char *p = (const unsigned char *)hex;
    for (size_t i = 0; i < out_len; i++) {
        int8_t hi = HEX_LUT[p[0]];
        if (hi < 0)
            return 0;
        int8_t lo = HEX_LUT[p[1]];
        if (lo < 0)
            return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
        p += 2;
    }
    return *p == '\0' ? 1 : 0;
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
