#include "base64url.hpp"

#include <cstdint>

namespace cashu {

static const char B64URL_ENC[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// Accepts both URL-safe (-, _) and standard (+, /) alphabets.
static const int8_t B64URL_DEC[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,62,-1,63,
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,63,
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
};

void base64url_encode_append(const unsigned char *data, size_t len, std::string &out)
{
    const size_t enc_len = (len / 3) * 4 + (len % 3 == 0 ? 0 : (len % 3) + 1);
    const size_t start = out.size();
    out.resize(start + enc_len);
    char *dst = out.data() + start;

    size_t i = 0;
    while (i + 3 <= len) {
        uint32_t v = ((uint32_t)data[i] << 16) |
                     ((uint32_t)data[i + 1] << 8) |
                     (uint32_t)data[i + 2];
        dst[0] = B64URL_ENC[(v >> 18) & 0x3F];
        dst[1] = B64URL_ENC[(v >> 12) & 0x3F];
        dst[2] = B64URL_ENC[(v >> 6) & 0x3F];
        dst[3] = B64URL_ENC[v & 0x3F];
        dst += 4;
        i += 3;
    }

    size_t rem = len - i;
    if (rem == 1) {
        uint32_t v = (uint32_t)data[i];
        dst[0] = B64URL_ENC[(v >> 2) & 0x3F];
        dst[1] = B64URL_ENC[(v << 4) & 0x3F];
    } else if (rem == 2) {
        uint32_t v = ((uint32_t)data[i] << 8) | (uint32_t)data[i + 1];
        dst[0] = B64URL_ENC[(v >> 10) & 0x3F];
        dst[1] = B64URL_ENC[(v >> 4) & 0x3F];
        dst[2] = B64URL_ENC[(v << 2) & 0x3F];
    }
}

std::string base64url_encode(const unsigned char *data, size_t len)
{
    std::string result;
    base64url_encode_append(data, len, result);
    return result;
}

bool base64url_decode(const char *input, size_t input_len, std::string &out)
{
    if (!input && input_len != 0)
        return false;

    // Strip up to two trailing '=' padding characters.
    size_t pad = 0;
    while (input_len > 0 && input[input_len - 1] == '=' && pad < 2) {
        input_len--;
        pad++;
    }

    const size_t rem = input_len & 3;
    if (rem == 1)
        return false;

    const size_t full_quads = input_len >> 2;
    const size_t dec_len = full_quads * 3 + (rem ? rem - 1 : 0);
    out.resize(dec_len);

    const unsigned char *src = (const unsigned char *)input;
    unsigned char *dst = (unsigned char *)out.data();

    for (size_t q = 0; q < full_quads; q++) {
        int8_t a = B64URL_DEC[src[0]];
        int8_t b = B64URL_DEC[src[1]];
        int8_t c = B64URL_DEC[src[2]];
        int8_t d = B64URL_DEC[src[3]];
        if ((a | b | c | d) < 0)
            return false;
        uint32_t v = ((uint32_t)a << 18) | ((uint32_t)b << 12) |
                     ((uint32_t)c << 6) | (uint32_t)d;
        dst[0] = (unsigned char)(v >> 16);
        dst[1] = (unsigned char)(v >> 8);
        dst[2] = (unsigned char)v;
        src += 4;
        dst += 3;
    }

    if (rem == 2) {
        int8_t a = B64URL_DEC[src[0]];
        int8_t b = B64URL_DEC[src[1]];
        if ((a | b) < 0)
            return false;
        dst[0] = (unsigned char)(((uint32_t)a << 2) | ((uint32_t)b >> 4));
    } else if (rem == 3) {
        int8_t a = B64URL_DEC[src[0]];
        int8_t b = B64URL_DEC[src[1]];
        int8_t c = B64URL_DEC[src[2]];
        if ((a | b | c) < 0)
            return false;
        uint32_t v = ((uint32_t)a << 12) | ((uint32_t)b << 6) | (uint32_t)c;
        dst[0] = (unsigned char)(v >> 10);
        dst[1] = (unsigned char)(v >> 2);
    }

    return true;
}

} // namespace cashu
