#include "base64url.hpp"

#include <mbedtls/base64.h>

namespace cashu {

std::string base64url_encode(const unsigned char *data, size_t len)
{
    size_t out_len = 0;
    mbedtls_base64_encode(nullptr, 0, &out_len, data, len);
    std::string result(out_len, '\0');
    mbedtls_base64_encode((unsigned char *)result.data(), out_len, &out_len,
                          data, len);
    result.resize(out_len);
    for (char &c : result) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }
    while (!result.empty() && result.back() == '=')
        result.pop_back();
    return result;
}

bool base64url_decode(const char *input, size_t input_len, std::string &out)
{
    std::string b64(input, input_len);
    for (char &c : b64) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    while (b64.size() % 4 != 0)
        b64.push_back('=');

    size_t out_len = 0;
    int ret = mbedtls_base64_decode(nullptr, 0, &out_len,
                                    (const unsigned char *)b64.data(),
                                    b64.size());
    if (ret != 0 && ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
        return false;

    out.resize(out_len);
    ret = mbedtls_base64_decode((unsigned char *)out.data(), out_len, &out_len,
                                (const unsigned char *)b64.data(),
                                b64.size());
    if (ret != 0) return false;
    out.resize(out_len);
    return true;
}

} // namespace cashu
