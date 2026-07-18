#pragma once

#include <string>

namespace cashu {

// URL-safe base64 without padding, as used by cashu token serialization.
std::string base64url_encode(const unsigned char *data, size_t len);
bool base64url_decode(const char *input, size_t input_len, std::string &out);

} // namespace cashu
