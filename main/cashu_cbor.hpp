#ifndef CASHU_CBOR_HPP
#define CASHU_CBOR_HPP

#include "cashu.hpp"
#include <string>

namespace cashu {

std::string serialize_token_v4(const Token& token);
bool deserialize_token_v4(const char* token_str, Token& out);

std::string serialize_payment_request(const PaymentRequest& req);
bool deserialize_payment_request(const char* req_str, PaymentRequest& out);

} // namespace cashu

#endif
