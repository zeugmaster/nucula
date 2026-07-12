#pragma once

#include "cashu.hpp"
#include <string>

namespace cashu {

std::string serialize_token_v4(const Token& token);
bool deserialize_token_v4(const char* token_str, Token& out);

std::string serialize_payment_request(const PaymentRequest& req);
bool deserialize_payment_request(const char* req_str, PaymentRequest& out);

// On-device self-test: V4 token round-trip with mixed v2/v3 proofs.
bool cashu_cbor_run_tests();

} // namespace cashu

