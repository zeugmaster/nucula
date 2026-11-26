#pragma once

#include "cashu.hpp"
#include "cJSON.h"
#include <string>

namespace cashu {

// Append a JSON-quoted, RFC 8259 escaped string to `out`.
void json_append_string(std::string& out, const char* s, size_t len);
inline void json_append_string(std::string& out, const std::string& s) {
    json_append_string(out, s.data(), s.size());
}

// Direct zero-DOM JSON serializers (single pre-reserved std::string, avoiding
// hundreds of transient cJSON tree allocations before TLS/NVS calls).
std::string serialize(const Keyset& v);
std::string serialize(const SwapRequest& v);
std::string serialize(const MintRequest& v);
std::string serialize(const MeltRequest& v);

// Non-copying request serializers for wallet flows.
std::string serialize_swap_request(const std::vector<Proof>& inputs,
                                   const std::vector<BlindedMessage>& outputs);
std::string serialize_mint_request(const std::string& quote,
                                   const std::vector<BlindedMessage>& outputs);
std::string serialize_melt_request(const std::string& quote,
                                   const std::vector<Proof>& inputs,
                                   const std::vector<BlindedMessage>* outputs);

// Deserialize model from cJSON object. Returns false if required
// fields are missing or have wrong types.
bool from_json(const cJSON* j, DLEQ& out);
bool from_json(const cJSON* j, BlindedMessage& out);
bool from_json(const cJSON* j, BlindSignature& out);
bool from_json(const cJSON* j, Proof& out);
bool from_json(const cJSON* j, Keyset& out);
bool from_json(const cJSON* j, KeysetInfo& out);
bool from_json(const cJSON* j, SwapResponse& out);
bool from_json(const cJSON* j, MintQuote& out);
bool from_json(const cJSON* j, MintResponse& out);
bool from_json(const cJSON* j, MeltQuote& out);
bool from_json(const cJSON* j, Token& out);

template<typename T>
bool from_json_array(const cJSON* arr, std::vector<T>& out) {
    if (!cJSON_IsArray(arr)) return false;
    out.clear();
    int n = cJSON_GetArraySize(arr);
    if (n > 0) out.reserve((size_t)n);
    const cJSON* elem = nullptr;
    cJSON_ArrayForEach(elem, arr) {
        T item{};
        if (!from_json(elem, item)) return false;
        out.push_back(std::move(item));
    }
    return true;
}

// Convenience: deserialize from JSON string (or length-bounded buffer).
template<typename T>
bool deserialize(const char* json_str, T& out) {
    cJSON* j = cJSON_Parse(json_str);
    if (!j) return false;
    bool ok = from_json(j, out);
    cJSON_Delete(j);
    return ok;
}

template<typename T>
bool deserialize(const char* json_str, size_t len, T& out) {
    cJSON* j = cJSON_ParseWithLength(json_str, len);
    if (!j) return false;
    bool ok = from_json(j, out);
    cJSON_Delete(j);
    return ok;
}

// Parse the {"keysets": [...]} response from GET /v1/keys or /v1/keysets
bool from_json_keyset_response(const cJSON* j, std::vector<Keyset>& out);
bool from_json_keyset_info_response(const cJSON* j, std::vector<KeysetInfo>& out);

// Parse the NUT-06 GET /v1/info response (subset: name + method matrices).
bool from_json_mint_info(const cJSON* j, MintInfo& out);

// Self-test of the quote/mint-info parse contract and direct JSON writers.
bool cashu_json_run_tests();

// Blob serialization for NVS persistence
std::string proofs_to_json(const std::vector<Proof>& proofs);
bool proofs_from_json(const char* json_str, std::vector<Proof>& out);
bool keysets_from_json(const char* json_str, std::vector<Keyset>& out);

// V3 token parsing: "cashuA..." string -> Token (receive-only; the wallet
// never emits V3 tokens)
bool deserialize_token_v3(const char* token_str, Token& out);

// Decode either token format by its prefix (cashuB -> V4, cashuA -> V3).
// Returns false for anything else.
bool deserialize_token(const char* token_str, Token& out);

} // namespace cashu
