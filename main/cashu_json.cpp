#include "cashu_json.hpp"
#include <cstdlib>
#include <cstring>
#include <mbedtls/base64.h>

namespace cashu {

static const char* get_string(const cJSON* obj, const char* key) {
    const cJSON* item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!item || !cJSON_IsString(item)) return nullptr;
    return item->valuestring;
}

static bool get_int(const cJSON* obj, const char* key, int& out) {
    const cJSON* item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!item || !cJSON_IsNumber(item)) return false;
    out = item->valueint;
    return true;
}

static bool get_int64(const cJSON* obj, const char* key, int64_t& out) {
    const cJSON* item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!item || !cJSON_IsNumber(item)) return false;
    out = (int64_t)item->valuedouble;
    return true;
}

static bool get_bool(const cJSON* obj, const char* key, bool& out) {
    const cJSON* item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!item) return false;
    if (cJSON_IsTrue(item)) { out = true; return true; }
    if (cJSON_IsFalse(item)) { out = false; return true; }
    if (cJSON_IsNumber(item)) { out = item->valueint != 0; return true; }
    return false;
}

// ---------------------------------------------------------------------------
// DLEQ
// ---------------------------------------------------------------------------

cJSON* to_json(const DLEQ& v) {
    cJSON* j = cJSON_CreateObject();
    cJSON_AddStringToObject(j, "e", v.e.c_str());
    cJSON_AddStringToObject(j, "s", v.s.c_str());
    if (v.r)
        cJSON_AddStringToObject(j, "r", v.r->c_str());
    return j;
}

bool from_json(const cJSON* j, DLEQ& out) {
    const char* e = get_string(j, "e");
    const char* s = get_string(j, "s");
    if (!e || !s) return false;
    out.e = e;
    out.s = s;
    const char* r = get_string(j, "r");
    out.r = r ? std::optional<std::string>(r) : std::nullopt;
    return true;
}

// ---------------------------------------------------------------------------
// BlindedMessage
// ---------------------------------------------------------------------------

cJSON* to_json(const BlindedMessage& v) {
    cJSON* j = cJSON_CreateObject();
    cJSON_AddNumberToObject(j, "amount", v.amount);
    cJSON_AddStringToObject(j, "B_", v.B_.c_str());
    cJSON_AddStringToObject(j, "id", v.id.c_str());
    return j;
}

bool from_json(const cJSON* j, BlindedMessage& out) {
    const char* B_ = get_string(j, "B_");
    const char* id = get_string(j, "id");
    if (!B_ || !id) return false;
    if (!get_int(j, "amount", out.amount)) return false;
    out.B_ = B_;
    out.id = id;
    return true;
}

// ---------------------------------------------------------------------------
// BlindSignature
// ---------------------------------------------------------------------------

cJSON* to_json(const BlindSignature& v) {
    cJSON* j = cJSON_CreateObject();
    cJSON_AddStringToObject(j, "id", v.id.c_str());
    cJSON_AddNumberToObject(j, "amount", v.amount);
    cJSON_AddStringToObject(j, "C_", v.C_.c_str());
    if (v.dleq)
        cJSON_AddItemToObject(j, "dleq", to_json(*v.dleq));
    return j;
}

bool from_json(const cJSON* j, BlindSignature& out) {
    const char* id = get_string(j, "id");
    const char* C_ = get_string(j, "C_");
    if (!id || !C_) return false;
    if (!get_int(j, "amount", out.amount)) return false;
    out.id = id;
    out.C_ = C_;
    const cJSON* dleq = cJSON_GetObjectItemCaseSensitive(j, "dleq");
    if (dleq && cJSON_IsObject(dleq)) {
        DLEQ d{};
        if (from_json(dleq, d))
            out.dleq = std::move(d);
    } else {
        out.dleq = std::nullopt;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Proof
// ---------------------------------------------------------------------------

cJSON* to_json(const Proof& v) {
    cJSON* j = cJSON_CreateObject();
    cJSON_AddStringToObject(j, "id", v.id.c_str());
    cJSON_AddNumberToObject(j, "amount", v.amount);
    cJSON_AddStringToObject(j, "secret", v.secret.c_str());
    cJSON_AddStringToObject(j, "C", v.C.c_str());
    if (v.dleq)
        cJSON_AddItemToObject(j, "dleq", to_json(*v.dleq));
    if (v.witness)
        cJSON_AddStringToObject(j, "witness", v.witness->c_str());
    return j;
}

bool from_json(const cJSON* j, Proof& out) {
    const char* id = get_string(j, "id");
    const char* secret = get_string(j, "secret");
    const char* C = get_string(j, "C");
    if (!id || !secret || !C) return false;
    if (!get_int(j, "amount", out.amount)) return false;
    out.id = id;
    out.secret = secret;
    out.C = C;
    const cJSON* dleq = cJSON_GetObjectItemCaseSensitive(j, "dleq");
    if (dleq && cJSON_IsObject(dleq)) {
        DLEQ d{};
        if (from_json(dleq, d))
            out.dleq = std::move(d);
    } else {
        out.dleq = std::nullopt;
    }
    const char* witness = get_string(j, "witness");
    out.witness = witness ? std::optional<std::string>(witness) : std::nullopt;
    return true;
}

// ---------------------------------------------------------------------------
// Keyset
// ---------------------------------------------------------------------------

cJSON* to_json(const Keyset& v) {
    cJSON* j = cJSON_CreateObject();
    cJSON_AddStringToObject(j, "id", v.id.c_str());
    cJSON_AddStringToObject(j, "unit", v.unit.c_str());
    cJSON_AddBoolToObject(j, "active", v.active);
    cJSON_AddNumberToObject(j, "input_fee_ppk", v.input_fee_ppk);
    cJSON* keys = cJSON_CreateObject();
    for (const auto& [amount, pubkey] : v.keys) {
        std::string key = std::to_string(amount);
        cJSON_AddStringToObject(keys, key.c_str(), pubkey.c_str());
    }
    cJSON_AddItemToObject(j, "keys", keys);
    return j;
}

bool from_json(const cJSON* j, Keyset& out) {
    const char* id = get_string(j, "id");
    const char* unit = get_string(j, "unit");
    if (!id || !unit) return false;
    out.id = id;
    out.unit = unit;
    if (!get_bool(j, "active", out.active))
        out.active = true;
    if (!get_int(j, "input_fee_ppk", out.input_fee_ppk))
        out.input_fee_ppk = 0;
    out.keys.clear();
    const cJSON* keys = cJSON_GetObjectItemCaseSensitive(j, "keys");
    if (keys && cJSON_IsObject(keys)) {
        const cJSON* entry = nullptr;
        cJSON_ArrayForEach(entry, keys) {
            if (!cJSON_IsString(entry)) continue;
            uint64_t amount = strtoull(entry->string, nullptr, 10);
            out.keys[amount] = entry->valuestring;
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// KeysetInfo
// ---------------------------------------------------------------------------

cJSON* to_json(const KeysetInfo& v) {
    cJSON* j = cJSON_CreateObject();
    cJSON_AddStringToObject(j, "id", v.id.c_str());
    cJSON_AddStringToObject(j, "unit", v.unit.c_str());
    cJSON_AddBoolToObject(j, "active", v.active);
    cJSON_AddNumberToObject(j, "input_fee_ppk", v.input_fee_ppk);
    return j;
}

bool from_json(const cJSON* j, KeysetInfo& out) {
    const char* id = get_string(j, "id");
    const char* unit = get_string(j, "unit");
    if (!id || !unit) return false;
    out.id = id;
    out.unit = unit;
    if (!get_bool(j, "active", out.active))
        out.active = true;
    if (!get_int(j, "input_fee_ppk", out.input_fee_ppk))
        out.input_fee_ppk = 0;
    return true;
}

// ---------------------------------------------------------------------------
// SwapRequest / SwapResponse
// ---------------------------------------------------------------------------

cJSON* to_json(const SwapRequest& v) {
    cJSON* j = cJSON_CreateObject();
    cJSON_AddItemToObject(j, "inputs", to_json_array(v.inputs));
    cJSON_AddItemToObject(j, "outputs", to_json_array(v.outputs));
    return j;
}

cJSON* to_json(const SwapResponse& v) {
    cJSON* j = cJSON_CreateObject();
    cJSON_AddItemToObject(j, "signatures", to_json_array(v.signatures));
    return j;
}

bool from_json(const cJSON* j, SwapResponse& out) {
    const cJSON* sigs = cJSON_GetObjectItemCaseSensitive(j, "signatures");
    if (!sigs) return false;
    return from_json_array(sigs, out.signatures);
}

// ---------------------------------------------------------------------------
// MintQuote
// ---------------------------------------------------------------------------

cJSON* to_json(const MintQuote& v) {
    cJSON* j = cJSON_CreateObject();
    cJSON_AddStringToObject(j, "quote", v.quote.c_str());
    cJSON_AddStringToObject(j, "request", v.request.c_str());
    cJSON_AddStringToObject(j, "state", v.state.c_str());
    cJSON_AddNumberToObject(j, "expiry", (double)v.expiry);
    return j;
}

bool from_json(const cJSON* j, MintQuote& out) {
    const char* quote = get_string(j, "quote");
    const char* request = get_string(j, "request");
    const char* state = get_string(j, "state");
    if (!quote || !request || !state) return false;
    out.quote = quote;
    out.request = request;
    out.state = state;
    if (!get_int64(j, "expiry", out.expiry))
        out.expiry = 0;
    return true;
}

// ---------------------------------------------------------------------------
// MintRequest / MintResponse
// ---------------------------------------------------------------------------

cJSON* to_json(const MintRequest& v) {
    cJSON* j = cJSON_CreateObject();
    cJSON_AddStringToObject(j, "quote", v.quote.c_str());
    cJSON_AddItemToObject(j, "outputs", to_json_array(v.outputs));
    return j;
}

cJSON* to_json(const MintResponse& v) {
    cJSON* j = cJSON_CreateObject();
    cJSON_AddItemToObject(j, "signatures", to_json_array(v.signatures));
    return j;
}

bool from_json(const cJSON* j, MintResponse& out) {
    const cJSON* sigs = cJSON_GetObjectItemCaseSensitive(j, "signatures");
    if (!sigs) return false;
    return from_json_array(sigs, out.signatures);
}

// ---------------------------------------------------------------------------
// MeltQuote
// ---------------------------------------------------------------------------

cJSON* to_json(const MeltQuote& v) {
    cJSON* j = cJSON_CreateObject();
    cJSON_AddStringToObject(j, "quote", v.quote.c_str());
    cJSON_AddNumberToObject(j, "amount", v.amount);
    cJSON_AddNumberToObject(j, "fee_reserve", v.fee_reserve);
    cJSON_AddStringToObject(j, "state", v.state.c_str());
    cJSON_AddNumberToObject(j, "expiry", (double)v.expiry);
    if (v.payment_preimage)
        cJSON_AddStringToObject(j, "payment_preimage",
                                v.payment_preimage->c_str());
    if (v.change)
        cJSON_AddItemToObject(j, "change", to_json_array(*v.change));
    return j;
}

bool from_json(const cJSON* j, MeltQuote& out) {
    const char* quote = get_string(j, "quote");
    const char* state = get_string(j, "state");
    if (!quote || !state) return false;
    out.quote = quote;
    out.state = state;
    if (!get_int(j, "amount", out.amount)) return false;
    if (!get_int(j, "fee_reserve", out.fee_reserve)) return false;
    if (!get_int64(j, "expiry", out.expiry))
        out.expiry = 0;
    const char* preimage = get_string(j, "payment_preimage");
    out.payment_preimage = preimage
        ? std::optional<std::string>(preimage)
        : std::nullopt;
    const cJSON* change = cJSON_GetObjectItemCaseSensitive(j, "change");
    if (change && cJSON_IsArray(change)) {
        std::vector<BlindSignature> sigs;
        if (from_json_array(change, sigs))
            out.change = std::move(sigs);
    } else {
        out.change = std::nullopt;
    }
    return true;
}

// ---------------------------------------------------------------------------
// MeltRequest
// ---------------------------------------------------------------------------

cJSON* to_json(const MeltRequest& v) {
    cJSON* j = cJSON_CreateObject();
    cJSON_AddStringToObject(j, "quote", v.quote.c_str());
    cJSON_AddItemToObject(j, "inputs", to_json_array(v.inputs));
    if (v.outputs)
        cJSON_AddItemToObject(j, "outputs", to_json_array(*v.outputs));
    return j;
}

// ---------------------------------------------------------------------------
// Token (V3 JSON format)
// ---------------------------------------------------------------------------

cJSON* to_json(const Token& v) {
    cJSON* j = cJSON_CreateObject();

    cJSON* token_arr = cJSON_CreateArray();
    cJSON* entry = cJSON_CreateObject();
    cJSON_AddStringToObject(entry, "mint", v.mint.c_str());
    cJSON_AddItemToObject(entry, "proofs", to_json_array(v.proofs));
    cJSON_AddItemToArray(token_arr, entry);
    cJSON_AddItemToObject(j, "token", token_arr);

    if (v.memo)
        cJSON_AddStringToObject(j, "memo", v.memo->c_str());
    cJSON_AddStringToObject(j, "unit", v.unit.c_str());
    return j;
}

bool from_json(const cJSON* j, Token& out) {
    const cJSON* token_arr = cJSON_GetObjectItemCaseSensitive(j, "token");
    if (!token_arr || !cJSON_IsArray(token_arr)) return false;

    const cJSON* first = cJSON_GetArrayItem(token_arr, 0);
    if (!first) return false;

    const char* mint = get_string(first, "mint");
    if (!mint) return false;
    out.mint = mint;

    const cJSON* proofs = cJSON_GetObjectItemCaseSensitive(first, "proofs");
    if (!proofs) return false;
    if (!from_json_array(proofs, out.proofs)) return false;

    const char* memo = get_string(j, "memo");
    out.memo = memo ? std::optional<std::string>(memo) : std::nullopt;

    const char* unit = get_string(j, "unit");
    out.unit = unit ? unit : "sat";
    return true;
}

// ---------------------------------------------------------------------------
// Keyset list response (GET /v1/keys, GET /v1/keys/{id})
// ---------------------------------------------------------------------------

bool from_json_keyset_response(const cJSON *j, std::vector<Keyset> &out) {
    const cJSON *keysets = cJSON_GetObjectItemCaseSensitive(j, "keysets");
    if (!keysets) return false;
    return from_json_array(keysets, out);
}

bool from_json_keyset_info_response(const cJSON *j, std::vector<KeysetInfo> &out) {
    const cJSON *keysets = cJSON_GetObjectItemCaseSensitive(j, "keysets");
    if (!keysets) return false;
    return from_json_array(keysets, out);
}

// ---------------------------------------------------------------------------
// V3 token serialization
// ---------------------------------------------------------------------------

static const char V3_PREFIX[] = "cashuA";
static const size_t V3_PREFIX_LEN = 6;

static std::string base64url_encode(const unsigned char *data, size_t len) {
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

static bool base64url_decode(const char *input, size_t input_len,
                             std::string &out) {
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

std::string serialize_token_v3(const Token &token) {
    cJSON *j = to_json(token);
    char *json_str = cJSON_PrintUnformatted(j);
    std::string encoded = base64url_encode(
        (const unsigned char *)json_str, strlen(json_str));
    cJSON_free(json_str);
    cJSON_Delete(j);
    return std::string(V3_PREFIX) + encoded;
}

bool deserialize_token_v3(const char *token_str, Token &out) {
    size_t len = strlen(token_str);
    if (len <= V3_PREFIX_LEN) return false;
    if (strncmp(token_str, V3_PREFIX, V3_PREFIX_LEN) != 0) return false;

    std::string json_str;
    if (!base64url_decode(token_str + V3_PREFIX_LEN,
                          len - V3_PREFIX_LEN, json_str))
        return false;

    return deserialize(json_str.c_str(), out);
}

} // namespace cashu
