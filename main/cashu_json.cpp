#include "cashu_json.hpp"
#include "cashu_cbor.hpp"
#include "base64url.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <esp_log.h>

#define TAG "cashu_json"

namespace cashu {

// ---------------------------------------------------------------------------
// Direct JSON writer helpers (zero cJSON DOM allocations)
// ---------------------------------------------------------------------------

void json_append_string(std::string& out, const char* s, size_t len) {
    out.push_back('"');
    size_t run_start = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c >= 0x20 && c != '"' && c != '\\')
            continue;
        if (i > run_start)
            out.append(s + run_start, i - run_start);
        switch (c) {
        case '"':  out.append("\\\"", 2); break;
        case '\\': out.append("\\\\", 2); break;
        case '\b': out.append("\\b", 2);  break;
        case '\f': out.append("\\f", 2);  break;
        case '\n': out.append("\\n", 2);  break;
        case '\r': out.append("\\r", 2);  break;
        case '\t': out.append("\\t", 2);  break;
        default: {
            static const char hex[] = "0123456789abcdef";
            char esc[6] = {'\\', 'u', '0', '0', hex[c >> 4], hex[c & 0x0F]};
            out.append(esc, 6);
            break;
        }
        }
        run_start = i + 1;
    }
    if (len > run_start)
        out.append(s + run_start, len - run_start);
    out.push_back('"');
}

static void append_u64(std::string& out, uint64_t v) {
    char buf[24];
    char* p = buf + sizeof(buf);
    do {
        *--p = (char)('0' + (v % 10));
        v /= 10;
    } while (v != 0);
    out.append(p, (size_t)((buf + sizeof(buf)) - p));
}

static void append_i64(std::string& out, int64_t v) {
    if (v < 0) {
        out.push_back('-');
        append_u64(out, 0ULL - (uint64_t)v);
    } else {
        append_u64(out, (uint64_t)v);
    }
}

static void append_dleq(std::string& out, const DLEQ& v) {
    out.append("{\"e\":", 5);
    json_append_string(out, v.e);
    out.append(",\"s\":", 5);
    json_append_string(out, v.s);
    if (v.r) {
        out.append(",\"r\":", 5);
        json_append_string(out, *v.r);
    }
    out.push_back('}');
}

static void append_blinded_message(std::string& out, const BlindedMessage& v) {
    out.append("{\"amount\":", 10);
    append_i64(out, v.amount);
    out.append(",\"B_\":", 6);
    json_append_string(out, v.B_);
    out.append(",\"id\":", 6);
    json_append_string(out, v.id);
    out.push_back('}');
}

static void append_proof(std::string& out, const Proof& v) {
    out.append("{\"id\":", 6);
    json_append_string(out, v.id);
    out.append(",\"amount\":", 10);
    append_i64(out, v.amount);
    out.append(",\"secret\":", 10);
    json_append_string(out, v.secret);
    out.append(",\"C\":", 5);
    json_append_string(out, v.C);
    if (v.dleq) {
        out.append(",\"dleq\":", 8);
        append_dleq(out, *v.dleq);
    }
    if (v.witness) {
        out.append(",\"witness\":", 11);
        json_append_string(out, *v.witness);
    }
    out.push_back('}');
}

static size_t estimate_proofs_json(const std::vector<Proof>& proofs) {
    size_t est = 2;
    for (const auto& p : proofs) {
        est += 64 + p.id.size() + p.secret.size() + p.C.size();
        if (p.dleq) est += 24 + p.dleq->e.size() + p.dleq->s.size() + (p.dleq->r ? p.dleq->r->size() + 8 : 0);
        if (p.witness) est += 16 + p.witness->size();
    }
    return est;
}

static size_t estimate_outputs_json(const std::vector<BlindedMessage>& outputs) {
    size_t est = 2;
    for (const auto& o : outputs)
        est += 36 + o.B_.size() + o.id.size();
    return est;
}

static void append_proofs_array(std::string& out, const std::vector<Proof>& proofs) {
    out.push_back('[');
    for (size_t i = 0; i < proofs.size(); i++) {
        if (i > 0) out.push_back(',');
        append_proof(out, proofs[i]);
    }
    out.push_back(']');
}

static void append_outputs_array(std::string& out, const std::vector<BlindedMessage>& outputs) {
    out.push_back('[');
    for (size_t i = 0; i < outputs.size(); i++) {
        if (i > 0) out.push_back(',');
        append_blinded_message(out, outputs[i]);
    }
    out.push_back(']');
}

std::string serialize(const Keyset& v) {
    std::string out;
    out.reserve(128 + v.id.size() + v.unit.size() + v.keys.size() * 82);
    out.append("{\"id\":", 6);
    json_append_string(out, v.id);
    out.append(",\"unit\":", 8);
    json_append_string(out, v.unit);
    out.append(",\"active\":", 10);
    out.append(v.active ? "true" : "false");
    out.append(",\"input_fee_ppk\":", 17);
    append_i64(out, v.input_fee_ppk);
    if (v.final_expiry) {
        out.append(",\"final_expiry\":", 16);
        append_i64(out, *v.final_expiry);
    }
    out.append(",\"keys\":{", 9);
    bool first = true;
    for (const auto& [amount, pubkey] : v.keys) {
        if (!first) out.push_back(',');
        first = false;
        out.push_back('"');
        append_u64(out, amount);
        out.append("\":", 2);
        json_append_string(out, pubkey);
    }
    out.append("}}", 2);
    return out;
}

std::string serialize_swap_request(const std::vector<Proof>& inputs,
                                   const std::vector<BlindedMessage>& outputs) {
    std::string out;
    out.reserve(32 + estimate_proofs_json(inputs) + estimate_outputs_json(outputs));
    out.append("{\"inputs\":", 10);
    append_proofs_array(out, inputs);
    out.append(",\"outputs\":", 11);
    append_outputs_array(out, outputs);
    out.push_back('}');
    return out;
}

std::string serialize(const SwapRequest& v) {
    return serialize_swap_request(v.inputs, v.outputs);
}

std::string serialize_mint_request(const std::string& quote,
                                   const std::vector<BlindedMessage>& outputs) {
    std::string out;
    out.reserve(32 + quote.size() + estimate_outputs_json(outputs));
    out.append("{\"quote\":", 9);
    json_append_string(out, quote);
    out.append(",\"outputs\":", 11);
    append_outputs_array(out, outputs);
    out.push_back('}');
    return out;
}

std::string serialize(const MintRequest& v) {
    return serialize_mint_request(v.quote, v.outputs);
}

std::string serialize_melt_request(const std::string& quote,
                                   const std::vector<Proof>& inputs,
                                   const std::vector<BlindedMessage>* outputs) {
    std::string out;
    out.reserve(48 + quote.size() + estimate_proofs_json(inputs)
                + (outputs ? estimate_outputs_json(*outputs) : 0));
    out.append("{\"quote\":", 9);
    json_append_string(out, quote);
    out.append(",\"inputs\":", 10);
    append_proofs_array(out, inputs);
    if (outputs) {
        out.append(",\"outputs\":", 11);
        append_outputs_array(out, *outputs);
    }
    out.push_back('}');
    return out;
}

std::string serialize(const MeltRequest& v) {
    return serialize_melt_request(v.quote, v.inputs, v.outputs ? &*v.outputs : nullptr);
}

// ---------------------------------------------------------------------------
// cJSON single-pass deserialization helpers
// ---------------------------------------------------------------------------

static bool item_to_int(const cJSON* item, int& out) {
    if (!cJSON_IsNumber(item)) return false;
    // All protocol ints (amounts, fees) are non-negative and must fit in
    // int32 — valueint saturates silently, so bound via the double value.
    if (item->valuedouble < 0 || item->valuedouble > 2147483647.0)
        return false;
    out = item->valueint;
    return true;
}

static bool item_to_int64(const cJSON* item, int64_t& out) {
    if (!cJSON_IsNumber(item)) return false;
    out = (int64_t)item->valuedouble;
    return true;
}

static bool item_to_bool(const cJSON* item, bool& out) {
    if (cJSON_IsTrue(item)) { out = true; return true; }
    if (cJSON_IsFalse(item)) { out = false; return true; }
    if (cJSON_IsNumber(item)) { out = item->valueint != 0; return true; }
    return false;
}

static const char* get_string(const cJSON* obj, const char* key) {
    const cJSON* item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!item || !cJSON_IsString(item)) return nullptr;
    return item->valuestring;
}

// ---------------------------------------------------------------------------
// DLEQ
// ---------------------------------------------------------------------------

bool from_json(const cJSON* j, DLEQ& out) {
    if (!cJSON_IsObject(j)) return false;
    const char* e = nullptr;
    const char* s = nullptr;
    const char* r = nullptr;
    for (const cJSON* f = j->child; f; f = f->next) {
        if (!f->string || !cJSON_IsString(f)) continue;
        if (f->string[1] != '\0') continue;
        if (f->string[0] == 'e') e = f->valuestring;
        else if (f->string[0] == 's') s = f->valuestring;
        else if (f->string[0] == 'r') r = f->valuestring;
    }
    if (!e || !s) return false;
    out.e = e;
    out.s = s;
    out.r = r ? std::optional<std::string>(r) : std::nullopt;
    return true;
}

// ---------------------------------------------------------------------------
// BlindedMessage
// ---------------------------------------------------------------------------

bool from_json(const cJSON* j, BlindedMessage& out) {
    if (!cJSON_IsObject(j)) return false;
    const char* B_ = nullptr;
    const char* id = nullptr;
    bool has_amt = false;
    for (const cJSON* f = j->child; f; f = f->next) {
        if (!f->string) continue;
        if (strcmp(f->string, "B_") == 0 && cJSON_IsString(f))
            B_ = f->valuestring;
        else if (strcmp(f->string, "id") == 0 && cJSON_IsString(f))
            id = f->valuestring;
        else if (strcmp(f->string, "amount") == 0)
            has_amt = item_to_int(f, out.amount);
    }
    if (!B_ || !id || !has_amt) return false;
    out.B_ = B_;
    out.id = id;
    return true;
}

// ---------------------------------------------------------------------------
// BlindSignature
// ---------------------------------------------------------------------------

bool from_json(const cJSON* j, BlindSignature& out) {
    if (!cJSON_IsObject(j)) return false;
    const char* id = nullptr;
    const char* C_ = nullptr;
    const cJSON* dleq = nullptr;
    bool has_amt = false;
    for (const cJSON* f = j->child; f; f = f->next) {
        if (!f->string) continue;
        if (strcmp(f->string, "id") == 0 && cJSON_IsString(f))
            id = f->valuestring;
        else if (strcmp(f->string, "C_") == 0 && cJSON_IsString(f))
            C_ = f->valuestring;
        else if (strcmp(f->string, "amount") == 0)
            has_amt = item_to_int(f, out.amount);
        else if (strcmp(f->string, "dleq") == 0 && cJSON_IsObject(f))
            dleq = f;
    }
    if (!id || !C_ || !has_amt) return false;
    out.id = id;
    out.C_ = C_;
    if (dleq) {
        DLEQ d{};
        if (from_json(dleq, d))
            out.dleq = std::move(d);
        else
            out.dleq = std::nullopt;
    } else {
        out.dleq = std::nullopt;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Proof
// ---------------------------------------------------------------------------

bool from_json(const cJSON* j, Proof& out) {
    if (!cJSON_IsObject(j)) return false;
    const char* id = nullptr;
    const char* secret = nullptr;
    const char* C = nullptr;
    const char* witness = nullptr;
    const cJSON* dleq = nullptr;
    bool has_amt = false;
    for (const cJSON* f = j->child; f; f = f->next) {
        if (!f->string) continue;
        if (strcmp(f->string, "id") == 0 && cJSON_IsString(f))
            id = f->valuestring;
        else if (strcmp(f->string, "secret") == 0 && cJSON_IsString(f))
            secret = f->valuestring;
        else if (strcmp(f->string, "C") == 0 && cJSON_IsString(f))
            C = f->valuestring;
        else if (strcmp(f->string, "amount") == 0)
            has_amt = item_to_int(f, out.amount);
        else if (strcmp(f->string, "dleq") == 0 && cJSON_IsObject(f))
            dleq = f;
        else if (strcmp(f->string, "witness") == 0 && cJSON_IsString(f))
            witness = f->valuestring;
    }
    if (!id || !secret || !C || !has_amt) return false;
    out.id = id;
    out.secret = secret;
    out.C = C;
    if (dleq) {
        DLEQ d{};
        if (from_json(dleq, d))
            out.dleq = std::move(d);
        else
            out.dleq = std::nullopt;
    } else {
        out.dleq = std::nullopt;
    }
    out.witness = witness ? std::optional<std::string>(witness) : std::nullopt;
    return true;
}

// ---------------------------------------------------------------------------
// Keyset
// ---------------------------------------------------------------------------

bool from_json(const cJSON* j, Keyset& out) {
    if (!cJSON_IsObject(j)) return false;
    const char* id = nullptr;
    const char* unit = nullptr;
    const cJSON* keys = nullptr;
    out.active = true;
    out.input_fee_ppk = 0;
    out.final_expiry = std::nullopt;

    for (const cJSON* f = j->child; f; f = f->next) {
        if (!f->string) continue;
        if (strcmp(f->string, "id") == 0 && cJSON_IsString(f))
            id = f->valuestring;
        else if (strcmp(f->string, "unit") == 0 && cJSON_IsString(f))
            unit = f->valuestring;
        else if (strcmp(f->string, "active") == 0)
            item_to_bool(f, out.active);
        else if (strcmp(f->string, "input_fee_ppk") == 0)
            item_to_int(f, out.input_fee_ppk);
        else if (strcmp(f->string, "final_expiry") == 0) {
            int64_t fe;
            if (item_to_int64(f, fe))
                out.final_expiry = fe;
        } else if (strcmp(f->string, "keys") == 0 && cJSON_IsObject(f))
            keys = f;
    }
    if (!id || !unit) return false;
    out.id = id;
    out.unit = unit;
    out.keys.clear();
    if (keys) {
        for (const cJSON* entry = keys->child; entry; entry = entry->next) {
            if (!entry->string || !cJSON_IsString(entry)) continue;
            uint64_t amount = strtoull(entry->string, nullptr, 10);
            out.keys.emplace(amount, entry->valuestring);
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// KeysetInfo
// ---------------------------------------------------------------------------

bool from_json(const cJSON* j, KeysetInfo& out) {
    if (!cJSON_IsObject(j)) return false;
    const char* id = nullptr;
    const char* unit = nullptr;
    out.active = true;
    out.input_fee_ppk = 0;
    out.final_expiry = std::nullopt;

    for (const cJSON* f = j->child; f; f = f->next) {
        if (!f->string) continue;
        if (strcmp(f->string, "id") == 0 && cJSON_IsString(f))
            id = f->valuestring;
        else if (strcmp(f->string, "unit") == 0 && cJSON_IsString(f))
            unit = f->valuestring;
        else if (strcmp(f->string, "active") == 0)
            item_to_bool(f, out.active);
        else if (strcmp(f->string, "input_fee_ppk") == 0)
            item_to_int(f, out.input_fee_ppk);
        else if (strcmp(f->string, "final_expiry") == 0) {
            int64_t fe;
            if (item_to_int64(f, fe))
                out.final_expiry = fe;
        }
    }
    if (!id || !unit) return false;
    out.id = id;
    out.unit = unit;
    return true;
}

// ---------------------------------------------------------------------------
// SwapResponse / MintResponse
// ---------------------------------------------------------------------------

bool from_json(const cJSON* j, SwapResponse& out) {
    const cJSON* sigs = cJSON_GetObjectItemCaseSensitive(j, "signatures");
    if (!sigs) return false;
    return from_json_array(sigs, out.signatures);
}

bool from_json(const cJSON* j, MintResponse& out) {
    const cJSON* sigs = cJSON_GetObjectItemCaseSensitive(j, "signatures");
    if (!sigs) return false;
    return from_json_array(sigs, out.signatures);
}

// ---------------------------------------------------------------------------
// MintQuote
// ---------------------------------------------------------------------------

bool from_json(const cJSON* j, MintQuote& out) {
    if (!cJSON_IsObject(j)) return false;
    const char* quote = nullptr;
    const char* request = nullptr;
    out.state.clear();
    out.unit.clear();
    out.method.clear();
    out.amount = 0;
    out.expiry = 0;
    out.amount_paid = std::nullopt;
    out.amount_issued = std::nullopt;

    for (const cJSON* f = j->child; f; f = f->next) {
        if (!f->string) continue;
        if (strcmp(f->string, "quote") == 0 && cJSON_IsString(f))
            quote = f->valuestring;
        else if (strcmp(f->string, "request") == 0 && cJSON_IsString(f))
            request = f->valuestring;
        else if (strcmp(f->string, "state") == 0 && cJSON_IsString(f))
            out.state = f->valuestring;
        else if (strcmp(f->string, "unit") == 0 && cJSON_IsString(f))
            out.unit = f->valuestring;
        else if (strcmp(f->string, "method") == 0 && cJSON_IsString(f))
            out.method = f->valuestring;
        else if (strcmp(f->string, "amount") == 0)
            item_to_int(f, out.amount);
        else if (strcmp(f->string, "expiry") == 0)
            item_to_int64(f, out.expiry);
        else if (strcmp(f->string, "amount_paid") == 0) {
            int paid;
            if (item_to_int(f, paid)) out.amount_paid = paid;
        } else if (strcmp(f->string, "amount_issued") == 0) {
            int issued;
            if (item_to_int(f, issued)) out.amount_issued = issued;
        }
    }
    if (!quote || !request) return false;
    out.quote = quote;
    out.request = request;
    return true;
}

// ---------------------------------------------------------------------------
// MeltQuote
// ---------------------------------------------------------------------------

bool from_json(const cJSON* j, MeltQuote& out) {
    if (!cJSON_IsObject(j)) return false;
    const char* quote = nullptr;
    const char* state = nullptr;
    const cJSON* change = nullptr;
    bool has_amt = false;
    out.fee_reserve = 0;
    out.unit.clear();
    out.method.clear();
    out.expiry = 0;
    out.request = std::nullopt;
    out.payment_preimage = std::nullopt;
    out.change = std::nullopt;

    for (const cJSON* f = j->child; f; f = f->next) {
        if (!f->string) continue;
        if (strcmp(f->string, "quote") == 0 && cJSON_IsString(f))
            quote = f->valuestring;
        else if (strcmp(f->string, "state") == 0 && cJSON_IsString(f))
            state = f->valuestring;
        else if (strcmp(f->string, "amount") == 0)
            has_amt = item_to_int(f, out.amount);
        else if (strcmp(f->string, "fee_reserve") == 0)
            item_to_int(f, out.fee_reserve);
        else if (strcmp(f->string, "unit") == 0 && cJSON_IsString(f))
            out.unit = f->valuestring;
        else if (strcmp(f->string, "method") == 0 && cJSON_IsString(f))
            out.method = f->valuestring;
        else if (strcmp(f->string, "expiry") == 0)
            item_to_int64(f, out.expiry);
        else if (strcmp(f->string, "request") == 0 && cJSON_IsString(f))
            out.request = f->valuestring;
        else if (strcmp(f->string, "payment_preimage") == 0 && cJSON_IsString(f))
            out.payment_preimage = f->valuestring;
        else if (strcmp(f->string, "change") == 0 && cJSON_IsArray(f))
            change = f;
    }
    if (!quote || !state || !has_amt) return false;
    out.quote = quote;
    out.state = state;
    if (change) {
        std::vector<BlindSignature> sigs;
        if (from_json_array(change, sigs))
            out.change = std::move(sigs);
    }
    return true;
}

// ---------------------------------------------------------------------------
// Token (V3 JSON format)
// ---------------------------------------------------------------------------

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
// Keyset list response (GET /v1/keys, GET /v1/keysets)
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
// NUT-06 mint info (subset: name + nuts."4"/"5" method-unit matrices)
// ---------------------------------------------------------------------------

static void parse_method_settings(const cJSON* nut_obj,
                                  std::vector<MintMethodSetting>& out) {
    out.clear();
    if (!nut_obj) return;   // NUT not advertised
    const cJSON* methods = cJSON_GetObjectItemCaseSensitive(nut_obj, "methods");
    if (!cJSON_IsArray(methods)) return;
    int n = cJSON_GetArraySize(methods);
    if (n > 0) out.reserve((size_t)n);
    const cJSON* row = nullptr;
    cJSON_ArrayForEach(row, methods) {
        if (!cJSON_IsObject(row)) continue;
        MintMethodSetting s;
        const char* method = nullptr;
        const char* unit = nullptr;
        for (const cJSON* f = row->child; f; f = f->next) {
            if (!f->string) continue;
            if (strcmp(f->string, "method") == 0 && cJSON_IsString(f))
                method = f->valuestring;
            else if (strcmp(f->string, "unit") == 0 && cJSON_IsString(f))
                unit = f->valuestring;
            else if (strcmp(f->string, "method_name") == 0 && cJSON_IsString(f))
                s.method_name = f->valuestring;
            else if (strcmp(f->string, "min_amount") == 0) {
                int64_t v;
                if (item_to_int64(f, v)) s.min_amount = v;
            } else if (strcmp(f->string, "max_amount") == 0) {
                int64_t v;
                if (item_to_int64(f, v)) s.max_amount = v;
            }
        }
        if (!method || !unit) continue;   // skip malformed rows
        s.method = method;
        s.unit = unit;
        out.push_back(std::move(s));
    }
}

bool from_json_mint_info(const cJSON* j, MintInfo& out) {
    if (!cJSON_IsObject(j)) return false;
    const char* name = get_string(j, "name");
    out.name = name ? name : "";
    out.mint_methods.clear();
    out.melt_methods.clear();
    const cJSON* nuts = cJSON_GetObjectItemCaseSensitive(j, "nuts");
    if (!cJSON_IsObject(nuts)) return true;   // nuts map is optional
    parse_method_settings(cJSON_GetObjectItemCaseSensitive(nuts, "4"),
                          out.mint_methods);
    parse_method_settings(cJSON_GetObjectItemCaseSensitive(nuts, "5"),
                          out.melt_methods);
    return true;
}

// ---------------------------------------------------------------------------
// Blob serialization for NVS persistence
// ---------------------------------------------------------------------------

std::string proofs_to_json(const std::vector<Proof>& proofs) {
    std::string out;
    out.reserve(estimate_proofs_json(proofs));
    append_proofs_array(out, proofs);
    return out;
}

bool proofs_from_json(const char* json_str, std::vector<Proof>& out) {
    cJSON* arr = cJSON_Parse(json_str);
    if (!arr) return false;
    bool ok = from_json_array(arr, out);
    cJSON_Delete(arr);
    return ok;
}

bool keysets_from_json(const char* json_str, std::vector<Keyset>& out) {
    cJSON* arr = cJSON_Parse(json_str);
    if (!arr) return false;
    bool ok = from_json_array(arr, out);
    cJSON_Delete(arr);
    return ok;
}

// ---------------------------------------------------------------------------
// V3 token serialization
// ---------------------------------------------------------------------------

static const char V3_PREFIX[] = "cashuA";
static const size_t V3_PREFIX_LEN = 6;

bool deserialize_token_v3(const char *token_str, Token &out) {
    size_t len = strlen(token_str);
    if (len <= V3_PREFIX_LEN) return false;
    if (strncmp(token_str, V3_PREFIX, V3_PREFIX_LEN) != 0) return false;

    std::string json_str;
    if (!base64url_decode(token_str + V3_PREFIX_LEN,
                          len - V3_PREFIX_LEN, json_str))
        return false;

    return deserialize(json_str.data(), json_str.size(), out);
}

bool deserialize_token(const char *token_str, Token &out) {
    if (!token_str) return false;
    if (strncmp(token_str, "cashuB", 6) == 0)
        return deserialize_token_v4(token_str, out);
    if (strncmp(token_str, "cashuA", 6) == 0)
        return deserialize_token_v3(token_str, out);
    return false;
}

// ---------------------------------------------------------------------------
// Self-test: quote/mint-info parse contract + direct JSON writer round-trips
// ---------------------------------------------------------------------------

bool cashu_json_run_tests()
{
    bool ok = true;
    auto expect = [&](const char* name, bool cond) {
        if (!cond) {
            ESP_LOGE(TAG, "%s FAIL", name);
            ok = false;
        } else {
            ESP_LOGI(TAG, "%s ok", name);
        }
    };

    { // Legacy NUT-23 bolt11 mint quote: state-driven, no accounting pair
        MintQuote q;
        expect("mint quote legacy",
               deserialize(R"({"quote":"q1","request":"lnbc10n1...","amount":100,)"
                           R"("state":"PAID","expiry":1753000000})", q)
               && q.mintable() == 100 && q.unit.empty());
    }
    { // PR#382 custom-method quote: accounting pair, no state at all
        MintQuote q;
        expect("mint quote pr382",
               deserialize(R"({"quote":"q2","request":"https://pay.example/abc",)"
                           R"("unit":"usd","method":"paypal","amount_paid":500,)"
                           R"("amount_issued":200,"updated_at":1753000000})", q)
               && q.mintable() == 300 && q.unit == "usd"
               && q.method == "paypal" && q.state.empty());
    }
    { // Accounting pair takes precedence over a stale legacy state
        MintQuote q;
        expect("mint quote paid-out",
               deserialize(R"({"quote":"q3","request":"r","state":"PAID",)"
                           R"("amount":100,"amount_paid":100,"amount_issued":100})", q)
               && q.mintable() == 0);
    }
    { // Melt quote without fee_reserve (custom methods may omit it)
        MeltQuote m;
        expect("melt quote no fee_reserve",
               deserialize(R"({"quote":"m1","amount":250,"unit":"usd",)"
                           R"("state":"UNPAID","expiry":1753000000})", m)
               && m.fee_reserve == 0 && m.unit == "usd");
    }
    { // NUT-06 method-unit matrix
        MintInfo info;
        cJSON* j = cJSON_Parse(
            R"({"name":"Test Mint","nuts":{)"
            R"("4":{"methods":[)"
            R"({"method":"bolt11","unit":"sat","min_amount":1,"max_amount":10000},)"
            R"({"method":"paypal","unit":"usd","method_name":"PayPal"},)"
            R"({"unit":"bad-row-no-method"}],"disabled":false},)"
            R"("5":{"methods":[{"method":"bolt11","unit":"sat"}]}}})");
        bool parsed = j && from_json_mint_info(j, info);
        if (j) cJSON_Delete(j);
        expect("mint info matrix",
               parsed && info.name == "Test Mint"
               && info.mint_methods.size() == 2
               && info.mint_methods[1].method_name
               && *info.mint_methods[1].method_name == "PayPal"
               && info.mint_methods[0].min_amount
               && *info.mint_methods[0].min_amount == 1
               && info.melt_methods.size() == 1);
    }
    { // Direct JSON writer round-trip with escaped NUT-10 secret, DLEQ, witness, and Keyset
        Proof p;
        p.id = "01aabb";
        p.amount = 8;
        p.secret = R"(["P2PK",{"nonce":"n1","data":"02aa\n"}])";
        p.C = "02cc";
        p.dleq = DLEQ{"11", "22", std::string("33")};
        p.witness = R"({"signatures":["deadbeef"]})";
        std::string js = proofs_to_json({p});
        std::vector<Proof> back;
        expect("proofs direct json",
               proofs_from_json(js.c_str(), back) && back.size() == 1 &&
               back[0].secret == p.secret && back[0].witness == p.witness &&
               back[0].dleq && back[0].dleq->r && *back[0].dleq->r == "33");

        Keyset ks;
        ks.id = "01aabb";
        ks.unit = "sat";
        ks.active = true;
        ks.input_fee_ppk = 100;
        ks.final_expiry = 1893456000;
        ks.keys = {{1, "02aa"}, {2, "03bb"}};
        std::string kjs = serialize(ks);
        Keyset kback;
        expect("keyset direct json",
               deserialize(kjs.data(), kjs.size(), kback) &&
               kback.id == ks.id && kback.input_fee_ppk == 100 &&
               kback.final_expiry == ks.final_expiry && kback.keys == ks.keys);
    }
    return ok;
}

} // namespace cashu
