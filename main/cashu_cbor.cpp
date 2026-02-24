#include "cashu_cbor.hpp"
#include "hex.h"

#include <cstring>
#include <esp_log.h>
#include <mbedtls/base64.h>
#include <cbor.h>

#define TAG "cashu_cbor"

namespace cashu {

// -------------------------------------------------------------------------
// Base64url helpers (same as in cashu_json.cpp, kept local)
// -------------------------------------------------------------------------

static std::string base64url_encode(const unsigned char *data, size_t len)
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

static bool base64url_decode(const char *input, size_t input_len,
                             std::string &out)
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

// -------------------------------------------------------------------------
// CBOR decoder helpers
// -------------------------------------------------------------------------

static bool cbor_find_in_map(CborValue *map, const char *key, CborValue *out)
{
    if (!cbor_value_is_map(map)) return false;
    return cbor_value_map_find_value(map, key, out) == CborNoError
           && out->type != CborInvalidType;
}

static bool cbor_get_string(CborValue *val, std::string &out)
{
    if (!cbor_value_is_text_string(val)) return false;
    size_t len = 0;
    if (cbor_value_get_string_length(val, &len) != CborNoError) return false;
    out.resize(len);
    if (cbor_value_copy_text_string(val, out.data(), &len, nullptr) != CborNoError)
        return false;
    out.resize(len);
    return true;
}

static bool cbor_get_bytes_as_hex(CborValue *val, std::string &out)
{
    if (!cbor_value_is_byte_string(val)) return false;
    size_t len = 0;
    if (cbor_value_get_string_length(val, &len) != CborNoError) return false;
    std::vector<uint8_t> buf(len);
    if (cbor_value_copy_byte_string(val, buf.data(), &len, nullptr) != CborNoError)
        return false;
    char *hex = new char[len * 2 + 1];
    bytes_to_hex(buf.data(), len, hex);
    out = std::string(hex);
    delete[] hex;
    return true;
}

static bool cbor_get_uint(CborValue *val, uint64_t &out)
{
    if (!cbor_value_is_unsigned_integer(val)) return false;
    return cbor_value_get_uint64(val, &out) == CborNoError;
}

static bool cbor_get_int(CborValue *val, int &out)
{
    uint64_t u;
    if (cbor_get_uint(val, u)) {
        out = (int)u;
        return true;
    }
    if (cbor_value_is_integer(val)) {
        int64_t i;
        if (cbor_value_get_int64(val, &i) == CborNoError) {
            out = (int)i;
            return true;
        }
    }
    return false;
}

static bool cbor_get_bool(CborValue *val, bool &out)
{
    if (!cbor_value_is_boolean(val)) return false;
    return cbor_value_get_boolean(val, &out) == CborNoError;
}

// -------------------------------------------------------------------------
// Token V4 Decode
// -------------------------------------------------------------------------

static bool decode_v4_dleq(CborValue *map, DLEQ &dleq)
{
    CborValue val;
    if (!cbor_find_in_map(map, "e", &val) || !cbor_get_bytes_as_hex(&val, dleq.e))
        return false;
    if (!cbor_find_in_map(map, "s", &val) || !cbor_get_bytes_as_hex(&val, dleq.s))
        return false;
    CborValue rval;
    if (cbor_find_in_map(map, "r", &rval) && cbor_value_is_byte_string(&rval)) {
        std::string r_hex;
        if (cbor_get_bytes_as_hex(&rval, r_hex))
            dleq.r = r_hex;
    }
    return true;
}

static bool decode_v4_proof(CborValue *it, Proof &proof, const std::string &keyset_id)
{
    if (!cbor_value_is_map(it)) return false;

    CborValue val;
    int amount;
    if (!cbor_find_in_map(it, "a", &val) || !cbor_get_int(&val, amount))
        return false;
    proof.amount = amount;
    proof.id = keyset_id;

    if (!cbor_find_in_map(it, "s", &val) || !cbor_get_string(&val, proof.secret))
        return false;

    if (!cbor_find_in_map(it, "c", &val) || !cbor_get_bytes_as_hex(&val, proof.C))
        return false;

    CborValue dval;
    if (cbor_find_in_map(it, "d", &dval) && cbor_value_is_map(&dval)) {
        DLEQ dleq;
        if (decode_v4_dleq(&dval, dleq))
            proof.dleq = dleq;
    }

    CborValue wval;
    if (cbor_find_in_map(it, "w", &wval) && cbor_value_is_text_string(&wval)) {
        std::string w;
        if (cbor_get_string(&wval, w))
            proof.witness = w;
    }

    return true;
}

bool deserialize_token_v4(const char *token_str, Token &out)
{
    size_t len = strlen(token_str);
    static const char PREFIX[] = "cashuB";
    static const size_t PREFIX_LEN = 6;

    if (len <= PREFIX_LEN || strncmp(token_str, PREFIX, PREFIX_LEN) != 0) {
        ESP_LOGE(TAG, "not a V4 token (wrong prefix)");
        return false;
    }

    std::string cbor_data;
    if (!base64url_decode(token_str + PREFIX_LEN, len - PREFIX_LEN, cbor_data)) {
        ESP_LOGE(TAG, "base64url decode failed");
        return false;
    }

    CborParser parser;
    CborValue root;
    if (cbor_parser_init((const uint8_t *)cbor_data.data(), cbor_data.size(),
                         0, &parser, &root) != CborNoError) {
        ESP_LOGE(TAG, "CBOR parse init failed");
        return false;
    }

    if (!cbor_value_is_map(&root)) {
        ESP_LOGE(TAG, "expected CBOR map at root");
        return false;
    }

    CborValue val;
    if (!cbor_find_in_map(&root, "m", &val) || !cbor_get_string(&val, out.mint))
        return false;
    if (!cbor_find_in_map(&root, "u", &val) || !cbor_get_string(&val, out.unit))
        return false;

    CborValue dval;
    if (cbor_find_in_map(&root, "d", &dval) && cbor_value_is_text_string(&dval)) {
        std::string memo;
        if (cbor_get_string(&dval, memo))
            out.memo = memo;
    }

    CborValue t_arr_val;
    if (!cbor_find_in_map(&root, "t", &t_arr_val) || !cbor_value_is_array(&t_arr_val))
        return false;

    CborValue t_it;
    if (cbor_value_enter_container(&t_arr_val, &t_it) != CborNoError)
        return false;

    out.proofs.clear();
    while (!cbor_value_at_end(&t_it)) {
        if (!cbor_value_is_map(&t_it)) {
            cbor_value_advance(&t_it);
            continue;
        }

        CborValue i_val;
        std::string keyset_id_hex;
        if (!cbor_find_in_map(&t_it, "i", &i_val) ||
            !cbor_get_bytes_as_hex(&i_val, keyset_id_hex))
            return false;

        CborValue p_arr_val;
        if (!cbor_find_in_map(&t_it, "p", &p_arr_val) || !cbor_value_is_array(&p_arr_val))
            return false;

        CborValue p_it;
        if (cbor_value_enter_container(&p_arr_val, &p_it) != CborNoError)
            return false;

        while (!cbor_value_at_end(&p_it)) {
            Proof proof;
            if (!decode_v4_proof(&p_it, proof, keyset_id_hex))
                return false;
            out.proofs.push_back(std::move(proof));
            if (cbor_value_advance(&p_it) != CborNoError)
                break;
        }

        if (cbor_value_advance(&t_it) != CborNoError)
            break;
    }

    ESP_LOGI(TAG, "decoded V4 token: %d proofs from %s",
             (int)out.proofs.size(), out.mint.c_str());
    return true;
}

// -------------------------------------------------------------------------
// Token V4 Encode
// -------------------------------------------------------------------------

std::string serialize_token_v4(const Token &token)
{
    // Group proofs by keyset ID
    std::map<std::string, std::vector<const Proof *>> by_keyset;
    for (const auto &p : token.proofs)
        by_keyset[p.id].push_back(&p);

    uint8_t buf[4096];
    CborEncoder enc;
    cbor_encoder_init(&enc, buf, sizeof(buf), 0);

    int map_items = 3 + (token.memo ? 1 : 0);
    CborEncoder map_enc;
    cbor_encoder_create_map(&enc, &map_enc, map_items);

    // "m": mint URL
    cbor_encode_text_stringz(&map_enc, "m");
    cbor_encode_text_stringz(&map_enc, token.mint.c_str());

    // "u": unit
    cbor_encode_text_stringz(&map_enc, "u");
    cbor_encode_text_stringz(&map_enc, token.unit.c_str());

    if (token.memo) {
        cbor_encode_text_stringz(&map_enc, "d");
        cbor_encode_text_stringz(&map_enc, token.memo->c_str());
    }

    // "t": token entries array
    cbor_encode_text_stringz(&map_enc, "t");
    CborEncoder t_arr;
    cbor_encoder_create_array(&map_enc, &t_arr, by_keyset.size());

    for (const auto &[keyset_id, proofs] : by_keyset) {
        CborEncoder entry_map;
        cbor_encoder_create_map(&t_arr, &entry_map, 2);

        // "i": keyset ID as bytes (short form: first 8 bytes = 16 hex chars)
        cbor_encode_text_stringz(&entry_map, "i");
        size_t id_byte_len = keyset_id.size() / 2;
        if (id_byte_len > 8) id_byte_len = 8;
        uint8_t id_bytes[33];
        hex_to_bytes(keyset_id.c_str(), id_bytes, id_byte_len);
        cbor_encode_byte_string(&entry_map, id_bytes, id_byte_len);

        // "p": proofs array
        cbor_encode_text_stringz(&entry_map, "p");
        CborEncoder p_arr;
        cbor_encoder_create_array(&entry_map, &p_arr, proofs.size());

        for (const Proof *p : proofs) {
            int proof_items = 3;
            if (p->dleq) proof_items++;
            if (p->witness) proof_items++;

            CborEncoder p_map;
            cbor_encoder_create_map(&p_arr, &p_map, proof_items);

            // "a": amount
            cbor_encode_text_stringz(&p_map, "a");
            cbor_encode_uint(&p_map, (uint64_t)p->amount);

            // "s": secret (text string)
            cbor_encode_text_stringz(&p_map, "s");
            cbor_encode_text_stringz(&p_map, p->secret.c_str());

            // "c": signature (byte string)
            cbor_encode_text_stringz(&p_map, "c");
            size_t c_len = p->C.size() / 2;
            uint8_t c_bytes[33];
            hex_to_bytes(p->C.c_str(), c_bytes, c_len);
            cbor_encode_byte_string(&p_map, c_bytes, c_len);

            if (p->dleq) {
                cbor_encode_text_stringz(&p_map, "d");
                CborEncoder dleq_map;
                int dleq_items = 2 + (p->dleq->r ? 1 : 0);
                cbor_encoder_create_map(&p_map, &dleq_map, dleq_items);

                cbor_encode_text_stringz(&dleq_map, "e");
                size_t e_len = p->dleq->e.size() / 2;
                uint8_t e_bytes[32];
                hex_to_bytes(p->dleq->e.c_str(), e_bytes, e_len);
                cbor_encode_byte_string(&dleq_map, e_bytes, e_len);

                cbor_encode_text_stringz(&dleq_map, "s");
                size_t s_len = p->dleq->s.size() / 2;
                uint8_t s_bytes[32];
                hex_to_bytes(p->dleq->s.c_str(), s_bytes, s_len);
                cbor_encode_byte_string(&dleq_map, s_bytes, s_len);

                if (p->dleq->r) {
                    cbor_encode_text_stringz(&dleq_map, "r");
                    size_t r_len = p->dleq->r->size() / 2;
                    uint8_t r_bytes[32];
                    hex_to_bytes(p->dleq->r->c_str(), r_bytes, r_len);
                    cbor_encode_byte_string(&dleq_map, r_bytes, r_len);
                }
                cbor_encoder_close_container(&p_map, &dleq_map);
            }

            if (p->witness) {
                cbor_encode_text_stringz(&p_map, "w");
                cbor_encode_text_stringz(&p_map, p->witness->c_str());
            }

            cbor_encoder_close_container(&p_arr, &p_map);
        }
        cbor_encoder_close_container(&entry_map, &p_arr);
        cbor_encoder_close_container(&t_arr, &entry_map);
    }
    cbor_encoder_close_container(&map_enc, &t_arr);
    cbor_encoder_close_container(&enc, &map_enc);

    size_t cbor_len = cbor_encoder_get_buffer_size(&enc, buf);
    std::string encoded = base64url_encode(buf, cbor_len);
    return std::string("cashuB") + encoded;
}

// -------------------------------------------------------------------------
// Payment Request Decode (NUT-18)
// -------------------------------------------------------------------------

static bool decode_tags(CborValue *arr_val,
                        std::vector<std::vector<std::string>> &out)
{
    if (!cbor_value_is_array(arr_val)) return false;
    CborValue arr_it;
    if (cbor_value_enter_container(arr_val, &arr_it) != CborNoError)
        return false;

    out.clear();
    while (!cbor_value_at_end(&arr_it)) {
        if (!cbor_value_is_array(&arr_it)) {
            cbor_value_advance(&arr_it);
            continue;
        }
        CborValue inner_it;
        if (cbor_value_enter_container(&arr_it, &inner_it) != CborNoError)
            return false;

        std::vector<std::string> tag;
        while (!cbor_value_at_end(&inner_it)) {
            std::string s;
            if (cbor_value_is_text_string(&inner_it) && cbor_get_string(&inner_it, s))
                tag.push_back(std::move(s));
            cbor_value_advance(&inner_it);
        }
        if (!tag.empty())
            out.push_back(std::move(tag));
        cbor_value_advance(&arr_it);
    }
    return true;
}

static bool decode_transport(CborValue *it, Transport &t)
{
    if (!cbor_value_is_map(it)) return false;
    CborValue val;
    if (!cbor_find_in_map(it, "t", &val) || !cbor_get_string(&val, t.type))
        return false;
    if (!cbor_find_in_map(it, "a", &val) || !cbor_get_string(&val, t.target))
        return false;

    CborValue g_val;
    if (cbor_find_in_map(it, "g", &g_val) && cbor_value_is_array(&g_val)) {
        std::vector<std::vector<std::string>> tags;
        if (decode_tags(&g_val, tags))
            t.tags = std::move(tags);
    }
    return true;
}

static bool decode_nut10(CborValue *it, NUT10Option &opt)
{
    if (!cbor_value_is_map(it)) return false;
    CborValue val;
    if (!cbor_find_in_map(it, "k", &val) || !cbor_get_string(&val, opt.kind))
        return false;
    if (!cbor_find_in_map(it, "d", &val) || !cbor_get_string(&val, opt.data))
        return false;

    CborValue t_val;
    if (cbor_find_in_map(it, "t", &t_val) && cbor_value_is_array(&t_val)) {
        std::vector<std::vector<std::string>> tags;
        if (decode_tags(&t_val, tags))
            opt.tags = std::move(tags);
    }
    return true;
}

bool deserialize_payment_request(const char *req_str, PaymentRequest &out)
{
    size_t len = strlen(req_str);
    static const char PREFIX[] = "creqA";
    static const size_t PREFIX_LEN = 5;

    if (len <= PREFIX_LEN || strncmp(req_str, PREFIX, PREFIX_LEN) != 0) {
        ESP_LOGE(TAG, "not a payment request (wrong prefix)");
        return false;
    }

    std::string cbor_data;
    if (!base64url_decode(req_str + PREFIX_LEN, len - PREFIX_LEN, cbor_data)) {
        ESP_LOGE(TAG, "base64url decode failed");
        return false;
    }

    CborParser parser;
    CborValue root;
    if (cbor_parser_init((const uint8_t *)cbor_data.data(), cbor_data.size(),
                         0, &parser, &root) != CborNoError)
        return false;

    if (!cbor_value_is_map(&root)) return false;

    CborValue val;
    if (cbor_find_in_map(&root, "i", &val) && cbor_value_is_text_string(&val)) {
        std::string id;
        if (cbor_get_string(&val, id))
            out.payment_id = id;
    }

    if (cbor_find_in_map(&root, "a", &val)) {
        int amount;
        if (cbor_get_int(&val, amount))
            out.amount = amount;
    }

    if (cbor_find_in_map(&root, "u", &val) && cbor_value_is_text_string(&val)) {
        std::string unit;
        if (cbor_get_string(&val, unit))
            out.unit = unit;
    }

    if (cbor_find_in_map(&root, "s", &val)) {
        bool single;
        if (cbor_get_bool(&val, single))
            out.single_use = single;
    }

    if (cbor_find_in_map(&root, "d", &val) && cbor_value_is_text_string(&val)) {
        std::string desc;
        if (cbor_get_string(&val, desc))
            out.description = desc;
    }

    if (cbor_find_in_map(&root, "m", &val) && cbor_value_is_array(&val)) {
        CborValue m_it;
        if (cbor_value_enter_container(&val, &m_it) == CborNoError) {
            std::vector<std::string> mints;
            while (!cbor_value_at_end(&m_it)) {
                std::string m;
                if (cbor_value_is_text_string(&m_it) && cbor_get_string(&m_it, m))
                    mints.push_back(std::move(m));
                cbor_value_advance(&m_it);
            }
            if (!mints.empty())
                out.mints = std::move(mints);
        }
    }

    if (cbor_find_in_map(&root, "t", &val) && cbor_value_is_array(&val)) {
        CborValue t_it;
        if (cbor_value_enter_container(&val, &t_it) == CborNoError) {
            std::vector<Transport> transports;
            while (!cbor_value_at_end(&t_it)) {
                Transport t;
                if (decode_transport(&t_it, t))
                    transports.push_back(std::move(t));
                cbor_value_advance(&t_it);
            }
            if (!transports.empty())
                out.transports = std::move(transports);
        }
    }

    CborValue nut10_val;
    if (cbor_find_in_map(&root, "nut10", &nut10_val) && cbor_value_is_map(&nut10_val)) {
        NUT10Option opt;
        if (decode_nut10(&nut10_val, opt))
            out.nut10 = std::move(opt);
    }

    ESP_LOGI(TAG, "decoded payment request id=%s amount=%s unit=%s",
             out.payment_id.value_or("-").c_str(),
             out.amount ? std::to_string(*out.amount).c_str() : "-",
             out.unit.value_or("-").c_str());
    return true;
}

// -------------------------------------------------------------------------
// Payment Request Encode (NUT-18)
// -------------------------------------------------------------------------

static void encode_tags(CborEncoder *parent,
                        const std::vector<std::vector<std::string>> &tags)
{
    CborEncoder arr;
    cbor_encoder_create_array(parent, &arr, tags.size());
    for (const auto &tag : tags) {
        CborEncoder inner;
        cbor_encoder_create_array(&arr, &inner, tag.size());
        for (const auto &s : tag)
            cbor_encode_text_stringz(&inner, s.c_str());
        cbor_encoder_close_container(&arr, &inner);
    }
    cbor_encoder_close_container(parent, &arr);
}

std::string serialize_payment_request(const PaymentRequest &req)
{
    uint8_t buf[2048];
    CborEncoder enc;
    cbor_encoder_init(&enc, buf, sizeof(buf), 0);

    int items = 0;
    if (req.payment_id) items++;
    if (req.amount) items++;
    if (req.unit) items++;
    if (req.single_use) items++;
    if (req.mints) items++;
    if (req.description) items++;
    if (req.transports) items++;
    if (req.nut10) items++;

    CborEncoder map_enc;
    cbor_encoder_create_map(&enc, &map_enc, items);

    if (req.transports && !req.transports->empty()) {
        cbor_encode_text_stringz(&map_enc, "t");
        CborEncoder t_arr;
        cbor_encoder_create_array(&map_enc, &t_arr, req.transports->size());
        for (const auto &t : *req.transports) {
            int t_items = 2 + (t.tags && !t.tags->empty() ? 1 : 0);
            CborEncoder t_map;
            cbor_encoder_create_map(&t_arr, &t_map, t_items);
            cbor_encode_text_stringz(&t_map, "t");
            cbor_encode_text_stringz(&t_map, t.type.c_str());
            cbor_encode_text_stringz(&t_map, "a");
            cbor_encode_text_stringz(&t_map, t.target.c_str());
            if (t.tags && !t.tags->empty()) {
                cbor_encode_text_stringz(&t_map, "g");
                encode_tags(&t_map, *t.tags);
            }
            cbor_encoder_close_container(&t_arr, &t_map);
        }
        cbor_encoder_close_container(&map_enc, &t_arr);
    }

    if (req.payment_id) {
        cbor_encode_text_stringz(&map_enc, "i");
        cbor_encode_text_stringz(&map_enc, req.payment_id->c_str());
    }
    if (req.amount) {
        cbor_encode_text_stringz(&map_enc, "a");
        cbor_encode_uint(&map_enc, (uint64_t)*req.amount);
    }
    if (req.unit) {
        cbor_encode_text_stringz(&map_enc, "u");
        cbor_encode_text_stringz(&map_enc, req.unit->c_str());
    }
    if (req.mints && !req.mints->empty()) {
        cbor_encode_text_stringz(&map_enc, "m");
        CborEncoder m_arr;
        cbor_encoder_create_array(&map_enc, &m_arr, req.mints->size());
        for (const auto &m : *req.mints)
            cbor_encode_text_stringz(&m_arr, m.c_str());
        cbor_encoder_close_container(&map_enc, &m_arr);
    }
    if (req.description) {
        cbor_encode_text_stringz(&map_enc, "d");
        cbor_encode_text_stringz(&map_enc, req.description->c_str());
    }
    if (req.single_use) {
        cbor_encode_text_stringz(&map_enc, "s");
        cbor_encode_boolean(&map_enc, *req.single_use);
    }
    if (req.nut10) {
        cbor_encode_text_stringz(&map_enc, "nut10");
        int n_items = 2 + (req.nut10->tags && !req.nut10->tags->empty() ? 1 : 0);
        CborEncoder n_map;
        cbor_encoder_create_map(&map_enc, &n_map, n_items);
        cbor_encode_text_stringz(&n_map, "k");
        cbor_encode_text_stringz(&n_map, req.nut10->kind.c_str());
        cbor_encode_text_stringz(&n_map, "d");
        cbor_encode_text_stringz(&n_map, req.nut10->data.c_str());
        if (req.nut10->tags && !req.nut10->tags->empty()) {
            cbor_encode_text_stringz(&n_map, "t");
            encode_tags(&n_map, *req.nut10->tags);
        }
        cbor_encoder_close_container(&map_enc, &n_map);
    }

    cbor_encoder_close_container(&enc, &map_enc);

    size_t cbor_len = cbor_encoder_get_buffer_size(&enc, buf);
    std::string encoded = base64url_encode(buf, cbor_len);
    return std::string("creqA") + encoded;
}

} // namespace cashu
