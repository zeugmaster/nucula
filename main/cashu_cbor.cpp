#include "cashu_cbor.hpp"
#include "base64url.hpp"
#include "cashu_suite.h"
#include "hex.h"

#include <cstring>
#include <utility>
#include <esp_log.h>
#include <cbor.h>

#define TAG "cashu_cbor"

namespace cashu {

// -------------------------------------------------------------------------
// CBOR decoder helpers
// -------------------------------------------------------------------------

static bool cbor_get_string(const CborValue *val, std::string &out)
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

static bool cbor_get_bytes_as_hex(const CborValue *val, std::string &out)
{
    if (!cbor_value_is_byte_string(val)) return false;
    size_t len = 0;
    if (cbor_value_get_string_length(val, &len) != CborNoError) return false;

    uint8_t stack_buf[64];
    std::vector<uint8_t> heap_buf;
    uint8_t *buf = stack_buf;
    if (len > sizeof(stack_buf)) {
        heap_buf.resize(len);
        buf = heap_buf.data();
    }
    if (cbor_value_copy_byte_string(val, buf, &len, nullptr) != CborNoError)
        return false;

    static const char digits[] = "0123456789abcdef";
    out.resize(len * 2);
    char *dst = out.data();
    for (size_t i = 0; i < len; i++) {
        dst[i * 2]     = digits[buf[i] >> 4];
        dst[i * 2 + 1] = digits[buf[i] & 0x0F];
    }
    return true;
}

static bool cbor_get_uint(const CborValue *val, uint64_t &out)
{
    if (!cbor_value_is_unsigned_integer(val)) return false;
    return cbor_value_get_uint64(val, &out) == CborNoError;
}

static bool cbor_get_int(const CborValue *val, int &out)
{
    // Amounts/fees are non-negative and must fit in int32; the previous
    // unchecked casts silently truncated 64-bit values.
    uint64_t u;
    if (cbor_get_uint(val, u)) {
        if (u > INT32_MAX)
            return false;
        out = (int)u;
        return true;
    }
    if (cbor_value_is_integer(val)) {
        int64_t i;
        if (cbor_value_get_int64(val, &i) == CborNoError) {
            if (i < 0 || i > INT32_MAX)
                return false;
            out = (int)i;
            return true;
        }
    }
    return false;
}

static bool cbor_get_bool(const CborValue *val, bool &out)
{
    if (!cbor_value_is_boolean(val)) return false;
    return cbor_value_get_boolean(val, &out) == CborNoError;
}

// Advance past a map key into its value, copying short text keys (<= 7 chars)
// onto the stack. Returns false only on malformed CBOR; non-text or long keys
// set key_len = 0 so the caller simply skips the value.
static bool cbor_next_map_key(CborValue &it, char key_out[8], size_t &key_len)
{
    key_len = 0;
    if (cbor_value_is_text_string(&it)) {
        size_t slen = 0;
        if (cbor_value_get_string_length(&it, &slen) == CborNoError && slen < 8) {
            size_t n = 8;
            CborValue next;
            if (cbor_value_copy_text_string(&it, key_out, &n, &next) != CborNoError)
                return false;
            key_out[n] = '\0';
            key_len = n;
            it = next;
            return !cbor_value_at_end(&it);
        }
    }
    if (cbor_value_advance(&it) != CborNoError)
        return false;
    return !cbor_value_at_end(&it);
}

// -------------------------------------------------------------------------
// Token V4 Decode (single-pass map iteration)
// -------------------------------------------------------------------------

static bool decode_v4_dleq(const CborValue *map, DLEQ &dleq)
{
    if (!cbor_value_is_map(map)) return false;
    CborValue it;
    if (cbor_value_enter_container(map, &it) != CborNoError)
        return false;

    bool has_e = false, has_s = false;
    while (!cbor_value_at_end(&it)) {
        char k[8];
        size_t klen = 0;
        if (!cbor_next_map_key(it, k, klen)) return false;

        if (klen == 1) {
            if (k[0] == 'e') {
                if (!cbor_get_bytes_as_hex(&it, dleq.e)) return false;
                has_e = true;
            } else if (k[0] == 's') {
                if (!cbor_get_bytes_as_hex(&it, dleq.s)) return false;
                has_s = true;
            } else if (k[0] == 'r' && cbor_value_is_byte_string(&it)) {
                std::string r_hex;
                if (cbor_get_bytes_as_hex(&it, r_hex))
                    dleq.r = std::move(r_hex);
            }
        }
        if (cbor_value_advance(&it) != CborNoError) return false;
    }
    return has_e && has_s;
}

static bool decode_v4_proof(const CborValue *map, Proof &proof, const std::string &keyset_id)
{
    if (!cbor_value_is_map(map)) return false;
    CborValue it;
    if (cbor_value_enter_container(map, &it) != CborNoError)
        return false;

    proof.id = keyset_id;
    bool has_a = false, has_s = false, has_c = false;

    while (!cbor_value_at_end(&it)) {
        char k[8];
        size_t klen = 0;
        if (!cbor_next_map_key(it, k, klen)) return false;

        if (klen == 1) {
            switch (k[0]) {
            case 'a':
                if (!cbor_get_int(&it, proof.amount)) return false;
                has_a = true;
                break;
            case 's':
                if (!cbor_get_string(&it, proof.secret)) return false;
                has_s = true;
                break;
            case 'c':
                if (!cbor_get_bytes_as_hex(&it, proof.C)) return false;
                has_c = true;
                break;
            case 'd':
                if (cbor_value_is_map(&it)) {
                    DLEQ dleq;
                    if (decode_v4_dleq(&it, dleq))
                        proof.dleq = std::move(dleq);
                }
                break;
            case 'w':
                if (cbor_value_is_text_string(&it)) {
                    std::string w;
                    if (cbor_get_string(&it, w))
                        proof.witness = std::move(w);
                }
                break;
            default:
                break;
            }
        }
        if (cbor_value_advance(&it) != CborNoError) return false;
    }
    return has_a && has_s && has_c;
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

    CborValue it;
    if (cbor_value_enter_container(&root, &it) != CborNoError)
        return false;

    out.memo = std::nullopt;
    out.proofs.clear();
    bool has_m = false, has_u = false, has_t = false;
    CborValue t_arr_val{};

    while (!cbor_value_at_end(&it)) {
        char k[8];
        size_t klen = 0;
        if (!cbor_next_map_key(it, k, klen)) return false;

        if (klen == 1) {
            if (k[0] == 'm') {
                if (!cbor_get_string(&it, out.mint)) return false;
                has_m = true;
            } else if (k[0] == 'u') {
                if (!cbor_get_string(&it, out.unit)) return false;
                has_u = true;
            } else if (k[0] == 'd' && cbor_value_is_text_string(&it)) {
                std::string memo;
                if (cbor_get_string(&it, memo))
                    out.memo = std::move(memo);
            } else if (k[0] == 't') {
                if (!cbor_value_is_array(&it)) return false;
                t_arr_val = it;
                has_t = true;
            }
        }
        if (cbor_value_advance(&it) != CborNoError) return false;
    }

    if (!has_m || !has_u || !has_t)
        return false;

    CborValue t_it;
    if (cbor_value_enter_container(&t_arr_val, &t_it) != CborNoError)
        return false;

    while (!cbor_value_at_end(&t_it)) {
        if (!cbor_value_is_map(&t_it)) {
            if (cbor_value_advance(&t_it) != CborNoError) break;
            continue;
        }

        CborValue e_it;
        if (cbor_value_enter_container(&t_it, &e_it) != CborNoError)
            return false;

        std::string keyset_id_hex;
        CborValue p_arr_val{};
        bool has_i = false, has_p = false;

        while (!cbor_value_at_end(&e_it)) {
            char k[8];
            size_t klen = 0;
            if (!cbor_next_map_key(e_it, k, klen)) return false;

            if (klen == 1 && k[0] == 'i') {
                if (!cbor_get_bytes_as_hex(&e_it, keyset_id_hex)) return false;
                has_i = true;
            } else if (klen == 1 && k[0] == 'p') {
                if (!cbor_value_is_array(&e_it)) return false;
                p_arr_val = e_it;
                has_p = true;
            }
            if (cbor_value_advance(&e_it) != CborNoError) return false;
        }

        if (!has_i || !has_p)
            return false;

        size_t arr_len = 0;
        if (cbor_value_is_length_known(&p_arr_val) &&
            cbor_value_get_array_length(&p_arr_val, &arr_len) == CborNoError)
            out.proofs.reserve(out.proofs.size() + arr_len);

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

// Encode a hex string as a CBOR byte string. Hard-fails on odd length,
// invalid characters, or more than max_bytes (<= CASHU_MAX_POINT_LEN)
// decoded bytes — a malformed field must abort the whole token, not
// silently truncate it.
static bool encode_hex_bytes(CborEncoder *enc, const std::string &hex,
                             size_t max_bytes)
{
    uint8_t bytes[CASHU_MAX_POINT_LEN];
    size_t len = hex.size() / 2;
    if ((hex.size() % 2) != 0 || len > max_bytes || max_bytes > sizeof(bytes))
        return false;
    if (len > 0 && !hex_to_bytes(hex.c_str(), bytes, len))
        return false;
    cbor_encode_byte_string(enc, bytes, len);
    return true;
}

using KeysetGroup = std::pair<const std::string *, std::vector<const Proof *>>;

// One encoding pass. Returns false on malformed fields; buffer overflow is
// not an error here — the caller checks cbor_encoder_get_extra_bytes_needed
// and retries with a larger buffer.
static bool encode_token_v4(const Token &token,
                            const std::vector<KeysetGroup> &by_keyset,
                            uint8_t *buf, size_t buf_size, CborEncoder &enc)
{
    cbor_encoder_init(&enc, buf, buf_size, 0);

    int map_items = 3 + (token.memo ? 1 : 0);
    CborEncoder map_enc;
    cbor_encoder_create_map(&enc, &map_enc, map_items);

    // "m": mint URL
    cbor_encode_text_string(&map_enc, "m", 1);
    cbor_encode_text_string(&map_enc, token.mint.data(), token.mint.size());

    // "u": unit
    cbor_encode_text_string(&map_enc, "u", 1);
    cbor_encode_text_string(&map_enc, token.unit.data(), token.unit.size());

    if (token.memo) {
        cbor_encode_text_string(&map_enc, "d", 1);
        cbor_encode_text_string(&map_enc, token.memo->data(), token.memo->size());
    }

    // "t": token entries array
    cbor_encode_text_string(&map_enc, "t", 1);
    CborEncoder t_arr;
    cbor_encoder_create_array(&map_enc, &t_arr, by_keyset.size());

    for (const auto &[keyset_id, proofs] : by_keyset) {
        CborEncoder entry_map;
        cbor_encoder_create_map(&t_arr, &entry_map, 2);

        // "i": keyset ID as bytes. Encode the FULL id: v1 -> 8 bytes, v2 -> 33.
        cbor_encode_text_string(&entry_map, "i", 1);
        if (!encode_hex_bytes(&entry_map, *keyset_id, CASHU_MAX_POINT_LEN))
            return false;

        // "p": proofs array
        cbor_encode_text_string(&entry_map, "p", 1);
        CborEncoder p_arr;
        cbor_encoder_create_array(&entry_map, &p_arr, proofs.size());

        for (const Proof *p : proofs) {
            int proof_items = 3;
            if (p->dleq) proof_items++;
            if (p->witness) proof_items++;

            CborEncoder p_map;
            cbor_encoder_create_map(&p_arr, &p_map, proof_items);

            // "a": amount
            cbor_encode_text_string(&p_map, "a", 1);
            cbor_encode_uint(&p_map, (uint64_t)p->amount);

            // "s": secret (text string)
            cbor_encode_text_string(&p_map, "s", 1);
            cbor_encode_text_string(&p_map, p->secret.data(), p->secret.size());

            // "c": signature (byte string), sized for any suite's points
            cbor_encode_text_string(&p_map, "c", 1);
            if (!encode_hex_bytes(&p_map, p->C, CASHU_MAX_POINT_LEN))
                return false;

            if (p->dleq) {
                cbor_encode_text_string(&p_map, "d", 1);
                CborEncoder dleq_map;
                int dleq_items = 2 + (p->dleq->r ? 1 : 0);
                cbor_encoder_create_map(&p_map, &dleq_map, dleq_items);

                cbor_encode_text_string(&dleq_map, "e", 1);
                if (!encode_hex_bytes(&dleq_map, p->dleq->e, 32))
                    return false;

                cbor_encode_text_string(&dleq_map, "s", 1);
                if (!encode_hex_bytes(&dleq_map, p->dleq->s, 32))
                    return false;

                if (p->dleq->r) {
                    cbor_encode_text_string(&dleq_map, "r", 1);
                    if (!encode_hex_bytes(&dleq_map, *p->dleq->r, 32))
                        return false;
                }
                cbor_encoder_close_container(&p_map, &dleq_map);
            }

            if (p->witness) {
                cbor_encode_text_string(&p_map, "w", 1);
                cbor_encode_text_string(&p_map, p->witness->data(), p->witness->size());
            }

            cbor_encoder_close_container(&p_arr, &p_map);
        }
        cbor_encoder_close_container(&entry_map, &p_arr);
        cbor_encoder_close_container(&t_arr, &entry_map);
    }
    cbor_encoder_close_container(&map_enc, &t_arr);
    cbor_encoder_close_container(&enc, &map_enc);
    return true;
}

std::string serialize_token_v4(const Token &token)
{
    // Group proofs by keyset ID without allocating RB-tree nodes or copying IDs.
    std::vector<KeysetGroup> by_keyset;
    by_keyset.reserve(2);
    for (const auto &p : token.proofs) {
        KeysetGroup *grp = nullptr;
        for (auto &g : by_keyset) {
            if (*g.first == p.id) { grp = &g; break; }
        }
        if (!grp) {
            by_keyset.emplace_back(&p.id, std::vector<const Proof *>{});
            grp = &by_keyset.back();
            grp->second.reserve(token.proofs.size());
        }
        grp->second.push_back(&p);
    }

    // Capacity estimate only — if it's short, TinyCBOR reports how many
    // bytes were missing and we re-encode once into an exact-sized buffer.
    std::vector<uint8_t> buf(256 + token.proofs.size() * 240);
    CborEncoder enc;
    if (!encode_token_v4(token, by_keyset, buf.data(), buf.size(), enc)) {
        ESP_LOGE(TAG, "token encode: malformed field");
        return "";
    }

    size_t extra = cbor_encoder_get_extra_bytes_needed(&enc);
    if (extra > 0) {
        buf.resize(buf.size() + extra);
        if (!encode_token_v4(token, by_keyset, buf.data(), buf.size(), enc) ||
            cbor_encoder_get_extra_bytes_needed(&enc) > 0) {
            ESP_LOGE(TAG, "token encode: buffer sizing failed");
            return "";
        }
    }

    size_t cbor_len = cbor_encoder_get_buffer_size(&enc, buf.data());
    std::string result;
    result.reserve(6 + ((cbor_len * 4 + 2) / 3));
    result.append("cashuB", 6);
    base64url_encode_append(buf.data(), cbor_len, result);
    return result;
}

// -------------------------------------------------------------------------
// Payment Request Decode (NUT-18)
// -------------------------------------------------------------------------

static bool decode_tags(const CborValue *arr_val,
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

static bool decode_transport(const CborValue *map, Transport &t)
{
    if (!cbor_value_is_map(map)) return false;
    CborValue it;
    if (cbor_value_enter_container(map, &it) != CborNoError)
        return false;

    bool has_t = false, has_a = false;
    while (!cbor_value_at_end(&it)) {
        char k[8];
        size_t klen = 0;
        if (!cbor_next_map_key(it, k, klen)) return false;

        if (klen == 1) {
            if (k[0] == 't') {
                if (!cbor_get_string(&it, t.type)) return false;
                has_t = true;
            } else if (k[0] == 'a') {
                if (!cbor_get_string(&it, t.target)) return false;
                has_a = true;
            } else if (k[0] == 'g' && cbor_value_is_array(&it)) {
                std::vector<std::vector<std::string>> tags;
                if (decode_tags(&it, tags))
                    t.tags = std::move(tags);
            }
        }
        if (cbor_value_advance(&it) != CborNoError) return false;
    }
    return has_t && has_a;
}

static bool decode_nut10(const CborValue *map, NUT10Option &opt)
{
    if (!cbor_value_is_map(map)) return false;
    CborValue it;
    if (cbor_value_enter_container(map, &it) != CborNoError)
        return false;

    bool has_k = false, has_d = false;
    while (!cbor_value_at_end(&it)) {
        char k[8];
        size_t klen = 0;
        if (!cbor_next_map_key(it, k, klen)) return false;

        if (klen == 1) {
            if (k[0] == 'k') {
                if (!cbor_get_string(&it, opt.kind)) return false;
                has_k = true;
            } else if (k[0] == 'd') {
                if (!cbor_get_string(&it, opt.data)) return false;
                has_d = true;
            } else if (k[0] == 't' && cbor_value_is_array(&it)) {
                std::vector<std::vector<std::string>> tags;
                if (decode_tags(&it, tags))
                    opt.tags = std::move(tags);
            }
        }
        if (cbor_value_advance(&it) != CborNoError) return false;
    }
    return has_k && has_d;
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

    CborValue it;
    if (cbor_value_enter_container(&root, &it) != CborNoError)
        return false;

    out = PaymentRequest{};

    while (!cbor_value_at_end(&it)) {
        char k[8];
        size_t klen = 0;
        if (!cbor_next_map_key(it, k, klen)) return false;

        if (klen == 1) {
            switch (k[0]) {
            case 'i':
                if (cbor_value_is_text_string(&it)) {
                    std::string id;
                    if (cbor_get_string(&it, id))
                        out.payment_id = std::move(id);
                }
                break;
            case 'a': {
                int amount;
                if (cbor_get_int(&it, amount))
                    out.amount = amount;
                break;
            }
            case 'u':
                if (cbor_value_is_text_string(&it)) {
                    std::string unit;
                    if (cbor_get_string(&it, unit))
                        out.unit = std::move(unit);
                }
                break;
            case 's': {
                bool single;
                if (cbor_get_bool(&it, single))
                    out.single_use = single;
                break;
            }
            case 'd':
                if (cbor_value_is_text_string(&it)) {
                    std::string desc;
                    if (cbor_get_string(&it, desc))
                        out.description = std::move(desc);
                }
                break;
            case 'm':
                if (cbor_value_is_array(&it)) {
                    CborValue m_it;
                    if (cbor_value_enter_container(&it, &m_it) == CborNoError) {
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
                break;
            case 't':
                if (cbor_value_is_array(&it)) {
                    CborValue t_it;
                    if (cbor_value_enter_container(&it, &t_it) == CborNoError) {
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
                break;
            default:
                break;
            }
        } else if (klen == 5 && memcmp(k, "nut10", 5) == 0 && cbor_value_is_map(&it)) {
            NUT10Option opt;
            if (decode_nut10(&it, opt))
                out.nut10 = std::move(opt);
        }

        if (cbor_value_advance(&it) != CborNoError) return false;
    }

    ESP_LOGI(TAG, "decoded payment request id=%s amount=%d unit=%s",
             out.payment_id ? out.payment_id->c_str() : "-",
             out.amount ? *out.amount : -1,
             out.unit ? out.unit->c_str() : "-");
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
            cbor_encode_text_string(&inner, s.data(), s.size());
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
    if (req.mints && !req.mints->empty()) items++;
    if (req.description) items++;
    if (req.transports && !req.transports->empty()) items++;
    if (req.nut10) items++;

    CborEncoder map_enc;
    cbor_encoder_create_map(&enc, &map_enc, items);

    if (req.transports && !req.transports->empty()) {
        cbor_encode_text_string(&map_enc, "t", 1);
        CborEncoder t_arr;
        cbor_encoder_create_array(&map_enc, &t_arr, req.transports->size());
        for (const auto &t : *req.transports) {
            int t_items = 2 + (t.tags && !t.tags->empty() ? 1 : 0);
            CborEncoder t_map;
            cbor_encoder_create_map(&t_arr, &t_map, t_items);
            cbor_encode_text_string(&t_map, "t", 1);
            cbor_encode_text_string(&t_map, t.type.data(), t.type.size());
            cbor_encode_text_string(&t_map, "a", 1);
            cbor_encode_text_string(&t_map, t.target.data(), t.target.size());
            if (t.tags && !t.tags->empty()) {
                cbor_encode_text_string(&t_map, "g", 1);
                encode_tags(&t_map, *t.tags);
            }
            cbor_encoder_close_container(&t_arr, &t_map);
        }
        cbor_encoder_close_container(&map_enc, &t_arr);
    }

    if (req.payment_id) {
        cbor_encode_text_string(&map_enc, "i", 1);
        cbor_encode_text_string(&map_enc, req.payment_id->data(), req.payment_id->size());
    }
    if (req.amount) {
        cbor_encode_text_string(&map_enc, "a", 1);
        cbor_encode_uint(&map_enc, (uint64_t)*req.amount);
    }
    if (req.unit) {
        cbor_encode_text_string(&map_enc, "u", 1);
        cbor_encode_text_string(&map_enc, req.unit->data(), req.unit->size());
    }
    if (req.mints && !req.mints->empty()) {
        cbor_encode_text_string(&map_enc, "m", 1);
        CborEncoder m_arr;
        cbor_encoder_create_array(&map_enc, &m_arr, req.mints->size());
        for (const auto &m : *req.mints)
            cbor_encode_text_string(&m_arr, m.data(), m.size());
        cbor_encoder_close_container(&map_enc, &m_arr);
    }
    if (req.description) {
        cbor_encode_text_string(&map_enc, "d", 1);
        cbor_encode_text_string(&map_enc, req.description->data(), req.description->size());
    }
    if (req.single_use) {
        cbor_encode_text_string(&map_enc, "s", 1);
        cbor_encode_boolean(&map_enc, *req.single_use);
    }
    if (req.nut10) {
        cbor_encode_text_string(&map_enc, "nut10", 5);
        int n_items = 2 + (req.nut10->tags && !req.nut10->tags->empty() ? 1 : 0);
        CborEncoder n_map;
        cbor_encoder_create_map(&map_enc, &n_map, n_items);
        cbor_encode_text_string(&n_map, "k", 1);
        cbor_encode_text_string(&n_map, req.nut10->kind.data(), req.nut10->kind.size());
        cbor_encode_text_string(&n_map, "d", 1);
        cbor_encode_text_string(&n_map, req.nut10->data.data(), req.nut10->data.size());
        if (req.nut10->tags && !req.nut10->tags->empty()) {
            cbor_encode_text_string(&n_map, "t", 1);
            encode_tags(&n_map, *req.nut10->tags);
        }
        cbor_encoder_close_container(&map_enc, &n_map);
    }

    cbor_encoder_close_container(&enc, &map_enc);

    if (cbor_encoder_get_extra_bytes_needed(&enc) > 0) {
        ESP_LOGE(TAG, "payment request encode: buffer too small");
        return "";
    }

    size_t cbor_len = cbor_encoder_get_buffer_size(&enc, buf);
    std::string result;
    result.reserve(5 + ((cbor_len * 4 + 2) / 3));
    result.append("creqA", 5);
    base64url_encode_append(buf, cbor_len, result);
    return result;
}

} // namespace cashu
