#include "keyset.hpp"

#include <cstdio>
#include <cstring>
#include <map>
#include <string>

#include "cashu_suite.h"
#include "hex.h"
#include <esp_log.h>
#include <mbedtls/sha256.h>

namespace cashu {

#define TAG "keyset"

static inline char ascii_lower(char c)
{
    return (c >= 'A' && c <= 'Z') ? (char)(c + ('a' - 'A')) : c;
}

static bool iequals(const std::string &a, const std::string &b)
{
    if (a.size() != b.size())
        return false;
    for (size_t i = 0; i < a.size(); i++)
        if (ascii_lower(a[i]) != ascii_lower(b[i]))
            return false;
    return true;
}

static bool istarts_with(const std::string &haystack, const std::string &prefix)
{
    if (haystack.size() < prefix.size())
        return false;
    for (size_t i = 0; i < prefix.size(); i++)
        if (ascii_lower(haystack[i]) != ascii_lower(prefix[i]))
            return false;
    return true;
}

KeysetVersion keyset_version(const std::string &id)
{
    if (id.size() < 2 || id[0] != '0')
        return KeysetVersion::unknown;
    if (id[1] == '0')
        return id.size() == 16 ? KeysetVersion::v1 : KeysetVersion::unknown;
    if (id[1] == '1')
        return id.size() == 66 ? KeysetVersion::v2 : KeysetVersion::unknown;
    if (id[1] == '2')
        // BLS scaffold. Assume a sha256-based 33-byte id (66 hex) like v2 so a
        // short legacy/base64 id that happens to start with "02" is not
        // misread as v3; the real length is fixed by the v3 spec.
        return id.size() == 66 ? KeysetVersion::v3 : KeysetVersion::unknown;
    // Anything else (incl. legacy pre-NUT-02 base64 ids like "ctv28hTYzQwr").
    return KeysetVersion::unknown;
}

KeysetProfile keyset_profile(KeysetVersion v)
{
    switch (v) {
    case KeysetVersion::v1:
        // v1 ("00") is a deprecated ID *format*, but mints still keep v1
        // keysets active and a wallet must mint against whatever active keyset
        // the mint offers. Mintability is gated by the mint's `active` flag +
        // an implemented suite (secp), not by the id-format version.
        return {KeysetVersion::v1, /*can_mint=*/true, /*has_dleq=*/true};
    case KeysetVersion::v2:
        return {KeysetVersion::v2, /*can_mint=*/true, /*has_dleq=*/true};
    case KeysetVersion::v3:
        return {KeysetVersion::v3, /*can_mint=*/false, /*has_dleq=*/false}; // scaffold
    default:
        // Legacy/unrecognized ids: secp BDHKE, so DLEQ may apply, but we can't
        // re-derive the id, so never mint with them (only spend existing proofs).
        return {KeysetVersion::unknown, /*can_mint=*/false, /*has_dleq=*/true};
    }
}

const cashu_suite_t *suite_for_id(const std::string &id)
{
    // BLS (v3) is the only non-secp scheme. Everything else — v1, v2, and
    // legacy/pre-NUT-02 ids — uses secp256k1 BDHKE, so secp is the default.
    if (keyset_version(id) == KeysetVersion::v3)
        return &cashu_suite_bls;  // scaffold (stub ops)
    return &cashu_suite_secp256k1;
}

// v1 (deprecated): "00" + first 14 hex of sha256(concatenated compressed
// pubkeys, amount-ascending). Mirrors nutshell derive_keyset_id().
static std::string derive_keyset_id_v1(const Keyset &ks)
{
    if (ks.keys.empty())
        return "";
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    bool ok = (mbedtls_sha256_starts(&sha, 0) == 0);
    for (const auto &kv : ks.keys) { // std::map => ascending by amount
        if (!ok || kv.second.size() != 66) { ok = false; break; }
        unsigned char pk[33];
        if (!hex_to_bytes(kv.second.c_str(), pk, 33) ||
            mbedtls_sha256_update(&sha, pk, 33) != 0) {
            ok = false;
            break;
        }
    }
    unsigned char digest[32];
    if (ok && mbedtls_sha256_finish(&sha, digest) != 0)
        ok = false;
    mbedtls_sha256_free(&sha);
    if (!ok)
        return "";

    char hex[17];
    hex[0] = '0';
    hex[1] = '0';
    bytes_to_hex(digest, 7, hex + 2);
    return std::string(hex, 16);
}

// v2 (current): "01" + sha256 of the UTF-8 preimage
//   "<amt>:<pk_hex>,<amt>:<pk_hex>,...|unit:<unit>[|input_fee_ppk:<f>][|final_expiry:<e>]"
// pubkeys lowercased; input_fee_ppk appended iff > 0; final_expiry appended iff
// present (matching nutshell derive_keyset_id_v2 — `if final_expiry is not None`).
static std::string derive_keyset_id_v2(const Keyset &ks)
{
    if (ks.keys.empty())
        return "";
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    bool ok = (mbedtls_sha256_starts(&sha, 0) == 0);

    auto feed = [&](const char *data, size_t len) {
        if (ok && len > 0 &&
            mbedtls_sha256_update(&sha, reinterpret_cast<const unsigned char *>(data), len) != 0)
            ok = false;
    };

    bool first = true;
    char seg[128];
    for (const auto &kv : ks.keys) { // ascending by amount
        if (!ok) break;
        int n = snprintf(seg, sizeof(seg), "%s%llu:",
                         first ? "" : ",", (unsigned long long)kv.first);
        first = false;
        if (n <= 0 || (size_t)n >= sizeof(seg)) { ok = false; break; }
        feed(seg, (size_t)n);

        // Lowercase pubkey hex on stack in chunks (typical length 66).
        const std::string &pk = kv.second;
        size_t pos = 0;
        while (pos < pk.size() && ok) {
            size_t chunk = pk.size() - pos;
            if (chunk > sizeof(seg)) chunk = sizeof(seg);
            for (size_t i = 0; i < chunk; i++)
                seg[i] = ascii_lower(pk[pos + i]);
            feed(seg, chunk);
            pos += chunk;
        }
    }

    feed("|unit:", 6);
    feed(ks.unit.data(), ks.unit.size());
    if (ks.input_fee_ppk > 0) {
        int n = snprintf(seg, sizeof(seg), "|input_fee_ppk:%d", ks.input_fee_ppk);
        if (n > 0 && (size_t)n < sizeof(seg)) feed(seg, (size_t)n);
        else ok = false;
    }
    if (ks.final_expiry) {
        int n = snprintf(seg, sizeof(seg), "|final_expiry:%lld", (long long)*ks.final_expiry);
        if (n > 0 && (size_t)n < sizeof(seg)) feed(seg, (size_t)n);
        else ok = false;
    }

    unsigned char digest[32];
    if (ok && mbedtls_sha256_finish(&sha, digest) != 0)
        ok = false;
    mbedtls_sha256_free(&sha);
    if (!ok)
        return "";

    char hex[67];
    hex[0] = '0';
    hex[1] = '1';
    bytes_to_hex(digest, 32, hex + 2);
    return std::string(hex, 66);
}

// v3 (BLS12-381): SCAFFOLD. The keyset-id preimage for BLS keysets is defined
// by the (draft) v3 spec; until implemented this returns "" so v3 keysets fail
// verify_keyset_id and are rejected at load time.
static std::string derive_keyset_id_v3(const Keyset &ks)
{
    (void)ks;
    return ""; // TODO(v3)
}

std::string derive_keyset_id(const Keyset &ks)
{
    switch (keyset_version(ks.id)) {
    case KeysetVersion::v1:
        return derive_keyset_id_v1(ks);
    case KeysetVersion::v2:
        return derive_keyset_id_v2(ks);
    case KeysetVersion::v3:
        return derive_keyset_id_v3(ks);
    default:
        return "";
    }
}

bool verify_keyset_id(const Keyset &ks)
{
    if (ks.id.empty())
        return false;
    const std::string derived = derive_keyset_id(ks);
    if (derived.empty())
        return false;
    return iequals(derived, ks.id);
}

std::string keyset_id_short(const std::string &id)
{
    return id.size() <= 16 ? id : id.substr(0, 16);
}

const Keyset *resolve_keyset(const std::vector<Keyset> &keysets,
                             const std::string &token_id,
                             bool *ambiguous)
{
    if (ambiguous)
        *ambiguous = false;
    if (token_id.empty())
        return nullptr;

    // Exact match wins.
    for (const auto &ks : keysets) {
        if (iequals(ks.id, token_id))
            return &ks;
    }
    // Otherwise treat token_id as a (short-form) prefix of a stored full id.
    const Keyset *match = nullptr;
    for (const auto &ks : keysets) {
        if (istarts_with(ks.id, token_id)) {
            if (match) { // more than one candidate => ambiguous, never guess
                if (ambiguous)
                    *ambiguous = true;
                return nullptr;
            }
            match = &ks;
        }
    }
    return match;
}

// Happy-path self-test. Vectors computed with nutshell's reference algorithm
// (pure SHA-256 over the documented preimage; no EC required to reproduce).
bool keyset_run_tests()
{
    bool ok = true;
    const std::map<uint64_t, std::string> keys = {
        {1, "03a40f20667ed53513075dc51e715ff2046cad64eb68960632269ba7f0210e38bc"},
        {2, "03fd4ce5a16b65576145949e6f99f445f8249fee17c606b688b504a849cdc452de"},
        {4, "02648eccfa4c026960966276fa5a4cae46ce0fd432211a4f449bf84f13aa5f8303"},
        {8, "02fdfd6796bfeac490cbee12f778f867f0a2c68f6508d17c649759ea0dc3547bc7"},
    };

    auto check = [&](const char *name, const Keyset &ks, const std::string &expect) {
        const std::string got = derive_keyset_id(ks);
        if (got != expect || !verify_keyset_id(ks)) {
            ESP_LOGE(TAG, "%s FAIL: got=%s want=%s", name, got.c_str(), expect.c_str());
            ok = false;
        } else {
            ESP_LOGI(TAG, "%s ok (%s)", name, expect.c_str());
        }
    };

    { // v1 deprecated: keys only
        Keyset ks;
        ks.unit = "sat";
        ks.active = true;
        ks.input_fee_ppk = 0;
        ks.keys = keys;
        ks.id = "00748e67013c1a1f";
        check("keyset_id v1", ks, "00748e67013c1a1f");
    }
    { // v2: no fee, no expiry
        Keyset ks;
        ks.unit = "sat";
        ks.active = true;
        ks.input_fee_ppk = 0;
        ks.keys = keys;
        ks.id = "018fa0e10e36d5d1d5bb784c8081c2dac0dcd022d9d188e96c320e5a7016c9883c";
        check("keyset_id v2 (no fee/expiry)", ks, ks.id);
    }
    { // v2: input_fee_ppk + final_expiry (exercises all preimage segments)
        Keyset ks;
        ks.unit = "sat";
        ks.active = true;
        ks.input_fee_ppk = 100;
        ks.final_expiry = 1893456000;
        ks.keys = keys;
        ks.id = "0127b003570e6f98b4723c574db6020d48a1c3bfe0a754e019f98a9546b8e922c1";
        check("keyset_id v2 (fee+expiry)", ks, ks.id);
    }
    return ok;
}

} // namespace cashu
