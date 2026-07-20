#include "wallet.hpp"
#include "wallet_internal.hpp"
#include "cashu_json.hpp"
#include "keyset.hpp"
#include "http.h"

#include <algorithm>
#include <esp_log.h>
#include <cJSON.h>

namespace cashu {

// -------------------------------------------------------------------------
// Keyset loading
// -------------------------------------------------------------------------

// Step 1: GET /v1/keysets for metadata (id, unit, active, input_fee_ppk),
// capped at MAX_KEYSETS with active keysets ranked first.
static bool fetch_keyset_infos(const std::string& mint_url,
                               std::vector<KeysetInfo>& infos)
{
    std::string keysets_url = mint_url + "/v1/keysets";
    http_response_t resp = {};
    esp_err_t err = http_get(keysets_url.c_str(), &resp);
    if (err != ESP_OK || resp.status != 200 || !resp.body) {
        ESP_LOGE(TAG, "GET %s failed (err=%s, status=%d)",
                 keysets_url.c_str(), esp_err_to_name(err), resp.status);
        http_response_free(&resp);
        return false;
    }

    cJSON* json = cJSON_Parse(resp.body);
    http_response_free(&resp);
    if (!json) {
        ESP_LOGE(TAG, "failed to parse /v1/keysets JSON");
        return false;
    }

    bool ok = from_json_keyset_info_response(json, infos);
    cJSON_Delete(json);

    if (!ok || infos.empty()) {
        ESP_LOGE(TAG, "no keysets in /v1/keysets response");
        return false;
    }

    if ((int)infos.size() > MAX_KEYSETS) {
        ESP_LOGW(TAG, "mint has %d keysets, capping at %d",
                 (int)infos.size(), MAX_KEYSETS);
        // Keep active keysets first, then fill remaining slots
        std::stable_sort(infos.begin(), infos.end(),
                         [](const KeysetInfo& a, const KeysetInfo& b) {
                             return a.active > b.active;
                         });
        infos.resize(MAX_KEYSETS);
    }
    return true;
}

// Step 2: fetch keys for all ACTIVE keysets in a SINGLE GET /v1/keys.
// This replaces N per-keyset /v1/keys/{id} TLS handshakes with one — far
// less peak heap and far more reliable on a memory-constrained device.
// Inactive keysets are not fetched here; any the wallet already holds
// proofs under are preserved from NVS by merge_keysets (it never drops
// existing keysets), so held proofs stay spendable. A response that
// fails to parse leaves keys_resp empty (every join below then misses).
static bool fetch_all_active_keys(const std::string& mint_url,
                                  std::vector<Keyset>& keys_resp)
{
    std::string keys_url = mint_url + "/v1/keys";
    http_response_t kresp = {};
    esp_err_t err = http_get(keys_url.c_str(), &kresp);
    if (err != ESP_OK || kresp.status != 200 || !kresp.body) {
        ESP_LOGE(TAG, "GET %s failed (err=%s, status=%d)",
                 keys_url.c_str(), esp_err_to_name(err), kresp.status);
        http_response_free(&kresp);
        return false;
    }
    cJSON* kjson = cJSON_Parse(kresp.body);
    http_response_free(&kresp);
    if (kjson) {
        from_json_keyset_response(kjson, keys_resp);
        cJSON_Delete(kjson);
    }
    return true;
}

// Join the metadata rows with their keys and apply NUT-02 id validation:
// re-derive each keyset id from its keys (+unit/fee/expiry for v2) and
// reject a mint whose claimed id does not match — closing the gap where
// the mint's claimed id was trusted verbatim. Only v1/v2 ids can be
// re-derived: v3/BLS crypto is not implemented yet (skip), and legacy
// pre-NUT-02 ids cannot be re-derived (accept unvalidated, secp).
static std::vector<Keyset> build_validated_keysets(
    const std::vector<KeysetInfo>& infos, std::vector<Keyset>& keys_resp)
{
    std::vector<Keyset> result;
    for (const auto& info : infos) {
        if (!info.active)
            continue;  // only active keysets are fetched here / minted with

        // Match this keyset's keys from the single /v1/keys response.
        std::map<uint64_t, std::string>* keys = nullptr;
        for (auto& kk : keys_resp) {
            if (kk.id == info.id) { keys = &kk.keys; break; }
        }
        if (!keys || keys->empty()) {
            ESP_LOGW(TAG, "no keys for active keyset %s, skipping", info.id.c_str());
            continue;
        }

        Keyset ks;
        ks.id = info.id;
        ks.unit = info.unit;
        ks.active = info.active;
        ks.input_fee_ppk = info.input_fee_ppk;
        ks.final_expiry = info.final_expiry;
        ks.keys = std::move(*keys);

        KeysetVersion ver = keyset_version(ks.id);
        if (ver == KeysetVersion::v3) {
            ESP_LOGW(TAG, "keyset %s: v3/BLS not supported yet, skipping", ks.id.c_str());
            continue;
        }
        if (ver == KeysetVersion::v1 || ver == KeysetVersion::v2) {
            if (!verify_keyset_id(ks)) {
#if CASHU_REQUIRE_VALID_KEYSET_ID
                ESP_LOGE(TAG, "keyset %s: id != derived %s, rejecting",
                         ks.id.c_str(), derive_keyset_id(ks).c_str());
                continue;
#else
                ESP_LOGW(TAG, "keyset %s: id != derived %s, accepting (validation off)",
                         ks.id.c_str(), derive_keyset_id(ks).c_str());
#endif
            }
        } else {
            ESP_LOGI(TAG, "keyset %s: legacy/unrecognized id, accepting unvalidated",
                     ks.id.c_str());
        }

        result.push_back(std::move(ks));
    }
    return result;
}

// NUT-02: reject keyset id collisions. The shortest prefix any subsystem
// keys on is the 13-hex NUT-13 counter key, so enforce uniqueness there
// (which also keeps the 8-byte short-form resolver unambiguous). False
// when two ACTIVE keysets collide — that mint cannot be used safely.
static bool drop_id_prefix_collisions(std::vector<Keyset>& result)
{
    for (size_t a = 0; a < result.size(); a++) {
        for (size_t b = a + 1; b < result.size(); ) {
            if (result[a].id.compare(0, 13, result[b].id, 0, 13) == 0) {
                ESP_LOGE(TAG, "keyset id prefix collision: %s vs %s",
                         result[a].id.c_str(), result[b].id.c_str());
                if (result[a].active && result[b].active) {
                    ESP_LOGE(TAG, "two active keysets collide; aborting load");
                    return false;
                }
                result.erase(result.begin() + b);  // drop the later one
            } else {
                b++;
            }
        }
    }
    return true;
}

bool Wallet::load_keysets()
{
    std::vector<KeysetInfo> infos;
    if (!fetch_keyset_infos(mint_url_, infos))
        return false;

    std::vector<Keyset> keys_resp;
    if (!fetch_all_active_keys(mint_url_, keys_resp))
        return false;

    std::vector<Keyset> result = build_validated_keysets(infos, keys_resp);
    if (result.empty()) {
        ESP_LOGE(TAG, "no active keyset keys loaded from %s", mint_url_.c_str());
        return false;
    }

    if (!drop_id_prefix_collisions(result))
        return false;

    bool changed = merge_keysets(result);
    ESP_LOGI(TAG, "loaded %d keyset(s) from %s (total %d after merge)",
             (int)result.size(), mint_url_.c_str(), (int)keysets_.size());

    for (const auto& k : keysets_) {
        ESP_LOGI(TAG, "  keyset %s unit=%s active=%d keys=%d fee=%d",
                 k.id.c_str(), k.unit.c_str(), k.active,
                 (int)k.keys.size(), k.input_fee_ppk);
    }

    // Each refresh used to rewrite every keyset blob (~16 KB of flash
    // writes) even when nothing changed — which is the common case.
    if (changed)
        save_keysets();
    return true;
}

} // namespace cashu
