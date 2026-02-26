#include "wallet.hpp"
#include "cashu_json.hpp"
#include "crypto.h"
#include "hex.h"
#include "http.h"

#include <algorithm>
#include <cstring>
#include <esp_log.h>
#include <esp_random.h>
#include <nvs_flash.h>
#include <nvs.h>

#define TAG "wallet"

static const char* NVS_NS = "wallet";
static const int MAX_KEYSETS = 10;

static void slot_key(char* buf, size_t sz, const char* base, int slot)
{
    snprintf(buf, sz, "%s_%d", base, slot);
}

namespace cashu {

Wallet::Wallet(const std::string& mint_url, secp256k1_context* ctx, int nvs_slot)
    : mint_url_(mint_url), ctx_(ctx), nvs_slot_(nvs_slot) {}

// -------------------------------------------------------------------------
// NVS persistence
// -------------------------------------------------------------------------

bool Wallet::save_mint_url()
{
    nvs_handle_t handle;
    if (nvs_open(NVS_NS, NVS_READWRITE, &handle) != ESP_OK)
        return false;
    char key[16];
    slot_key(key, sizeof(key), "url", nvs_slot_);
    esp_err_t err = nvs_set_str(handle, key, mint_url_.c_str());
    if (err == ESP_OK) err = nvs_commit(handle);
    nvs_close(handle);
    return err == ESP_OK;
}

std::string Wallet::load_mint_url_for_slot(int slot)
{
    nvs_handle_t handle;
    if (nvs_open(NVS_NS, NVS_READONLY, &handle) != ESP_OK)
        return "";
    char key[16];
    slot_key(key, sizeof(key), "url", slot);
    size_t len = 0;
    if (nvs_get_str(handle, key, nullptr, &len) != ESP_OK || len == 0) {
        nvs_close(handle);
        return "";
    }
    std::string url(len - 1, '\0');
    nvs_get_str(handle, key, url.data(), &len);
    nvs_close(handle);
    return url;
}

bool Wallet::erase_nvs()
{
    nvs_handle_t handle;
    if (nvs_open(NVS_NS, NVS_READWRITE, &handle) != ESP_OK)
        return false;
    char key[16];
    slot_key(key, sizeof(key), "url", nvs_slot_);
    nvs_erase_key(handle, key);
    slot_key(key, sizeof(key), "proofs", nvs_slot_);
    nvs_erase_key(handle, key);
    // Legacy single-blob keyset entry
    slot_key(key, sizeof(key), "keys", nvs_slot_);
    nvs_erase_key(handle, key);
    // Individual keyset entries
    snprintf(key, sizeof(key), "kn_%d", nvs_slot_);
    nvs_erase_key(handle, key);
    for (int i = 0; i < MAX_KEYSETS; i++) {
        snprintf(key, sizeof(key), "k_%d_%d", nvs_slot_, i);
        nvs_erase_key(handle, key);
    }
    nvs_commit(handle);
    nvs_close(handle);
    ESP_LOGI(TAG, "erased NVS slot %d", nvs_slot_);
    return true;
}

bool Wallet::save_proofs()
{
    std::string blob = proofs_to_json(proofs_);

    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NS, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open failed: %s", esp_err_to_name(err));
        return false;
    }

    char key[16];
    slot_key(key, sizeof(key), "proofs", nvs_slot_);
    err = nvs_set_blob(handle, key, blob.data(), blob.size());
    if (err == ESP_OK)
        err = nvs_commit(handle);
    nvs_close(handle);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "save_proofs failed: %s", esp_err_to_name(err));
        return false;
    }
    ESP_LOGI(TAG, "[%d] saved %d proofs (%d bytes)",
             nvs_slot_, (int)proofs_.size(), (int)blob.size());
    return true;
}

bool Wallet::load_proofs()
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NS, NVS_READONLY, &handle);
    if (err != ESP_OK)
        return false;

    char key[16];
    slot_key(key, sizeof(key), "proofs", nvs_slot_);
    size_t required = 0;
    err = nvs_get_blob(handle, key, nullptr, &required);
    if (err != ESP_OK || required == 0) {
        nvs_close(handle);
        return false;
    }

    std::string blob(required, '\0');
    err = nvs_get_blob(handle, key, blob.data(), &required);
    nvs_close(handle);
    if (err != ESP_OK)
        return false;

    std::vector<Proof> loaded;
    if (!proofs_from_json(blob.c_str(), loaded))
        return false;

    proofs_ = std::move(loaded);
    ESP_LOGI(TAG, "[%d] loaded %d proofs from NVS", nvs_slot_, (int)proofs_.size());
    return true;
}

bool Wallet::save_keysets()
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NS, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open failed: %s", esp_err_to_name(err));
        return false;
    }

    // Remove legacy single-blob entry if present
    char old_key[16];
    slot_key(old_key, sizeof(old_key), "keys", nvs_slot_);
    nvs_erase_key(handle, old_key);

    char cnt_key[16];
    snprintf(cnt_key, sizeof(cnt_key), "kn_%d", nvs_slot_);
    uint8_t count = (uint8_t)keysets_.size();
    if (count > MAX_KEYSETS) count = MAX_KEYSETS;

    err = nvs_set_u8(handle, cnt_key, count);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "save keyset count failed: %s", esp_err_to_name(err));
        nvs_close(handle);
        return false;
    }

    size_t total_bytes = 0;
    for (int i = 0; i < count; i++) {
        char ks_key[16];
        snprintf(ks_key, sizeof(ks_key), "k_%d_%d", nvs_slot_, i);
        std::string blob = serialize(keysets_[i]);
        err = nvs_set_blob(handle, ks_key, blob.data(), blob.size());
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "save keyset %d failed: %s", i, esp_err_to_name(err));
            nvs_close(handle);
            return false;
        }
        total_bytes += blob.size();
    }

    for (int i = count; i < MAX_KEYSETS; i++) {
        char ks_key[16];
        snprintf(ks_key, sizeof(ks_key), "k_%d_%d", nvs_slot_, i);
        nvs_erase_key(handle, ks_key);
    }

    err = nvs_commit(handle);
    nvs_close(handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "save_keysets commit failed: %s", esp_err_to_name(err));
        return false;
    }

    ESP_LOGI(TAG, "[%d] saved %d keysets (%d bytes total)",
             nvs_slot_, count, (int)total_bytes);
    return true;
}

bool Wallet::load_keysets_nvs()
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NS, NVS_READONLY, &handle);
    if (err != ESP_OK)
        return false;

    // Try individual-entry format first
    char cnt_key[16];
    snprintf(cnt_key, sizeof(cnt_key), "kn_%d", nvs_slot_);
    uint8_t count = 0;
    err = nvs_get_u8(handle, cnt_key, &count);

    if (err == ESP_OK && count > 0) {
        std::vector<Keyset> loaded;
        for (int i = 0; i < count && i < MAX_KEYSETS; i++) {
            char ks_key[16];
            snprintf(ks_key, sizeof(ks_key), "k_%d_%d", nvs_slot_, i);
            size_t required = 0;
            if (nvs_get_blob(handle, ks_key, nullptr, &required) != ESP_OK
                || required == 0)
                continue;
            std::string blob(required, '\0');
            if (nvs_get_blob(handle, ks_key, blob.data(), &required) != ESP_OK)
                continue;
            Keyset ks{};
            if (deserialize(blob.c_str(), ks))
                loaded.push_back(std::move(ks));
        }
        nvs_close(handle);
        if (!loaded.empty()) {
            keysets_ = std::move(loaded);
            ESP_LOGI(TAG, "[%d] loaded %d keysets from NVS",
                     nvs_slot_, (int)keysets_.size());
            return true;
        }
        return false;
    }

    // Fall back to legacy single-blob format
    char key[16];
    slot_key(key, sizeof(key), "keys", nvs_slot_);
    size_t required = 0;
    err = nvs_get_blob(handle, key, nullptr, &required);
    if (err != ESP_OK || required == 0) {
        nvs_close(handle);
        return false;
    }

    std::string blob(required, '\0');
    err = nvs_get_blob(handle, key, blob.data(), &required);
    nvs_close(handle);
    if (err != ESP_OK)
        return false;

    std::vector<Keyset> loaded;
    if (!keysets_from_json(blob.c_str(), loaded))
        return false;

    keysets_ = std::move(loaded);
    ESP_LOGI(TAG, "[%d] loaded %d keysets from NVS (legacy)",
             nvs_slot_, (int)keysets_.size());
    return true;
}

void Wallet::merge_keysets(const std::vector<Keyset>& fresh)
{
    for (const auto& fk : fresh) {
        bool found = false;
        for (auto& existing : keysets_) {
            if (existing.id == fk.id) {
                existing.active = fk.active;
                existing.input_fee_ppk = fk.input_fee_ppk;
                if (existing.keys.empty())
                    existing.keys = fk.keys;
                found = true;
                break;
            }
        }
        if (!found)
            keysets_.push_back(fk);
    }
}

bool Wallet::load_from_nvs()
{
    load_proofs();
    load_keysets_nvs();
    return !keysets_.empty() || !proofs_.empty();
}

const Keyset* Wallet::keyset_for_id(const std::string& id) const
{
    for (const auto& k : keysets_)
        if (k.id == id)
            return &k;
    return nullptr;
}

// -------------------------------------------------------------------------
// Keyset loading
// -------------------------------------------------------------------------

bool Wallet::load_keysets()
{
    // Step 1: GET /v1/keysets for metadata (id, unit, active, input_fee_ppk)
    std::string keysets_url = mint_url_ + "/v1/keysets";
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

    std::vector<KeysetInfo> infos;
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

    // Step 2: fetch full keys for each keyset
    std::vector<Keyset> result;
    for (const auto& info : infos) {
        std::string keys_url = mint_url_ + "/v1/keys/" + info.id;

        http_response_t kresp = {};
        err = http_get(keys_url.c_str(), &kresp);
        if (err != ESP_OK || kresp.status != 200 || !kresp.body) {
            ESP_LOGW(TAG, "GET %s failed, skipping keyset %s",
                     keys_url.c_str(), info.id.c_str());
            http_response_free(&kresp);
            continue;
        }

        cJSON* kjson = cJSON_Parse(kresp.body);
        http_response_free(&kresp);
        if (!kjson) continue;

        std::vector<Keyset> key_response;
        bool parsed = from_json_keyset_response(kjson, key_response);
        cJSON_Delete(kjson);

        if (!parsed || key_response.empty()) {
            ESP_LOGW(TAG, "failed to parse keys for keyset %s", info.id.c_str());
            continue;
        }

        Keyset ks;
        ks.id = info.id;
        ks.unit = info.unit;
        ks.active = info.active;
        ks.input_fee_ppk = info.input_fee_ppk;
        ks.keys = std::move(key_response[0].keys);

        result.push_back(std::move(ks));
    }

    if (result.empty()) {
        ESP_LOGE(TAG, "failed to load any keyset keys");
        return false;
    }

    merge_keysets(result);
    ESP_LOGI(TAG, "loaded %d keyset(s) from %s (total %d after merge)",
             (int)result.size(), mint_url_.c_str(), (int)keysets_.size());

    for (const auto& k : keysets_) {
        ESP_LOGI(TAG, "  keyset %s unit=%s active=%d keys=%d fee=%d",
                 k.id.c_str(), k.unit.c_str(), k.active,
                 (int)k.keys.size(), k.input_fee_ppk);
    }

    save_keysets();
    return true;
}

const Keyset* Wallet::active_keyset(const std::string& unit) const
{
    for (const auto& k : keysets_)
        if (k.active && k.unit == unit)
            return &k;
    return nullptr;
}

// -------------------------------------------------------------------------
// Fee calculation (NUT-02)
// -------------------------------------------------------------------------

int Wallet::calculate_fee(const std::vector<Proof>& inputs) const
{
    int sum_ppk = 0;
    for (const auto& p : inputs) {
        for (const auto& k : keysets_) {
            if (k.id == p.id) {
                sum_ppk += k.input_fee_ppk;
                break;
            }
        }
    }
    return (sum_ppk + 999) / 1000;
}

// -------------------------------------------------------------------------
// Amount splitting
// -------------------------------------------------------------------------

std::vector<int> Wallet::split_amount(int amount)
{
    std::vector<int> result;
    for (int i = 0; i < 31; i++) {
        int bit = 1 << i;
        if (amount & bit)
            result.push_back(bit);
    }
    return result;
}

// -------------------------------------------------------------------------
// Output generation (blinding)
// -------------------------------------------------------------------------

bool Wallet::generate_outputs(const std::vector<int>& amounts,
                              const std::string& keyset_id,
                              BlindingData& out)
{
    out.outputs.clear();
    out.secrets.clear();
    out.blinding_factors.clear();

    for (int amt : amounts) {
        unsigned char secret_bytes[32];
        unsigned char r_bytes[32];
        esp_fill_random(secret_bytes, 32);
        esp_fill_random(r_bytes, 32);

        char secret_hex[65];
        bytes_to_hex(secret_bytes, 32, secret_hex);
        std::string secret(secret_hex);

        char r_hex[65];
        bytes_to_hex(r_bytes, 32, r_hex);

        secp256k1_pubkey B_;
        if (!cashu_blind_message(ctx_, &B_,
                                 (const unsigned char*)secret.c_str(),
                                 secret.size(), r_bytes)) {
            ESP_LOGE(TAG, "blind_message failed");
            return false;
        }

        unsigned char B_ser[33];
        cashu_pubkey_serialize(ctx_, B_ser, &B_);
        char B_hex[67];
        bytes_to_hex(B_ser, 33, B_hex);

        out.outputs.push_back(BlindedMessage{amt, std::string(B_hex), keyset_id});
        out.secrets.push_back(secret);
        out.blinding_factors.push_back(std::string(r_hex));
    }

    return true;
}

// -------------------------------------------------------------------------
// Unblinding (NUT-00)
// -------------------------------------------------------------------------

bool Wallet::unblind_signatures(const std::vector<BlindSignature>& signatures,
                                const BlindingData& blinding,
                                const Keyset& keyset,
                                std::vector<Proof>& proofs_out)
{
    if (signatures.size() != blinding.outputs.size()) {
        ESP_LOGE(TAG, "signature count (%d) != output count (%d)",
                 (int)signatures.size(), (int)blinding.outputs.size());
        return false;
    }

    proofs_out.clear();

    for (size_t i = 0; i < signatures.size(); i++) {
        const auto& sig = signatures[i];
        uint64_t amt = (uint64_t)sig.amount;

        auto key_it = keyset.keys.find(amt);
        if (key_it == keyset.keys.end()) {
            ESP_LOGE(TAG, "no key for amount %d in keyset %s",
                     sig.amount, keyset.id.c_str());
            return false;
        }

        unsigned char C_bytes[33];
        if (!hex_to_bytes(sig.C_.c_str(), C_bytes, 33)) {
            ESP_LOGE(TAG, "invalid C_ hex");
            return false;
        }
        secp256k1_pubkey C_;
        if (!cashu_pubkey_parse(ctx_, &C_, C_bytes)) {
            ESP_LOGE(TAG, "invalid C_ pubkey");
            return false;
        }

        unsigned char K_bytes[33];
        if (!hex_to_bytes(key_it->second.c_str(), K_bytes, 33)) {
            ESP_LOGE(TAG, "invalid mint key hex");
            return false;
        }
        secp256k1_pubkey K;
        if (!cashu_pubkey_parse(ctx_, &K, K_bytes)) {
            ESP_LOGE(TAG, "invalid mint pubkey");
            return false;
        }

        unsigned char r_bytes[32];
        if (!hex_to_bytes(blinding.blinding_factors[i].c_str(), r_bytes, 32)) {
            ESP_LOGE(TAG, "invalid blinding factor hex");
            return false;
        }

        secp256k1_pubkey C;
        if (!cashu_unblind(ctx_, &C, &C_, r_bytes, &K)) {
            ESP_LOGE(TAG, "unblind failed");
            return false;
        }

        unsigned char C_ser[33];
        cashu_pubkey_serialize(ctx_, C_ser, &C);
        char C_hex[67];
        bytes_to_hex(C_ser, 33, C_hex);

        Proof proof;
        proof.id = keyset.id;
        proof.amount = sig.amount;
        proof.secret = blinding.secrets[i];
        proof.C = std::string(C_hex);
        if (sig.dleq && blinding.blinding_factors[i].size() == 64) {
            proof.dleq = DLEQ{
                sig.dleq->e,
                sig.dleq->s,
                blinding.blinding_factors[i]
            };
        }
        proofs_out.push_back(std::move(proof));
    }

    return true;
}

// -------------------------------------------------------------------------
// Swap (NUT-03)
// -------------------------------------------------------------------------

bool Wallet::swap(std::vector<Proof>& inputs, int amount,
                  std::vector<Proof>& new_proofs,
                  std::vector<Proof>& change)
{
    if (inputs.empty()) {
        ESP_LOGE(TAG, "swap: no inputs");
        return false;
    }

    const Keyset* ks = active_keyset();
    if (!ks) {
        ESP_LOGE(TAG, "swap: no active keyset");
        return false;
    }

    int fee = calculate_fee(inputs);
    int input_sum = 0;
    for (const auto& p : inputs)
        input_sum += p.amount;

    int return_amount, change_amount;
    if (amount >= 0) {
        if (input_sum < amount + fee) {
            ESP_LOGE(TAG, "swap: insufficient inputs (%d < %d + %d)",
                     input_sum, amount, fee);
            return false;
        }
        return_amount = amount;
        change_amount = input_sum - amount - fee;
    } else {
        return_amount = input_sum - fee;
        change_amount = 0;
    }

    auto send_dist = split_amount(return_amount);
    auto change_dist = split_amount(change_amount);

    std::vector<int> combined;
    combined.insert(combined.end(), send_dist.begin(), send_dist.end());
    combined.insert(combined.end(), change_dist.begin(), change_dist.end());
    std::sort(combined.begin(), combined.end());

    BlindingData blinding;
    if (!generate_outputs(combined, ks->id, blinding))
        return false;

    // Strip DLEQ from inputs before sending
    std::vector<Proof> stripped;
    for (const auto& p : inputs)
        stripped.push_back(Proof{p.id, p.amount, p.secret, p.C, std::nullopt, p.witness});

    SwapRequest req{stripped, blinding.outputs};
    std::string body = serialize(req);

    std::string url = mint_url_ + "/v1/swap";
    http_response_t resp = {};
    esp_err_t err = http_post_json(url.c_str(), body.c_str(), &resp);
    if (err != ESP_OK || !resp.body) {
        ESP_LOGE(TAG, "swap POST failed: %s", esp_err_to_name(err));
        http_response_free(&resp);
        return false;
    }

    if (resp.status != 200) {
        ESP_LOGE(TAG, "swap: mint returned %d: %.*s",
                 resp.status, (int)resp.body_len, resp.body);
        http_response_free(&resp);
        return false;
    }

    SwapResponse swap_resp;
    bool parsed = deserialize(resp.body, swap_resp);
    http_response_free(&resp);
    if (!parsed) {
        ESP_LOGE(TAG, "swap: failed to parse response");
        return false;
    }

    std::vector<Proof> all_proofs;
    if (!unblind_signatures(swap_resp.signatures, blinding, *ks, all_proofs))
        return false;

    // Separate send proofs from change proofs
    new_proofs.clear();
    change.clear();
    auto remaining = all_proofs;

    for (int n : send_dist) {
        for (auto it = remaining.begin(); it != remaining.end(); ++it) {
            if (it->amount == n) {
                new_proofs.push_back(std::move(*it));
                remaining.erase(it);
                break;
            }
        }
    }
    change = std::move(remaining);

    ESP_LOGI(TAG, "swap: %d inputs -> %d new + %d change (fee=%d)",
             (int)inputs.size(), (int)new_proofs.size(),
             (int)change.size(), fee);

    return true;
}

// -------------------------------------------------------------------------
// Receive (swap a token for new proofs)
// -------------------------------------------------------------------------

bool Wallet::receive(const Token& token, std::vector<Proof>& proofs_out)
{
    if (token.proofs.empty()) {
        ESP_LOGE(TAG, "receive: token has no proofs");
        return false;
    }

    std::vector<Proof> inputs = token.proofs;

    std::vector<Proof> new_proofs, change;
    if (!swap(inputs, -1, new_proofs, change))
        return false;

    // All proofs go to us (no specific send amount)
    proofs_out.clear();
    proofs_out.insert(proofs_out.end(), new_proofs.begin(), new_proofs.end());
    proofs_out.insert(proofs_out.end(), change.begin(), change.end());

    // Strip DLEQ/witness before storing -- only needed during verification
    for (auto& p : proofs_out) {
        p.dleq = std::nullopt;
        p.witness = std::nullopt;
    }

    for (const auto& p : proofs_out)
        proofs_.push_back(p);

    int total = 0;
    for (const auto& p : proofs_out)
        total += p.amount;

    ESP_LOGI(TAG, "received %d sat (%d proofs)", total, (int)proofs_out.size());
    save_proofs();
    return true;
}

// -------------------------------------------------------------------------
// Balance
// -------------------------------------------------------------------------

int Wallet::balance() const
{
    int sum = 0;
    for (const auto& p : proofs_)
        sum += p.amount;
    return sum;
}

// -------------------------------------------------------------------------
// Proof selection (greedy, largest first)
// -------------------------------------------------------------------------

bool Wallet::select_proofs(int amount_needed,
                           std::vector<Proof>& selected,
                           std::vector<Proof>& remaining)
{
    selected.clear();
    remaining.clear();

    std::vector<size_t> indices(proofs_.size());
    for (size_t i = 0; i < indices.size(); i++)
        indices[i] = i;

    std::sort(indices.begin(), indices.end(), [&](size_t a, size_t b) {
        return proofs_[a].amount > proofs_[b].amount;
    });

    int sum = 0;
    bool enough = false;
    for (size_t idx : indices) {
        if (!enough) {
            selected.push_back(proofs_[idx]);
            sum += proofs_[idx].amount;
            int fee = calculate_fee(selected);
            if (sum >= amount_needed + fee)
                enough = true;
        } else {
            remaining.push_back(proofs_[idx]);
        }
    }

    if (!enough) {
        ESP_LOGE(TAG, "select_proofs: insufficient balance (%d < %d)",
                 sum, amount_needed);
        selected.clear();
        remaining.clear();
        return false;
    }
    return true;
}

// -------------------------------------------------------------------------
// NUT-04: Mint tokens (bolt11)
// -------------------------------------------------------------------------

bool Wallet::request_mint_quote(int amount, MintQuote& quote_out)
{
    cJSON* body = cJSON_CreateObject();
    cJSON_AddNumberToObject(body, "amount", amount);
    cJSON_AddStringToObject(body, "unit", "sat");
    char* body_str = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);

    std::string url = mint_url_ + "/v1/mint/quote/bolt11";
    http_response_t resp = {};
    esp_err_t err = http_post_json(url.c_str(), body_str, &resp);
    cJSON_free(body_str);

    if (err != ESP_OK || !resp.body) {
        ESP_LOGE(TAG, "mint quote POST failed: %s", esp_err_to_name(err));
        http_response_free(&resp);
        return false;
    }
    if (resp.status != 200) {
        ESP_LOGE(TAG, "mint quote: mint returned %d: %.*s",
                 resp.status, (int)resp.body_len, resp.body);
        http_response_free(&resp);
        return false;
    }

    bool ok = deserialize(resp.body, quote_out);
    http_response_free(&resp);
    if (!ok) {
        ESP_LOGE(TAG, "mint quote: failed to parse response");
        return false;
    }

    ESP_LOGI(TAG, "mint quote: id=%s amount=%d state=%s",
             quote_out.quote.c_str(), quote_out.amount, quote_out.state.c_str());
    return true;
}

bool Wallet::check_mint_quote(const std::string& quote_id, MintQuote& quote_out)
{
    std::string url = mint_url_ + "/v1/mint/quote/bolt11/" + quote_id;
    http_response_t resp = {};
    esp_err_t err = http_get(url.c_str(), &resp);

    if (err != ESP_OK || !resp.body) {
        ESP_LOGD(TAG, "check mint quote GET failed: %s", esp_err_to_name(err));
        http_response_free(&resp);
        return false;
    }
    if (resp.status != 200) {
        ESP_LOGD(TAG, "check mint quote: mint returned %d", resp.status);
        http_response_free(&resp);
        return false;
    }

    bool ok = deserialize(resp.body, quote_out);
    http_response_free(&resp);
    if (!ok) {
        ESP_LOGD(TAG, "check mint quote: failed to parse response");
        return false;
    }

    ESP_LOGI(TAG, "mint quote %s: state=%s amount=%d",
             quote_id.c_str(), quote_out.state.c_str(), quote_out.amount);
    return true;
}

bool Wallet::mint_tokens(const std::string& quote_id, int amount)
{
    const Keyset* ks = active_keyset();
    if (!ks) {
        ESP_LOGE(TAG, "mint_tokens: no active keyset");
        return false;
    }

    auto amounts = split_amount(amount);
    BlindingData blinding;
    if (!generate_outputs(amounts, ks->id, blinding))
        return false;

    MintRequest req{quote_id, blinding.outputs};
    std::string body = serialize(req);

    std::string url = mint_url_ + "/v1/mint/bolt11";
    http_response_t resp = {};
    esp_err_t err = http_post_json(url.c_str(), body.c_str(), &resp);
    if (err != ESP_OK || !resp.body) {
        ESP_LOGE(TAG, "mint POST failed: %s", esp_err_to_name(err));
        http_response_free(&resp);
        return false;
    }
    if (resp.status != 200) {
        ESP_LOGE(TAG, "mint: mint returned %d: %.*s",
                 resp.status, (int)resp.body_len, resp.body);
        http_response_free(&resp);
        return false;
    }

    MintResponse mint_resp;
    bool parsed = deserialize(resp.body, mint_resp);
    http_response_free(&resp);
    if (!parsed) {
        ESP_LOGE(TAG, "mint: failed to parse response");
        return false;
    }

    std::vector<Proof> new_proofs;
    if (!unblind_signatures(mint_resp.signatures, blinding, *ks, new_proofs))
        return false;

    for (auto& p : new_proofs) {
        p.dleq = std::nullopt;
        p.witness = std::nullopt;
    }

    for (const auto& p : new_proofs)
        proofs_.push_back(p);

    int total = 0;
    for (const auto& p : new_proofs)
        total += p.amount;

    ESP_LOGI(TAG, "minted %d sat (%d proofs)", total, (int)new_proofs.size());
    save_proofs();
    return true;
}

// -------------------------------------------------------------------------
// NUT-05: Melt tokens (bolt11)
// -------------------------------------------------------------------------

bool Wallet::request_melt_quote(const std::string& bolt11, MeltQuote& quote_out)
{
    cJSON* body = cJSON_CreateObject();
    cJSON_AddStringToObject(body, "request", bolt11.c_str());
    cJSON_AddStringToObject(body, "unit", "sat");
    char* body_str = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);

    std::string url = mint_url_ + "/v1/melt/quote/bolt11";
    http_response_t resp = {};
    esp_err_t err = http_post_json(url.c_str(), body_str, &resp);
    cJSON_free(body_str);

    if (err != ESP_OK || !resp.body) {
        ESP_LOGE(TAG, "melt quote POST failed: %s", esp_err_to_name(err));
        http_response_free(&resp);
        return false;
    }
    if (resp.status != 200) {
        ESP_LOGE(TAG, "melt quote: mint returned %d: %.*s",
                 resp.status, (int)resp.body_len, resp.body);
        http_response_free(&resp);
        return false;
    }

    bool ok = deserialize(resp.body, quote_out);
    http_response_free(&resp);
    if (!ok) {
        ESP_LOGE(TAG, "melt quote: failed to parse response");
        return false;
    }

    ESP_LOGI(TAG, "melt quote: id=%s amount=%d fee_reserve=%d state=%s",
             quote_out.quote.c_str(), quote_out.amount,
             quote_out.fee_reserve, quote_out.state.c_str());
    return true;
}

bool Wallet::check_melt_quote(const std::string& quote_id, MeltQuote& quote_out)
{
    std::string url = mint_url_ + "/v1/melt/quote/bolt11/" + quote_id;
    http_response_t resp = {};
    esp_err_t err = http_get(url.c_str(), &resp);

    if (err != ESP_OK || !resp.body) {
        ESP_LOGE(TAG, "check melt quote GET failed: %s", esp_err_to_name(err));
        http_response_free(&resp);
        return false;
    }
    if (resp.status != 200) {
        ESP_LOGE(TAG, "check melt quote: mint returned %d: %.*s",
                 resp.status, (int)resp.body_len, resp.body);
        http_response_free(&resp);
        return false;
    }

    bool ok = deserialize(resp.body, quote_out);
    http_response_free(&resp);
    if (!ok) {
        ESP_LOGE(TAG, "check melt quote: failed to parse response");
        return false;
    }

    ESP_LOGI(TAG, "melt quote %s: state=%s", quote_id.c_str(), quote_out.state.c_str());
    return true;
}

bool Wallet::melt_tokens(const MeltQuote& quote, int& change_amount)
{
    change_amount = 0;

    const Keyset* ks = active_keyset();
    if (!ks) {
        ESP_LOGE(TAG, "melt: no active keyset");
        return false;
    }

    int needed = quote.amount + quote.fee_reserve;
    std::vector<Proof> selected, leftover;
    if (!select_proofs(needed, selected, leftover))
        return false;

    int input_sum = 0;
    for (const auto& p : selected)
        input_sum += p.amount;
    int input_fee = calculate_fee(selected);

    // Max possible change: if actual LN fee is 0, we get back fee_reserve + excess
    int max_change = input_sum - quote.amount - input_fee;
    if (max_change < 0) max_change = 0;

    // Generate blank outputs for change (amount=0, mint assigns values)
    int n_blank = 0;
    if (max_change > 0) {
        int tmp = max_change;
        while (tmp > 0) {
            n_blank++;
            tmp >>= 1;
        }
    }

    BlindingData change_blinding;
    if (n_blank > 0) {
        std::vector<int> blank_amounts(n_blank, 0);
        if (!generate_outputs(blank_amounts, ks->id, change_blinding))
            return false;
    }

    // Strip DLEQ from inputs
    std::vector<Proof> stripped;
    for (const auto& p : selected)
        stripped.push_back(Proof{p.id, p.amount, p.secret, p.C, std::nullopt, p.witness});

    MeltRequest req;
    req.quote = quote.quote;
    req.inputs = stripped;
    if (n_blank > 0)
        req.outputs = change_blinding.outputs;

    std::string body = serialize(req);

    std::string url = mint_url_ + "/v1/melt/bolt11";
    http_response_t resp = {};
    esp_err_t err = http_post_json_timeout(url.c_str(), body.c_str(), &resp, 120000);
    if (err != ESP_OK || !resp.body) {
        ESP_LOGE(TAG, "melt POST failed: %s", esp_err_to_name(err));
        http_response_free(&resp);
        return false;
    }
    if (resp.status != 200) {
        ESP_LOGE(TAG, "melt: mint returned %d: %.*s",
                 resp.status, (int)resp.body_len, resp.body);
        http_response_free(&resp);
        return false;
    }

    MeltQuote melt_resp;
    bool parsed = deserialize(resp.body, melt_resp);
    http_response_free(&resp);
    if (!parsed) {
        ESP_LOGE(TAG, "melt: failed to parse response");
        return false;
    }

    if (melt_resp.state != "PAID" && melt_resp.state != "PENDING") {
        ESP_LOGE(TAG, "melt: unexpected state: %s", melt_resp.state.c_str());
        return false;
    }

    // Remove spent proofs
    proofs_ = leftover;

    // Unblind change if returned. The mint may return fewer signatures
    // than blank outputs we sent (only enough to cover actual change).
    if (melt_resp.change && !melt_resp.change->empty() && n_blank > 0) {
        BlindingData truncated = change_blinding;
        size_t sig_count = melt_resp.change->size();
        if (sig_count < truncated.outputs.size()) {
            truncated.outputs.resize(sig_count);
            truncated.secrets.resize(sig_count);
            truncated.blinding_factors.resize(sig_count);
        }
        std::vector<Proof> change_proofs;
        if (unblind_signatures(*melt_resp.change, truncated, *ks, change_proofs)) {
            for (auto& p : change_proofs) {
                p.dleq = std::nullopt;
                p.witness = std::nullopt;
                change_amount += p.amount;
                proofs_.push_back(p);
            }
            ESP_LOGI(TAG, "melt: received %d sat change (%d proofs)",
                     change_amount, (int)change_proofs.size());
        } else {
            ESP_LOGW(TAG, "melt: failed to unblind change signatures");
        }
    }

    save_proofs();

    ESP_LOGI(TAG, "melt: state=%s input=%d change=%d",
             melt_resp.state.c_str(), input_sum, change_amount);
    return true;
}

// -------------------------------------------------------------------------
// Clear all proofs (for drain)
// -------------------------------------------------------------------------

bool Wallet::clear_proofs()
{
    proofs_.clear();
    return save_proofs();
}

} // namespace cashu
