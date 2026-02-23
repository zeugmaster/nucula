#include "wallet.hpp"
#include "cashu_json.hpp"
#include "crypto.h"
#include "hex.h"
#include "http.h"

#include <algorithm>
#include <cstring>
#include <esp_log.h>
#include <esp_random.h>

#define TAG "wallet"

namespace cashu {

Wallet::Wallet(const std::string& mint_url, secp256k1_context* ctx)
    : mint_url_(mint_url), ctx_(ctx) {}

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

    // Step 2: for each keyset, GET /v1/keys/{id} to fetch the actual public keys
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

        // Merge: take the keys from /v1/keys/{id}, metadata from /v1/keysets
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

    keysets_ = std::move(result);
    ESP_LOGI(TAG, "loaded %d keyset(s) from %s",
             (int)keysets_.size(), mint_url_.c_str());

    for (const auto& k : keysets_) {
        ESP_LOGI(TAG, "  keyset %s unit=%s active=%d keys=%d fee=%d",
                 k.id.c_str(), k.unit.c_str(), k.active,
                 (int)k.keys.size(), k.input_fee_ppk);
    }

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

    // Store in wallet
    for (const auto& p : proofs_out)
        proofs_.push_back(p);

    int total = 0;
    for (const auto& p : proofs_out)
        total += p.amount;

    ESP_LOGI(TAG, "received %d sat (%d proofs)", total, (int)proofs_out.size());
    return true;
}

} // namespace cashu
