#include "wallet.hpp"
#include "wallet_internal.hpp"
#include "crypto.h"
#include "keyset.hpp"
#include "hex.h"

#include <cstdio>
#include <cstring>
#include <esp_log.h>
#include <esp_random.h>

namespace cashu {

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

    const cashu_suite_t* suite = suite_for_id(keyset_id);
    if (!suite) {
        ESP_LOGE(TAG, "generate_outputs: no crypto suite for keyset %s",
                 keyset_id.c_str());
        return false;
    }

    uint32_t counter = 0;
    bool deterministic = s_seed_loaded;
    if (deterministic) {
        counter = load_counter(keyset_id);
        ESP_LOGI(TAG, "deterministic outputs: keyset=%.16s... counter=%lu n=%d",
                 keyset_id.c_str(), (unsigned long)counter, (int)amounts.size());
    }

    out.outputs.reserve(amounts.size());
    out.secrets.reserve(amounts.size());
    out.blinding_factors.reserve(amounts.size());

    for (size_t i = 0; i < amounts.size(); i++) {
        int amt = amounts[i];
        unsigned char secret_bytes[32];
        unsigned char r_bytes[32];

        if (deterministic) {
            if (!suite->derive_secret(s_seed, 64, keyset_id.c_str(),
                                      counter + (uint32_t)i, secret_bytes)) {
                ESP_LOGE(TAG, "derive_secret failed at counter %lu",
                         (unsigned long)(counter + i));
                return false;
            }
            if (!suite->derive_r(s_seed, 64, keyset_id.c_str(),
                                 counter + (uint32_t)i, r_bytes)) {
                ESP_LOGE(TAG, "derive_r failed at counter %lu",
                         (unsigned long)(counter + i));
                return false;
            }
        } else {
            esp_fill_random(secret_bytes, 32);
            esp_fill_random(r_bytes, 32);
        }

        char secret_hex[65];
        bytes_to_hex(secret_bytes, 32, secret_hex);

        char r_hex[65];
        bytes_to_hex(r_bytes, 32, r_hex);

        unsigned char B_ser[CASHU_MAX_POINT_LEN];
        size_t B_len = sizeof(B_ser);
        if (!suite->blind((void*)ctx_,
                          (const unsigned char*)secret_hex, 64,
                          r_bytes, 32, B_ser, &B_len)) {
            ESP_LOGE(TAG, "blind_message failed");
            return false;
        }
        char B_hex[CASHU_MAX_POINT_LEN * 2 + 1];
        bytes_to_hex(B_ser, B_len, B_hex);

        out.outputs.push_back(BlindedMessage{amt, std::string(B_hex, B_len * 2), keyset_id});
        out.secrets.emplace_back(secret_hex, 64);
        out.blinding_factors.emplace_back(r_hex, 64);
    }

    if (deterministic) {
        save_counter(keyset_id, counter + (uint32_t)amounts.size());
    }

    return true;
}

// -------------------------------------------------------------------------
// Unblinding (NUT-00) + NUT-12 DLEQ verification
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
    proofs_out.reserve(signatures.size());

    const cashu_suite_t* suite = suite_for_id(keyset.id);
    if (!suite) {
        ESP_LOGE(TAG, "unblind: no crypto suite for keyset %s", keyset.id.c_str());
        return false;
    }
    const size_t plen = suite->pubkey_len;
    if (plen > CASHU_MAX_POINT_LEN) {
        ESP_LOGE(TAG, "unblind: suite pubkey_len %d too large", (int)plen);
        return false;
    }

    for (size_t i = 0; i < signatures.size(); i++) {
        const auto& sig = signatures[i];
        uint64_t amt = (uint64_t)sig.amount;

        auto key_it = keyset.keys.find(amt);
        if (key_it == keyset.keys.end()) {
            ESP_LOGE(TAG, "no key for amount %llu in keyset %s",
                     (unsigned long long)amt, keyset.id.c_str());
            return false;
        }
        const std::string& K_hex = key_it->second;
        unsigned char K_bytes[CASHU_MAX_POINT_LEN];
        if (K_hex.size() != plen * 2 || !hex_to_bytes(K_hex.c_str(), K_bytes, plen)) {
            ESP_LOGE(TAG, "invalid mint key hex");
            return false;
        }

        unsigned char C__bytes[CASHU_MAX_POINT_LEN];
        if (sig.C_.size() != plen * 2 || !hex_to_bytes(sig.C_.c_str(), C__bytes, plen)) {
            ESP_LOGE(TAG, "invalid C_ hex");
            return false;
        }

        unsigned char r_bytes[32];
        if (!hex_to_bytes(blinding.blinding_factors[i].c_str(), r_bytes, 32)) {
            ESP_LOGE(TAG, "invalid blinding factor hex");
            return false;
        }

        unsigned char C_ser[CASHU_MAX_POINT_LEN];
        size_t C_len = sizeof(C_ser);
        bool unblinded = false;

        // NUT-12: verify the DLEQ proof on the BlindSignature before we trust C_.
        if (sig.dleq) {
            if (suite->has_dleq) {
                unsigned char e_b[32], s_b[32];
                if (!hex_to_bytes(sig.dleq->e.c_str(), e_b, 32) ||
                    !hex_to_bytes(sig.dleq->s.c_str(), s_b, 32)) {
                    ESP_LOGE(TAG, "dleq: invalid e/s hex on sig[%d]", (int)i);
                    return false;
                }
                unsigned char B__bytes[CASHU_MAX_POINT_LEN];
                if (blinding.outputs[i].B_.size() != plen * 2 ||
                    !hex_to_bytes(blinding.outputs[i].B_.c_str(), B__bytes, plen)) {
                    ESP_LOGE(TAG, "dleq: invalid B_ hex on sig[%d]", (int)i);
                    return false;
                }
                if (suite->verify_dleq_and_unblind) {
                    if (!suite->verify_dleq_and_unblind((void*)ctx_, K_bytes, plen,
                                                        B__bytes, plen, C__bytes, plen,
                                                        e_b, s_b, r_bytes, 32,
                                                        C_ser, &C_len)) {
                        ESP_LOGE(TAG, "dleq/unblind failed for sig[%d] amount=%d",
                                 (int)i, sig.amount);
                        return false;
                    }
                    unblinded = true;
                } else if (!suite->verify_dleq((void*)ctx_, K_bytes, plen, B__bytes, plen,
                                               C__bytes, plen, e_b, s_b)) {
                    ESP_LOGE(TAG, "dleq verification failed for sig[%d] amount=%d",
                             (int)i, sig.amount);
                    return false;
                }
            }
        } else {
#if CASHU_REQUIRE_DLEQ_FROM_MINT
            ESP_LOGE(TAG, "mint omitted DLEQ on sig[%d] amount=%d (rejecting)",
                     (int)i, sig.amount);
            return false;
#else
            ESP_LOGW(TAG, "mint omitted DLEQ on sig[%d] amount=%d",
                     (int)i, sig.amount);
#endif
        }

        if (!unblinded && !suite->unblind((void*)ctx_, C__bytes, plen, r_bytes, 32,
                                          K_bytes, plen, C_ser, &C_len)) {
            ESP_LOGE(TAG, "unblind failed");
            return false;
        }
        char C_hex[CASHU_MAX_POINT_LEN * 2 + 1];
        bytes_to_hex(C_ser, C_len, C_hex);

        Proof proof;
        proof.id = keyset.id;
        proof.amount = sig.amount;
        proof.secret = blinding.secrets[i];
        proof.C.assign(C_hex, C_len * 2);
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

} // namespace cashu
