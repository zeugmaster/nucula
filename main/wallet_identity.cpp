#include "wallet.hpp"
#include "wallet_internal.hpp"
#include "crypto.h"
#include "hex.h"
#include "unit.hpp"

#include <cstdio>
#include <cstring>
#include <esp_log.h>
#include <esp_random.h>
#include <nvs.h>

// Process-global identity and settings shared by every wallet slot: the
// NUT-13 seed, the NUT-11 P2PK keypair, per-keyset counters, and the
// default display unit. All storage is Wallet statics.

// Static seed storage
unsigned char cashu::Wallet::s_seed[64] = {};
bool cashu::Wallet::s_seed_loaded = false;

unsigned char cashu::Wallet::s_p2pk_priv[32]      = {};
char          cashu::Wallet::s_p2pk_pub_hex[67]   = {};
bool          cashu::Wallet::s_p2pk_loaded        = false;

namespace cashu {

// -------------------------------------------------------------------------
// NUT-13: Seed management
// -------------------------------------------------------------------------

bool Wallet::load_seed()
{
    nvs_handle_t handle;
    if (nvs_open(NVS_NS, NVS_READONLY, &handle) != ESP_OK)
        return false;
    size_t len = 64;
    esp_err_t err = nvs_get_blob(handle, "seed", s_seed, &len);
    nvs_close(handle);
    if (err == ESP_OK && len == 64) {
        s_seed_loaded = true;
        ESP_LOGI(TAG, "deterministic seed loaded");
        return true;
    }
    s_seed_loaded = false;
    return false;
}

bool Wallet::save_seed(const unsigned char seed[64], const char* mnemonic)
{
    nvs_handle_t handle;
    if (nvs_open(NVS_NS, NVS_READWRITE, &handle) != ESP_OK)
        return false;

    esp_err_t err = nvs_set_blob(handle, "seed", seed, 64);
    if (err == ESP_OK && mnemonic)
        err = nvs_set_str(handle, "mnemonic", mnemonic);
    if (err == ESP_OK)
        err = nvs_commit(handle);
    nvs_close(handle);

    if (err == ESP_OK) {
        memcpy(s_seed, seed, 64);
        s_seed_loaded = true;
        ESP_LOGI(TAG, "seed saved to NVS");
        return true;
    }
    ESP_LOGE(TAG, "save_seed failed: %s", esp_err_to_name(err));
    return false;
}

bool Wallet::seed_exists()
{
    if (s_seed_loaded)
        return true;
    nvs_handle_t handle;
    if (nvs_open(NVS_NS, NVS_READONLY, &handle) != ESP_OK)
        return false;
    size_t len = 0;
    esp_err_t err = nvs_get_blob(handle, "seed", NULL, &len);
    nvs_close(handle);
    return err == ESP_OK && len == 64;
}

bool Wallet::load_mnemonic(std::string& out)
{
    nvs_handle_t handle;
    if (nvs_open(NVS_NS, NVS_READONLY, &handle) != ESP_OK)
        return false;
    size_t len = 0;
    if (nvs_get_str(handle, "mnemonic", NULL, &len) != ESP_OK || len == 0) {
        nvs_close(handle);
        return false;
    }
    out.resize(len - 1);
    esp_err_t err = nvs_get_str(handle, "mnemonic", out.data(), &len);
    nvs_close(handle);
    return err == ESP_OK;
}

bool Wallet::erase_seed()
{
    nvs_handle_t handle;
    if (nvs_open(NVS_NS, NVS_READWRITE, &handle) != ESP_OK)
        return false;
    esp_err_t e1 = nvs_erase_key(handle, "seed");
    esp_err_t e2 = nvs_erase_key(handle, "mnemonic");
    esp_err_t ec = nvs_commit(handle);
    nvs_close(handle);
    memset(s_seed, 0, 64);
    s_seed_loaded = false;
    /* P2PK key is independent of the seed and intentionally retained. */
    bool ok = (e1 == ESP_OK || e1 == ESP_ERR_NVS_NOT_FOUND) &&
              (e2 == ESP_OK || e2 == ESP_ERR_NVS_NOT_FOUND) &&
              ec == ESP_OK;
    if (!ok) {
        ESP_LOGE(TAG, "seed erase incomplete — it may still be in flash");
        return false;
    }
    ESP_LOGI(TAG, "seed erased");
    return true;
}

// -------------------------------------------------------------------------
// NUT-11: P2PK identity
//
// For now the locking key is independent of the BIP-39 seed: a 32-byte
// scalar generated once with esp_fill_random, persisted in NVS under
// "p2pk_priv", and reused across transactions. This is privacy-naive (one
// observer-linkable pubkey) but lets the offline-receive flow function with
// a stable identity that survives reboots. Per-receive nonce derivation is
// a follow-up.
// -------------------------------------------------------------------------

bool Wallet::ensure_p2pk_keypair(secp256k1_context* ctx)
{
    if (s_p2pk_loaded)
        return true;

    nvs_handle_t h;
    bool have_priv = false;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) == ESP_OK) {
        size_t sz = sizeof(s_p2pk_priv);
        if (nvs_get_blob(h, "p2pk_priv", s_p2pk_priv, &sz) == ESP_OK && sz == 32) {
            have_priv = true;
        }
        if (!have_priv) {
            /* Generate fresh: random 32 bytes that satisfy
             * secp256k1_ec_seckey_verify (in [1, n-1]). Retry on the
             * vanishingly unlikely failure. */
            for (int tries = 0; tries < 8 && !have_priv; tries++) {
                esp_fill_random(s_p2pk_priv, 32);
                if (secp256k1_ec_seckey_verify(ctx, s_p2pk_priv))
                    have_priv = true;
            }
            if (have_priv) {
                if (nvs_set_blob(h, "p2pk_priv", s_p2pk_priv, 32) != ESP_OK ||
                    nvs_commit(h) != ESP_OK) {
                    ESP_LOGE(TAG, "p2pk: nvs persist failed");
                    have_priv = false;
                } else {
                    ESP_LOGI(TAG, "p2pk: generated and persisted new keypair");
                }
            }
        }
        nvs_close(h);
    }

    if (!have_priv) {
        ESP_LOGE(TAG, "p2pk: could not load or generate keypair");
        return false;
    }

    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_create(ctx, &pk, s_p2pk_priv)) {
        ESP_LOGE(TAG, "p2pk: pubkey_create failed");
        return false;
    }
    unsigned char pub33[33];
    size_t out_len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, pub33, &out_len,
                                       &pk, SECP256K1_EC_COMPRESSED)) {
        ESP_LOGE(TAG, "p2pk: pubkey serialize failed");
        return false;
    }

    bytes_to_hex(pub33, 33, s_p2pk_pub_hex);
    s_p2pk_loaded = true;
    ESP_LOGI(TAG, "p2pk pubkey: %s", s_p2pk_pub_hex);
    return true;
}

const char* Wallet::p2pk_pubkey_hex()
{
    return s_p2pk_loaded ? s_p2pk_pub_hex : "";
}

const unsigned char* Wallet::p2pk_privkey()
{
    return s_p2pk_loaded ? s_p2pk_priv : nullptr;
}

// -------------------------------------------------------------------------
// NUT-13: Per-keyset counter management
// -------------------------------------------------------------------------

static void counter_key(char* buf, size_t sz, const std::string& keyset_id)
{
    /* NVS key max 15 chars: "c_" + first 13 hex chars of keyset_id */
    snprintf(buf, sz, "c_%.13s", keyset_id.c_str());
}

uint32_t Wallet::load_counter(const std::string& keyset_id)
{
    nvs_handle_t handle;
    if (nvs_open(NVS_NS, NVS_READONLY, &handle) != ESP_OK)
        return 0;
    char key[16];
    counter_key(key, sizeof(key), keyset_id);
    uint32_t val = 0;
    nvs_get_u32(handle, key, &val);
    nvs_close(handle);
    return val;
}

bool Wallet::save_counter(const std::string& keyset_id, uint32_t counter)
{
    nvs_handle_t handle;
    if (nvs_open(NVS_NS, NVS_READWRITE, &handle) != ESP_OK)
        return false;
    char key[16];
    counter_key(key, sizeof(key), keyset_id);
    esp_err_t err = nvs_set_u32(handle, key, counter);
    if (err == ESP_OK)
        err = nvs_commit(handle);
    nvs_close(handle);
    return err == ESP_OK;
}

// -------------------------------------------------------------------------
// Default unit (global UX setting)
// -------------------------------------------------------------------------

std::string Wallet::s_default_unit;
bool        Wallet::s_default_unit_loaded = false;

std::string Wallet::default_unit()
{
    if (!s_default_unit_loaded) {
        s_default_unit = "sat";
        nvs_handle_t handle;
        if (nvs_open(NVS_NS, NVS_READONLY, &handle) == ESP_OK) {
            char buf[32] = {};
            size_t len = sizeof(buf);
            if (nvs_get_str(handle, "def_unit", buf, &len) == ESP_OK && buf[0])
                s_default_unit = buf;
            nvs_close(handle);
        }
        s_default_unit_loaded = true;
    }
    return s_default_unit;
}

bool Wallet::set_default_unit(const std::string& unit)
{
    if (unit.empty() || unit.size() > 31)
        return false;
    nvs_handle_t handle;
    if (nvs_open(NVS_NS, NVS_READWRITE, &handle) != ESP_OK)
        return false;
    esp_err_t err = nvs_set_str(handle, "def_unit", unit.c_str());
    if (err == ESP_OK)
        err = nvs_commit(handle);
    nvs_close(handle);
    if (err != ESP_OK)
        return false;
    s_default_unit = unit;
    s_default_unit_loaded = true;
    return true;
}

} // namespace cashu
