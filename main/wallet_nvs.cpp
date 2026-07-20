#include "wallet.hpp"
#include "wallet_internal.hpp"
#include "cashu_json.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <esp_log.h>
#include <nvs.h>

// Per-wallet-slot NVS persistence: mint URL, proof and keyset blobs, and
// the offline-receive pending-token queue.

static void slot_key(char* buf, size_t sz, const char* base, int slot)
{
    snprintf(buf, sz, "%s_%d", base, slot);
}

namespace cashu {

// -------------------------------------------------------------------------
// NVS persistence
// -------------------------------------------------------------------------

bool Wallet::save_mint_url()
{
    Nvs nvs(NVS_READWRITE);
    if (!nvs.ok())
        return false;
    char key[16];
    slot_key(key, sizeof(key), "url", nvs_slot_);
    return nvs_set_str(nvs.get(), key, mint_url_.c_str()) == ESP_OK
        && nvs.commit();
}

std::string Wallet::load_mint_url_for_slot(int slot)
{
    Nvs nvs(NVS_READONLY);
    char key[16];
    slot_key(key, sizeof(key), "url", slot);
    std::string url;
    if (!nvs.get_str(key, url))
        return "";
    return url;
}

// -------------------------------------------------------------------------
// NVS persistence (existing)
// -------------------------------------------------------------------------

bool Wallet::erase_nvs()
{
    Nvs nvs(NVS_READWRITE);
    if (!nvs.ok())
        return false;
    char key[16];
    slot_key(key, sizeof(key), "url", nvs_slot_);
    nvs_erase_key(nvs.get(), key);
    slot_key(key, sizeof(key), "proofs", nvs_slot_);
    nvs_erase_key(nvs.get(), key);
    // Legacy single-blob keyset entry
    slot_key(key, sizeof(key), "keys", nvs_slot_);
    nvs_erase_key(nvs.get(), key);
    // Individual keyset entries
    snprintf(key, sizeof(key), "kn_%d", nvs_slot_);
    nvs_erase_key(nvs.get(), key);
    for (int i = 0; i < MAX_KEYSETS; i++) {
        snprintf(key, sizeof(key), "k_%d_%d", nvs_slot_, i);
        nvs_erase_key(nvs.get(), key);
    }
    esp_err_t err = nvs_commit(nvs.get());
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "erase slot %d: commit failed: %s",
                 nvs_slot_, esp_err_to_name(err));
        return false;
    }
    ESP_LOGI(TAG, "erased NVS slot %d", nvs_slot_);
    return true;
}

bool Wallet::save_proofs()
{
    std::string blob = proofs_to_json(proofs_);
    // proofs_to_json returns "" only on allocation failure ("[]" for an
    // empty wallet). Never let that overwrite stored proofs with nothing —
    // they are bearer money.
    if (blob.empty() && !proofs_.empty()) {
        ESP_LOGE(TAG, "save_proofs: serialization failed, keeping stored proofs");
        return false;
    }

    Nvs nvs(NVS_READWRITE);
    if (!nvs.ok()) {
        ESP_LOGE(TAG, "nvs_open failed: %s", esp_err_to_name(nvs.err()));
        return false;
    }

    char key[16];
    slot_key(key, sizeof(key), "proofs", nvs_slot_);
    esp_err_t err = nvs_set_blob(nvs.get(), key, blob.data(), blob.size());
    if (err == ESP_OK)
        err = nvs_commit(nvs.get());

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
    Nvs nvs(NVS_READONLY);
    char key[16];
    slot_key(key, sizeof(key), "proofs", nvs_slot_);
    std::string blob;
    if (!nvs.get_blob(key, blob))
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
    Nvs nvs(NVS_READWRITE);
    if (!nvs.ok()) {
        ESP_LOGE(TAG, "nvs_open failed: %s", esp_err_to_name(nvs.err()));
        return false;
    }

    // Remove legacy single-blob entry if present
    char old_key[16];
    slot_key(old_key, sizeof(old_key), "keys", nvs_slot_);
    nvs_erase_key(nvs.get(), old_key);

    // Over the cap, prefer keysets our proofs reference (dropping one orphans
    // its proofs: no unit, no fee info, no keys for DLEQ), then active
    // keysets, then the rest.
    std::vector<size_t> order(keysets_.size());
    for (size_t i = 0; i < order.size(); i++)
        order[i] = i;
    if (keysets_.size() > (size_t)MAX_KEYSETS) {
        std::vector<int> rank(keysets_.size(), 2);
        for (size_t i = 0; i < keysets_.size(); i++)
            if (keysets_[i].active)
                rank[i] = 1;
        for (const auto& p : proofs_)
            for (size_t i = 0; i < keysets_.size(); i++)
                if (keysets_[i].id == p.id) { rank[i] = 0; break; }
        std::stable_sort(order.begin(), order.end(),
                         [&rank](size_t a, size_t b) { return rank[a] < rank[b]; });
        for (size_t i = MAX_KEYSETS; i < order.size(); i++) {
            const Keyset& ks = keysets_[order[i]];
            ESP_LOGE(TAG, "[%d] keyset cap: dropping %s (unit %s%s) from NVS",
                     nvs_slot_, ks.id.c_str(), ks.unit.c_str(),
                     ks.active ? ", active" : "");
        }
    }

    char cnt_key[16];
    snprintf(cnt_key, sizeof(cnt_key), "kn_%d", nvs_slot_);
    uint8_t count = (uint8_t)keysets_.size();
    if (count > MAX_KEYSETS) count = MAX_KEYSETS;

    esp_err_t err = nvs_set_u8(nvs.get(), cnt_key, count);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "save keyset count failed: %s", esp_err_to_name(err));
        return false;
    }

    size_t total_bytes = 0;
    for (int i = 0; i < count; i++) {
        char ks_key[16];
        snprintf(ks_key, sizeof(ks_key), "k_%d_%d", nvs_slot_, i);
        std::string blob = serialize(keysets_[order[i]]);
        if (blob.empty()) {
            ESP_LOGE(TAG, "save keyset %d: serialization failed", i);
            return false;
        }
        err = nvs_set_blob(nvs.get(), ks_key, blob.data(), blob.size());
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "save keyset %d failed: %s", i, esp_err_to_name(err));
            return false;
        }
        total_bytes += blob.size();
    }

    for (int i = count; i < MAX_KEYSETS; i++) {
        char ks_key[16];
        snprintf(ks_key, sizeof(ks_key), "k_%d_%d", nvs_slot_, i);
        nvs_erase_key(nvs.get(), ks_key);
    }

    err = nvs_commit(nvs.get());
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
    Nvs nvs(NVS_READONLY);
    if (!nvs.ok())
        return false;

    // Try individual-entry format first
    char cnt_key[16];
    snprintf(cnt_key, sizeof(cnt_key), "kn_%d", nvs_slot_);
    uint8_t count = 0;
    esp_err_t err = nvs_get_u8(nvs.get(), cnt_key, &count);

    if (err == ESP_OK && count > 0) {
        std::vector<Keyset> loaded;
        for (int i = 0; i < count && i < MAX_KEYSETS; i++) {
            char ks_key[16];
            snprintf(ks_key, sizeof(ks_key), "k_%d_%d", nvs_slot_, i);
            std::string blob;
            if (!nvs.get_blob(ks_key, blob))
                continue;
            Keyset ks{};
            if (deserialize(blob.c_str(), ks))
                loaded.push_back(std::move(ks));
        }
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
    std::string blob;
    if (!nvs.get_blob(key, blob))
        return false;

    std::vector<Keyset> loaded;
    if (!keysets_from_json(blob.c_str(), loaded))
        return false;

    keysets_ = std::move(loaded);
    ESP_LOGI(TAG, "[%d] loaded %d keysets from NVS (legacy)",
             nvs_slot_, (int)keysets_.size());
    return true;
}

bool Wallet::merge_keysets(const std::vector<Keyset>& fresh)
{
    bool changed = false;
    for (const auto& fk : fresh) {
        bool found = false;
        for (auto& existing : keysets_) {
            if (existing.id == fk.id) {
                if (existing.active != fk.active ||
                    existing.input_fee_ppk != fk.input_fee_ppk ||
                    existing.final_expiry != fk.final_expiry) {
                    existing.active = fk.active;
                    existing.input_fee_ppk = fk.input_fee_ppk;
                    existing.final_expiry = fk.final_expiry;
                    changed = true;
                }
                if (existing.keys.empty() && !fk.keys.empty()) {
                    existing.keys = fk.keys;
                    changed = true;
                }
                found = true;
                break;
            }
        }
        if (!found) {
            keysets_.push_back(fk);
            changed = true;
        }
    }
    return changed;
}

bool Wallet::load_from_nvs()
{
    load_proofs();
    load_keysets_nvs();
    return !keysets_.empty() || !proofs_.empty();
}

// -------------------------------------------------------------------------
// Offline-receive pending queue
// -------------------------------------------------------------------------
//
// NVS schema (namespace "wallet"):
//   pendn_<slot>     u8           current count, 0..PEND_MAX
//   pend_<slot>_<i>  string       full cashuA/cashuB token, i = 0..PEND_MAX-1
//
// PEND_MAX is bounded by the 15-char NVS key limit (single hex digit for i).

static const int PEND_MAX = 8;

static void pend_count_key(char* buf, size_t sz, int slot)
{
    snprintf(buf, sz, "pendn_%d", slot);
}

static void pend_item_key(char* buf, size_t sz, int slot, int idx)
{
    snprintf(buf, sz, "pend_%d_%x", slot, idx);
}

static int pending_count_for_slot(int slot)
{
    Nvs nvs(NVS_READONLY);
    if (!nvs.ok()) return 0;
    char k[16];
    pend_count_key(k, sizeof(k), slot);
    uint8_t n = 0;
    nvs_get_u8(nvs.get(), k, &n);
    return (int)n;
}

int Wallet::pending_count() const
{
    return pending_count_for_slot(nvs_slot_);
}

bool Wallet::stash_pending_token(const std::string& raw_token)
{
    Nvs nvs(NVS_READWRITE);
    if (!nvs.ok()) {
        ESP_LOGE(TAG, "pending: nvs_open failed");
        return false;
    }
    char ck[16];
    pend_count_key(ck, sizeof(ck), nvs_slot_);
    uint8_t n = 0;
    nvs_get_u8(nvs.get(), ck, &n);
    if (n >= PEND_MAX) {
        ESP_LOGE(TAG, "pending: queue full (%d/%d)", (int)n, PEND_MAX);
        return false;
    }
    char ik[16];
    pend_item_key(ik, sizeof(ik), nvs_slot_, (int)n);
    if (nvs_set_str(nvs.get(), ik, raw_token.c_str()) != ESP_OK) {
        ESP_LOGE(TAG, "pending: nvs_set_str failed");
        return false;
    }
    n++;
    if (nvs_set_u8(nvs.get(), ck, n) != ESP_OK)
        return false;
    esp_err_t err = nvs_commit(nvs.get());
    if (err != ESP_OK) {
        // Without a durable stash the sender's token would be silently
        // lost — report failure so the NFC exchange errors out.
        ESP_LOGE(TAG, "pending: commit failed: %s", esp_err_to_name(err));
        return false;
    }
    ESP_LOGI(TAG, "pending: stashed token %d (slot %d)", (int)n - 1, nvs_slot_);
    return true;
}

bool Wallet::list_pending_tokens(std::vector<std::string>& out)
{
    out.clear();
    Nvs nvs(NVS_READONLY);
    if (!nvs.ok())
        return false;
    char ck[16];
    pend_count_key(ck, sizeof(ck), nvs_slot_);
    uint8_t n = 0;
    nvs_get_u8(nvs.get(), ck, &n);
    for (int i = 0; i < (int)n; i++) {
        char ik[16];
        pend_item_key(ik, sizeof(ik), nvs_slot_, i);
        std::string s;
        if (!nvs.get_str(ik, s))
            continue;
        out.push_back(std::move(s));
    }
    return true;
}

bool Wallet::drain_pending_tokens(int& accepted, int& failed)
{
    accepted = 0;
    failed = 0;

    std::vector<std::string> items;
    if (!list_pending_tokens(items) || items.empty())
        return true;

    /* The pending list is rebuilt as we go. Tokens that swap successfully
     * (or fail permanently) are dropped; transient failures are retained. */
    std::vector<std::string> retained;

    for (size_t i = 0; i < items.size(); i++) {
        const std::string& raw = items[i];
        Token tok;
        if (!deserialize_token(raw.c_str(), tok)) {
            ESP_LOGW(TAG, "pending[%d]: decode failed, dropping", (int)i);
            failed++;
            continue;
        }
        if (tok.mint != mint_url_) {
            /* Stashed against the wrong wallet slot. Keep it; another
             * wallet's drain pass will pick it up. */
            ESP_LOGW(TAG, "pending[%d]: mint mismatch, retaining", (int)i);
            retained.push_back(raw);
            continue;
        }

        if (keysets_.empty() && !load_keysets()) {
            ESP_LOGW(TAG, "pending[%d]: keysets unavailable, retaining", (int)i);
            retained.push_back(raw);
            continue;
        }

        std::vector<Proof> got;
        if (receive(tok, got)) {
            ESP_LOGI(TAG, "pending[%d]: redeemed", (int)i);
            accepted++;
        } else {
            /* receive() can fail for either a transient (HTTP) or a
             * permanent (mint says spent / bad witness) reason. We can't
             * easily tell from here; conservatively keep the token unless
             * it's been retried many times. For v1: keep on first failure;
             * a future improvement can add a per-entry attempt counter. */
            ESP_LOGW(TAG, "pending[%d]: redeem failed, retaining", (int)i);
            retained.push_back(raw);
        }
    }

    /* Rewrite the pending list: erase all entries, write back retained. */
    Nvs nvs(NVS_READWRITE);
    if (!nvs.ok())
        return false;
    for (int i = 0; i < PEND_MAX; i++) {
        char ik[16];
        pend_item_key(ik, sizeof(ik), nvs_slot_, i);
        nvs_erase_key(nvs.get(), ik);
    }
    char ck[16];
    pend_count_key(ck, sizeof(ck), nvs_slot_);
    esp_err_t werr = ESP_OK;
    if (retained.empty()) {
        esp_err_t e = nvs_erase_key(nvs.get(), ck);
        if (e != ESP_OK && e != ESP_ERR_NVS_NOT_FOUND)
            werr = e;
    } else {
        for (size_t i = 0; i < retained.size(); i++) {
            char ik[16];
            pend_item_key(ik, sizeof(ik), nvs_slot_, (int)i);
            esp_err_t e = nvs_set_str(nvs.get(), ik, retained[i].c_str());
            if (e != ESP_OK)
                werr = e;
        }
        esp_err_t e = nvs_set_u8(nvs.get(), ck, (uint8_t)retained.size());
        if (e != ESP_OK)
            werr = e;
    }
    esp_err_t cerr = nvs_commit(nvs.get());
    if (werr != ESP_OK || cerr != ESP_OK) {
        ESP_LOGE(TAG, "pending: rewrite failed (%s/%s) — retained tokens may be lost",
                 esp_err_to_name(werr), esp_err_to_name(cerr));
        return false;
    }

    ESP_LOGI(TAG, "pending: drain slot %d -> %d ok, %d retained, %d dropped",
             nvs_slot_, accepted, (int)retained.size(), failed);
    return true;
}

} // namespace cashu
