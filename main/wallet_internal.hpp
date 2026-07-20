#pragma once

#include <nvs.h>
#include <string>

// Shared internals of the cashu::Wallet implementation, which is split
// across the wallet*.cpp translation units (core, nvs, identity, keysets,
// blind, flows). Not for callers of wallet.hpp.

// One log tag for the whole family, so the split is invisible in logs.
#define TAG "wallet"

namespace cashu {

// NVS namespace holding every wallet key (per-slot blobs, global seed,
// counters, default unit, pending queue).
inline constexpr const char* NVS_NS = "wallet";

// RAII over one nvs_open of NVS_NS: closes on scope exit, so no call site
// needs the close-before-every-return dance. When the open fails ok() is
// false and get()/commit() must not be used. Raw nvs_get/set_* calls go
// through get(); the two probe-length-then-fetch shapes are wrapped.
class Nvs {
public:
    explicit Nvs(nvs_open_mode_t mode)
    {
        err_ = nvs_open(NVS_NS, mode, &h_);
        ok_ = err_ == ESP_OK;
    }
    ~Nvs()
    {
        if (ok_) nvs_close(h_);
    }
    Nvs(const Nvs&) = delete;
    Nvs& operator=(const Nvs&) = delete;

    bool ok() const { return ok_; }
    esp_err_t err() const { return err_; }   // the nvs_open result
    nvs_handle_t get() const { return h_; }
    bool commit() { return ok_ && nvs_commit(h_) == ESP_OK; }

    // False when the key is absent, empty, or the read fails. `out` gets
    // the string without its stored NUL.
    bool get_str(const char* key, std::string& out)
    {
        size_t len = 0;
        if (!ok_ || nvs_get_str(h_, key, nullptr, &len) != ESP_OK || len == 0)
            return false;
        out.assign(len, '\0');
        if (nvs_get_str(h_, key, out.data(), &len) != ESP_OK)
            return false;
        if (!out.empty() && out.back() == '\0')
            out.pop_back();
        return true;
    }

    bool get_blob(const char* key, std::string& out)
    {
        size_t required = 0;
        if (!ok_ || nvs_get_blob(h_, key, nullptr, &required) != ESP_OK
            || required == 0)
            return false;
        out.assign(required, '\0');
        return nvs_get_blob(h_, key, out.data(), &required) == ESP_OK;
    }

private:
    nvs_handle_t h_ = 0;
    esp_err_t err_ = ESP_FAIL;
    bool ok_ = false;
};

// Cap on keysets persisted per wallet slot; save_keysets ranks and evicts
// beyond it, load_keysets caps what the mint advertises.
inline constexpr int MAX_KEYSETS = 10;

// NUT-08: blank change outputs needed to cover any change up to
// max_change, i.e. ceil(log2(max_change + 1)). Defined in
// wallet_flows.cpp; pure, exposed here for the self-tests.
int blank_output_count(int max_change);

} // namespace cashu
