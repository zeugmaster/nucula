#include "wallet.hpp"
#include "wallet_internal.hpp"
#include "keyset.hpp"

#include <algorithm>
#include <esp_log.h>

// Core wallet state: construction, keyset lookups, fee and amount math,
// balances and per-unit views, and proof selection. Persistence, identity,
// keyset sync, blinding, and the network flows live in the sibling
// wallet_*.cpp files.

namespace cashu {

Wallet::Wallet(const std::string& mint_url, secp256k1_context* ctx, int nvs_slot)
    : mint_url_(mint_url), ctx_(ctx), nvs_slot_(nvs_slot) {}

// -------------------------------------------------------------------------
// Keyset lookups
// -------------------------------------------------------------------------

const Keyset* Wallet::keyset_for_id(const std::string& id) const
{
    for (const auto& k : keysets_)
        if (k.id == id)
            return &k;
    return nullptr;
}

const Keyset* Wallet::active_keyset(const std::string& unit) const
{
    for (const auto& k : keysets_)
        if (k.active && k.unit == unit)
            return &k;
    return nullptr;
}

const Keyset* Wallet::active_keyset_for_mint(const std::string& unit) const
{
    for (const auto& k : keysets_)
        if (k.active && k.unit == unit &&
            keyset_profile(keyset_version(k.id)).can_mint)
            return &k;
    return nullptr;
}

// -------------------------------------------------------------------------
// Fee calculation (NUT-02)
// -------------------------------------------------------------------------

// NUT-02 input fees, summed per proof over each proof's keyset ppk.
// Callers guarantee single-unit inputs (proofs_unit / select_proofs):
// a ppk sum across different units would be meaningless.
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
// Balance
// -------------------------------------------------------------------------

int64_t Wallet::balance() const
{
    return proofs_sum(proofs_);
}

// -------------------------------------------------------------------------
// Per-unit views (a proof's unit lives on its keyset)
// -------------------------------------------------------------------------

const std::string* Wallet::unit_for_proof(const Proof& p) const
{
    bool amb = false;
    const Keyset* ks = resolve_keyset(keysets_, p.id, &amb);
    return (ks && !amb) ? &ks->unit : nullptr;
}

bool Wallet::proofs_unit(const std::vector<Proof>& proofs,
                         std::string& unit_out) const
{
    if (proofs.empty())
        return false;
    unit_out.clear();
    for (const auto& p : proofs) {
        const std::string* u = unit_for_proof(p);
        if (!u)
            return false;
        if (unit_out.empty())
            unit_out = *u;
        else if (unit_out != *u)
            return false;
    }
    return true;
}

int64_t Wallet::balance_for_unit(const std::string& unit) const
{
    int64_t total = 0;
    for (const auto& p : proofs_) {
        const std::string* u = unit_for_proof(p);
        if (u && *u == unit)
            total += p.amount;
    }
    return total;
}

void Wallet::collect_units(std::vector<std::string>& out) const
{
    for (const auto& p : proofs_) {
        const std::string* u = unit_for_proof(p);
        const char* name = u ? u->c_str() : "?";
        if (std::find(out.begin(), out.end(), name) == out.end())
            out.push_back(name);
    }
}

// -------------------------------------------------------------------------
// Proof selection (greedy, largest first, single unit)
// -------------------------------------------------------------------------

bool Wallet::select_proofs(int amount_needed, const std::string& unit,
                           std::vector<Proof>& selected,
                           std::vector<Proof>& remaining)
{
    selected.clear();
    remaining.clear();

    // Only same-unit proofs are candidates; everything else goes straight
    // to `remaining` (see the fund-safety contract in wallet.hpp).
    std::vector<size_t> candidates;
    for (size_t i = 0; i < proofs_.size(); i++) {
        const std::string* u = unit_for_proof(proofs_[i]);
        if (u && *u == unit)
            candidates.push_back(i);
        else
            remaining.push_back(proofs_[i]);
    }

    std::sort(candidates.begin(), candidates.end(), [&](size_t a, size_t b) {
        return proofs_[a].amount > proofs_[b].amount;
    });

    int sum = 0;
    bool enough = false;
    for (size_t idx : candidates) {
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
        ESP_LOGE(TAG, "select_proofs: insufficient %s balance (%d < %d)",
                 unit.c_str(), sum, amount_needed);
        selected.clear();
        remaining.clear();
        return false;
    }
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

bool Wallet::remove_proofs(const std::vector<Proof>& to_remove)
{
    std::vector<Proof> kept;
    kept.reserve(proofs_.size());
    for (const auto& p : proofs_) {
        bool drop = false;
        for (const auto& r : to_remove)
            if (r.secret == p.secret) { drop = true; break; }
        if (!drop)
            kept.push_back(p);
    }

    std::vector<Proof> backup = std::move(proofs_);
    proofs_ = std::move(kept);
    if (!save_proofs()) {
        proofs_ = std::move(backup);
        return false;
    }
    return true;
}

} // namespace cashu
