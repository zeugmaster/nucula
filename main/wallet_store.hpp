#pragma once

#include "wallet.hpp"
#include "secp256k1.h"

// Owner of the wallet slots and the shared secp256k1 context. All access to
// cashu::Wallet objects goes through this module.
//
// Concurrency rule: any dereference of a cashu::Wallet* must happen inside
// one continuous wallet_store_guard scope that also obtained the pointer —
// wallets are deleted via wallet_store_remove*, and only the lock keeps a
// pointer alive. (Lock call sites are being introduced incrementally; the
// mutex is recursive, so nested guards are fine.)

static const int MAX_MINTS = 3;

// Create the mutex and restore all persisted wallet slots from NVS.
bool wallet_store_init(secp256k1_context *ctx);

secp256k1_context *wallet_store_ctx();

void wallet_store_lock();
void wallet_store_unlock();
bool wallet_store_try_lock(uint32_t timeout_ms);

struct wallet_store_guard {
    wallet_store_guard() { wallet_store_lock(); }
    ~wallet_store_guard() { wallet_store_unlock(); }
    wallet_store_guard(const wallet_store_guard &) = delete;
    wallet_store_guard &operator=(const wallet_store_guard &) = delete;
};

// nullptr when the slot is empty or out of range.
cashu::Wallet *wallet_store_get(int slot);

// Find the wallet for a mint URL (exact match), or nullptr.
cashu::Wallet *wallet_store_find(const char *mint_url);

// Find or create a wallet for the mint URL. Returns nullptr when all
// slots are taken. The new slot's URL is persisted immediately.
cashu::Wallet *wallet_store_get_or_create(const std::string &mint_url);

// Erase the slot's NVS data and delete the wallet.
bool wallet_store_remove(int slot);
void wallet_store_remove_all();

int wallet_store_count();
long long wallet_store_total_balance();
long long wallet_store_balance_for_unit(const char *unit);
// Distinct units held across all wallets, deduped, in discovery order.
// Proofs whose keyset is unknown contribute "?".
void wallet_store_collect_units(std::vector<std::string> &out);
int wallet_store_total_pending();
