#pragma once

// Shared internals of the cashu::Wallet implementation, which is split
// across the wallet*.cpp translation units (core, nvs, identity, keysets,
// blind, flows). Not for callers of wallet.hpp.

// One log tag for the whole family, so the split is invisible in logs.
#define TAG "wallet"

namespace cashu {

// NVS namespace holding every wallet key (per-slot blobs, global seed,
// counters, default unit, pending queue).
inline constexpr const char* NVS_NS = "wallet";

// Cap on keysets persisted per wallet slot; save_keysets ranks and evicts
// beyond it, load_keysets caps what the mint advertises.
inline constexpr int MAX_KEYSETS = 10;

} // namespace cashu
