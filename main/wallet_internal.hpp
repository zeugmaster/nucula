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

// NUT-08: blank change outputs needed to cover any change up to
// max_change, i.e. ceil(log2(max_change + 1)). Defined in
// wallet_flows.cpp; pure, exposed here for the self-tests.
int blank_output_count(int max_change);

} // namespace cashu
