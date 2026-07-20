#pragma once

#include <string>

// Console command handlers, split by domain: commands_wallet.cpp (money),
// commands_seed.cpp (NUT-13 seed lifecycle), commands_system.cpp
// (nfc/keypad/diagnostics). Each *_register() adds its commands in the
// order they appear in `help`; app_main calls all three.

namespace cashu { class Wallet; }

// Trailing options shared by the money commands: "u=<unit> m=<method>
// a=<amount> w=<mint idx>" in any order. A bare integer token is still
// accepted as the mint index (the old positional syntax).
struct CmdOpts {
    std::string unit;     // empty = Wallet::default_unit()
    std::string method;   // empty = bolt11
    int amount = -1;      // a=, only meaningful where documented
    std::string idx;      // empty = auto-resolve
};

// Shared helpers (commands_common.cpp). All print their own console
// errors, so callers just bail on false/nullptr.
bool parse_cmd_opts(const char *p, CmdOpts &out);
cashu::Wallet *resolve_wallet(const char *idx_str);
bool print_unit_balances(cashu::Wallet *w, const char *prefix,
                         const char *label);
bool ensure_active_keyset(cashu::Wallet *w, const std::string &unit,
                          bool require_active);
bool split_first_token(const char *arg, std::string &first, CmdOpts &opts);
void print_flow_error(const cashu::Wallet *w, const char *what);

void commands_wallet_register(void);
void commands_seed_register(void);
void commands_system_register(void);
