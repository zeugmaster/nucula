#include "commands.h"
#include "console.h"
#include "wallet.hpp"
#include "wallet_store.hpp"
#include "unit.hpp"

#include <cstdlib>
#include <cstring>

bool parse_cmd_opts(const char *p, CmdOpts &out)
{
    while (p && *p) {
        while (*p == ' ') p++;
        if (!*p) break;
        const char *end = strchr(p, ' ');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        std::string tok(p, len);
        if (tok.rfind("u=", 0) == 0) {
            out.unit = cashu::normalize_unit(tok.substr(2));
            if (!cashu::unit_token_valid(out.unit.c_str())) {
                console_printf("error: bad unit '%s'\r\n", tok.c_str() + 2);
                return false;
            }
        } else if (tok.rfind("m=", 0) == 0) {
            out.method = tok.substr(2);
            if (!cashu::unit_token_valid(out.method.c_str())) {
                console_printf("error: bad method '%s'\r\n", tok.c_str() + 2);
                return false;
            }
        } else if (tok.rfind("a=", 0) == 0) {
            out.amount = atoi(tok.c_str() + 2);
            if (out.amount <= 0) {
                console_printf("error: bad amount '%s'\r\n", tok.c_str() + 2);
                return false;
            }
        } else if (tok.rfind("w=", 0) == 0) {
            out.idx = tok.substr(2);
        } else if (tok.find_first_not_of("0123456789") == std::string::npos) {
            out.idx = tok;   // bare integer = mint index (legacy syntax)
        } else {
            console_printf("error: unknown option '%s'\r\n", tok.c_str());
            return false;
        }
        p = end;
    }
    return true;
}

// Print one formatted line per unit held by the wallet, prefix-indented.
// Returns true when any proofs have an unknown keyset ("?" unit).
bool print_unit_balances(cashu::Wallet *w, const char *prefix,
                                const char *label)
{
    bool unknown = false;
    std::vector<std::string> units;
    w->collect_units(units);
    for (const auto &u : units) {
        if (u == "?") {
            unknown = true;
            continue;
        }
        char amt[48];
        cashu::format_amount(amt, sizeof(amt), w->balance_for_unit(u), u.c_str());
        console_printf("%s%s%s\r\n", prefix, label, amt);
    }
    return unknown;
}

// Caller must hold the wallet_store guard (all cmd_* callers do).
cashu::Wallet *resolve_wallet(const char *idx_str)
{
    int count = wallet_store_count();
    if (count == 0) {
        console_print("error: no mints configured\r\n");
        return nullptr;
    }
    if (idx_str && *idx_str) {
        int slot = atoi(idx_str);
        if (slot >= 0 && slot < MAX_MINTS && wallet_store_get(slot))
            return wallet_store_get(slot);
        console_print("error: invalid mint index\r\n");
        return nullptr;
    }
    if (count == 1) {
        for (int i = 0; i < MAX_MINTS; i++)
            if (wallet_store_get(i)) return wallet_store_get(i);
    }
    console_print("error: multiple mints, specify index\r\n");
    for (int i = 0; i < MAX_MINTS; i++) {
        if (!wallet_store_get(i)) continue;
        console_printf("  [%d] %s\r\n", i, wallet_store_get(i)->mint_url().c_str());
    }
    return nullptr;
}

// Ensure the wallet has keysets and — when require_active — an active
// keyset for `unit`, refreshing from the mint once. Prints its own
// console errors. cmd_receive passes require_active=false: the swap
// resolves the keyset itself and any actively-backed unit is fine.
bool ensure_active_keyset(cashu::Wallet *w, const std::string &unit,
                          bool require_active)
{
    if (!w->keysets().empty() && w->active_keyset(unit))
        return true;
    console_print("loading keysets...\r\n");
    if (!w->load_keysets()) {
        console_print("error: failed to load keysets\r\n");
        return false;
    }
    if (require_active && !w->active_keyset(unit)) {
        console_printf("error: mint has no active %s keyset\r\n", unit.c_str());
        return false;
    }
    return true;
}

// "First word is the payload, the rest is CmdOpts" — shared by claim
// (quote id) and melt (payment request).
bool split_first_token(const char *arg, std::string &first, CmdOpts &opts)
{
    const char *space = strchr(arg, ' ');
    if (space) {
        first = std::string(arg, space - arg);
        if (!parse_cmd_opts(space, opts))
            return false;
    } else {
        first = arg;
    }
    return true;
}

// The standard "error: <what>" line plus, when the wallet captured a
// decoded mint error on this flow, the mint's own explanation. Transport
// failures (all-zero MintError) print exactly the plain line.
void print_flow_error(const cashu::Wallet *w, const char *what)
{
    console_printf("error: %s\r\n", what);
    if (!w)
        return;
    const cashu::Wallet::MintError &e = w->last_mint_error();
    if (e.status == 0 && e.code == 0 && e.detail.empty())
        return;
    if (!e.detail.empty())
        console_printf("  mint said: %s (code %d, http %d)\r\n",
                       e.detail.c_str(), e.code, e.status);
    else
        console_printf("  mint returned http %d (code %d)\r\n",
                       e.status, e.code);
}
