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
        nucula_console_write("error: no mints configured\r\n");
        return nullptr;
    }
    if (idx_str && *idx_str) {
        int slot = atoi(idx_str);
        if (slot >= 0 && slot < MAX_MINTS && wallet_store_get(slot))
            return wallet_store_get(slot);
        nucula_console_write("error: invalid mint index\r\n");
        return nullptr;
    }
    if (count == 1) {
        for (int i = 0; i < MAX_MINTS; i++)
            if (wallet_store_get(i)) return wallet_store_get(i);
    }
    nucula_console_write("error: multiple mints, specify index\r\n");
    for (int i = 0; i < MAX_MINTS; i++) {
        if (!wallet_store_get(i)) continue;
        console_printf("  [%d] %s\r\n", i, wallet_store_get(i)->mint_url().c_str());
    }
    return nullptr;
}
