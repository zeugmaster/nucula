#include "wallet.hpp"
#include "wallet_internal.hpp"
#include "keyset.hpp"

#include <esp_log.h>

// Happy-path self-tests of the wallet's money-critical pure logic —
// fee math, greedy proof selection with its remaining-completeness
// contract, per-unit views, keyset resolution, and the NUT-08 blank
// count. Runs on a throwaway Wallet with injected state: the ctor
// touches no NVS and none of the exercised paths reach network or
// flash. A member function so the fixture can fill keysets_/proofs_.

namespace cashu {

bool Wallet::run_tests()
{
    bool ok = true;
    auto expect = [&](const char* name, bool cond) {
        if (!cond) {
            ESP_LOGE(TAG, "%s FAIL", name);
            ok = false;
        } else {
            ESP_LOGI(TAG, "%s ok", name);
        }
    };

    Wallet w("https://selftest.invalid", nullptr, 0);

    Keyset sat_ks;
    sat_ks.id = "0184237e63ce3423df7db2dcedc7329cff722a12b90206db53185fc31a4ca5ed96";
    sat_ks.unit = "sat";
    sat_ks.active = true;
    sat_ks.input_fee_ppk = 1000;   // 1 sat per input
    Keyset usd_ks;
    usd_ks.id = "00c36328e7b00abe";
    usd_ks.unit = "usd";
    usd_ks.active = true;
    usd_ks.input_fee_ppk = 0;
    w.keysets_ = {sat_ks, usd_ks};

    auto proof = [](const std::string& id, int amount) {
        Proof p;
        p.id = id;
        p.amount = amount;
        p.secret = "s" + std::to_string(amount);
        p.C = "02aa";
        return p;
    };
    const std::string unknown_id(66, 'f');
    w.proofs_ = {proof(sat_ks.id, 8), proof(sat_ks.id, 4),
                 proof(sat_ks.id, 2), proof(sat_ks.id, 1),
                 proof(usd_ks.id, 16), proof(unknown_id, 32)};

    { // NUT-02 fee: ppk summed per input, ceil to whole units
        std::vector<Proof> two = {w.proofs_[0], w.proofs_[1]};
        std::vector<Proof> none;
        expect("calculate_fee",
               w.calculate_fee(two) == 2 &&
               w.calculate_fee({w.proofs_[4]}) == 0 &&
               w.calculate_fee(none) == 0);
    }
    { // per-unit views: unknown keysets excluded, mixed units rejected
        std::string u;
        std::vector<Proof> sat_only = {w.proofs_[0], w.proofs_[1]};
        std::vector<Proof> mixed = {w.proofs_[0], w.proofs_[4]};
        expect("unit views",
               w.unit_for_proof(w.proofs_[0]) &&
               *w.unit_for_proof(w.proofs_[0]) == "sat" &&
               w.unit_for_proof(w.proofs_[5]) == nullptr &&
               w.proofs_unit(sat_only, u) && u == "sat" &&
               !w.proofs_unit(mixed, u) &&
               w.balance_for_unit("sat") == 15 &&
               w.balance_for_unit("usd") == 16);
    }
    { // greedy selection: largest-first until amount+fee covered; every
      // unselected proof (other units, unknown keysets) must land in
      // `remaining` — the fund-safety contract from wallet.hpp
        std::vector<Proof> sel, rem;
        bool got = w.select_proofs(10, "sat", sel, rem);
        expect("select_proofs happy",
               got && sel.size() == 2 &&
               sel[0].amount == 8 && sel[1].amount == 4 &&
               sel.size() + rem.size() == w.proofs_.size());
        std::vector<Proof> sel2, rem2;
        expect("select_proofs insufficient",
               !w.select_proofs(100, "sat", sel2, rem2) &&
               sel2.empty() && rem2.empty());
    }
    { // short-form (8-byte) keyset id resolution + ambiguity detection
        bool amb = false;
        const Keyset* hit = resolve_keyset(w.keysets_,
                                           sat_ks.id.substr(0, 16), &amb);
        std::vector<Keyset> twins = {sat_ks, sat_ks};
        twins[1].id[65] = '0';   // same 16-hex prefix, different id
        bool amb2 = false;
        const Keyset* dup = resolve_keyset(twins, sat_ks.id.substr(0, 16),
                                           &amb2);
        expect("resolve_keyset",
               hit == &w.keysets_[0] && !amb && !dup && amb2);
    }
    { // NUT-08: blanks cover any change up to max_change
        expect("blank_output_count",
               blank_output_count(0) == 0 && blank_output_count(1) == 1 &&
               blank_output_count(2) == 2 && blank_output_count(3) == 2 &&
               blank_output_count(4) == 3 && blank_output_count(976) == 10);
    }
    return ok;
}

} // namespace cashu
