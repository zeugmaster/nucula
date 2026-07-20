#include "wallet.hpp"
#include "wallet_internal.hpp"
#include "cashu_json.hpp"
#include "crypto.h"
#include "keyset.hpp"
#include "hex.h"
#include "http.h"
#include "nut10.hpp"
#include "unit.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <esp_log.h>
#include <cJSON.h>

// The network protocol flows: NUT-06 info, NUT-03 swap, receive,
// NUT-04 mint, and NUT-05 melt, all against this wallet's mint.

namespace cashu {

// -------------------------------------------------------------------------
// NUT-06: mint info (RAM cache, never persisted)
// -------------------------------------------------------------------------

bool Wallet::load_mint_info()
{
    std::string url = mint_url_ + "/v1/info";
    http_response_t resp = {};
    esp_err_t err = http_get(url.c_str(), &resp);
    if (err != ESP_OK || !resp.body) {
        ESP_LOGW(TAG, "mint info GET failed: %s", esp_err_to_name(err));
        http_response_free(&resp);
        return false;
    }
    if (resp.status != 200) {
        ESP_LOGW(TAG, "mint info: mint returned %d", resp.status);
        http_response_free(&resp);
        return false;
    }

    // Big mints ship 10-20 KB of info; parse and free the transient body +
    // tree immediately, keeping only the small extracted subset.
    cJSON* j = cJSON_ParseWithLength(resp.body, resp.body_len);
    http_response_free(&resp);
    if (!j) {
        ESP_LOGW(TAG, "mint info: parse failed");
        return false;
    }
    MintInfo info;
    bool ok = from_json_mint_info(j, info);
    cJSON_Delete(j);
    if (!ok)
        return false;

    info_ = std::move(info);
    ESP_LOGI(TAG, "[%d] mint info: %s (%d mint, %d melt method-unit pairs)",
             nvs_slot_, info_->name.c_str(),
             (int)info_->mint_methods.size(), (int)info_->melt_methods.size());
    return true;
}

const MintInfo* Wallet::mint_info() const
{
    return info_ ? &*info_ : nullptr;
}

bool Wallet::method_supported(bool melt, const std::string& method,
                              const std::string& unit, int amount) const
{
    if (!info_)
        return true;   // no info loaded: let the mint decide
    const auto& rows = melt ? info_->melt_methods : info_->mint_methods;
    for (const auto& r : rows) {
        if (r.method != method || r.unit != unit)
            continue;
        if (amount >= 0 && r.min_amount && amount < *r.min_amount) {
            ESP_LOGW(TAG, "%s %s/%s: amount %d below mint minimum %lld",
                     melt ? "melt" : "mint", method.c_str(), unit.c_str(),
                     amount, (long long)*r.min_amount);
            return false;
        }
        if (amount >= 0 && r.max_amount && amount > *r.max_amount) {
            ESP_LOGW(TAG, "%s %s/%s: amount %d above mint maximum %lld",
                     melt ? "melt" : "mint", method.c_str(), unit.c_str(),
                     amount, (long long)*r.max_amount);
            return false;
        }
        return true;
    }
    ESP_LOGW(TAG, "mint does not advertise %s %s/%s",
             melt ? "melt" : "mint", method.c_str(), unit.c_str());
    return false;
}

// -------------------------------------------------------------------------
// Mint error decoding
// -------------------------------------------------------------------------

// Decode a non-200 mint response ({"detail","code"}, see the NUTs error
// code registry) into a MintError the caller can surface.
static void decode_mint_error(const http_response_t& resp, Wallet::MintError& out)
{
    out.status = resp.status;
    out.code = 0;
    out.detail.clear();
    if (resp.body && resp.body_len > 0) {
        cJSON* j = cJSON_ParseWithLength(resp.body, resp.body_len);
        if (j) {
            const cJSON* c = cJSON_GetObjectItemCaseSensitive(j, "code");
            if (cJSON_IsNumber(c))
                out.code = c->valueint;
            const cJSON* d = cJSON_GetObjectItemCaseSensitive(j, "detail");
            if (cJSON_IsString(d) && d->valuestring)
                out.detail = d->valuestring;
            cJSON_Delete(j);
        }
    }
}

static void log_mint_error(const char* op, const Wallet::MintError& e)
{
    const char* hint = "";
    switch (e.code) {
        case 11006: hint = " (amount outside mint's min/max)"; break;
        case 11009: hint = " (inputs/outputs of multiple units)"; break;
        case 11010: hint = " (input and output units differ)"; break;
        case 11013: hint = " (unit or method not supported)"; break;
        default: break;
    }
    ESP_LOGE(TAG, "%s: mint returned %d code=%d %s%s",
             op, e.status, e.code, e.detail.c_str(), hint);
}

// -------------------------------------------------------------------------
// Mint round-trips
// -------------------------------------------------------------------------

// One mint POST: transport check -> non-200 decode into *err_out + log
// line tagged `op` -> deserialize<T>(body). Every flow used to repeat
// this block verbatim. timeout_ms == 0 uses the client default (melt
// passes its long timeout). Transport failures leave *err_out untouched
// (all-zero from the flow-entry clear = nothing to surface).
template <typename T>
static bool mint_post(const char* op, const std::string& url,
                      const char* body, T& out,
                      Wallet::MintError* err_out, int timeout_ms = 0)
{
    http_response_t resp = {};
    esp_err_t err = timeout_ms > 0
        ? http_post_json_timeout(url.c_str(), body, &resp, timeout_ms)
        : http_post_json(url.c_str(), body, &resp);
    if (err != ESP_OK || !resp.body) {
        ESP_LOGE(TAG, "%s POST failed: %s", op, esp_err_to_name(err));
        http_response_free(&resp);
        return false;
    }
    if (resp.status != 200) {
        Wallet::MintError e;
        decode_mint_error(resp, e);
        log_mint_error(op, e);
        if (err_out)
            *err_out = std::move(e);
        http_response_free(&resp);
        return false;
    }
    bool ok = deserialize(resp.body, out);
    http_response_free(&resp);
    if (!ok) {
        ESP_LOGE(TAG, "%s: failed to parse response", op);
        return false;
    }
    return true;
}

// GET counterpart. `quiet` drops all failure logging to DEBUG:
// check_mint_quote probes every mint slot during `claim`, so a miss on
// the wrong slot is expected, not an error.
template <typename T>
static bool mint_get(const char* op, const std::string& url, T& out,
                     Wallet::MintError* err_out, bool quiet = false)
{
    http_response_t resp = {};
    esp_err_t err = http_get(url.c_str(), &resp);
    if (err != ESP_OK || !resp.body) {
        if (quiet)
            ESP_LOGD(TAG, "%s GET failed: %s", op, esp_err_to_name(err));
        else
            ESP_LOGE(TAG, "%s GET failed: %s", op, esp_err_to_name(err));
        http_response_free(&resp);
        return false;
    }
    if (resp.status != 200) {
        Wallet::MintError e;
        decode_mint_error(resp, e);
        if (quiet)
            ESP_LOGD(TAG, "%s: mint returned %d", op, resp.status);
        else
            log_mint_error(op, e);
        if (err_out)
            *err_out = std::move(e);
        http_response_free(&resp);
        return false;
    }
    bool ok = deserialize(resp.body, out);
    http_response_free(&resp);
    if (!ok) {
        if (quiet)
            ESP_LOGD(TAG, "%s: failed to parse response", op);
        else
            ESP_LOGE(TAG, "%s: failed to parse response", op);
        return false;
    }
    return true;
}

// -------------------------------------------------------------------------
// Proof plumbing shared by the flows
// -------------------------------------------------------------------------

// Outgoing inputs never carry their DLEQ (the mint already knows its own
// signatures; forwarding `r` would be pointless). Witnesses ride along.
static std::vector<Proof> strip_dleq_for_send(const std::vector<Proof>& in)
{
    std::vector<Proof> out;
    out.reserve(in.size());
    for (const auto& p : in)
        out.push_back(Proof{p.id, p.amount, p.secret, p.C,
                            std::nullopt, p.witness});
    return out;
}

// NUT-11: any input whose secret is a P2PK structured secret locked to
// our pubkey gets a witness signature attached. Inputs locked to someone
// else are refused; unlocked inputs are a no-op (parse_nut10_secret
// returns false on raw-hex secrets).
static bool attach_p2pk_witnesses(secp256k1_context* ctx,
                                  std::vector<Proof>& inputs)
{
    for (auto& p : inputs) {
        NUT10Secret ns;
        if (!parse_nut10_secret(p.secret, ns)) continue;
        if (ns.kind != "P2PK") continue;
        const unsigned char* priv = Wallet::p2pk_privkey();
        if (!priv || ns.data != std::string(Wallet::p2pk_pubkey_hex())) {
            ESP_LOGE(TAG, "swap: input locked to %s, refusing", ns.data.c_str());
            return false;
        }
        unsigned char sig[64];
        // Deliberately NOT routed through the cashu_suite vtable: NUT-11
        // P2PK witnesses are secp256k1 Schnorr by spec, independent of
        // which suite signed the proof's keyset.
        if (!cashu_schnorr_sign_secret(ctx, priv,
                                       (const unsigned char*)p.secret.c_str(),
                                       p.secret.size(), sig)) {
            ESP_LOGE(TAG, "swap: schnorr sign failed");
            return false;
        }
        char sig_hex[129];
        bytes_to_hex(sig, 64, sig_hex);

        cJSON* witness = cJSON_CreateObject();
        cJSON* arr = cJSON_CreateArray();
        cJSON_AddItemToArray(arr, cJSON_CreateString(sig_hex));
        cJSON_AddItemToObject(witness, "signatures", arr);
        char* w = cJSON_PrintUnformatted(witness);
        p.witness = std::string(w ? w : "");
        if (w) cJSON_free(w);
        cJSON_Delete(witness);
    }
    return true;
}

// Take ownership of freshly unblinded proofs: clear the single-use
// witnesses (DLEQ stays so the proof can be forwarded, NUT-12 Carol-mode),
// append to proofs_, return their sum. Callers keep their own
// save_proofs() call and log line.
int64_t Wallet::adopt_proofs(std::vector<Proof>& fresh)
{
    int64_t sum = 0;
    for (auto& p : fresh) {
        p.witness = std::nullopt;
        sum += p.amount;
        proofs_.push_back(p);
    }
    return sum;
}

// NUT-08: blank change outputs needed to cover any change up to
// max_change, i.e. ceil(log2(max_change + 1)).
int blank_output_count(int max_change)
{
    int n = 0;
    while (max_change > 0) {
        n++;
        max_change >>= 1;
    }
    return n;
}

// -------------------------------------------------------------------------
// Swap (NUT-03)
// -------------------------------------------------------------------------

bool Wallet::swap(std::vector<Proof>& inputs, int amount,
                  std::vector<Proof>& new_proofs,
                  std::vector<Proof>& change)
{
    last_error_ = {};
    if (inputs.empty()) {
        ESP_LOGE(TAG, "swap: no inputs");
        return false;
    }

    // NUT-03 transactions are single-unit (mint error 11009) and outputs
    // must match the inputs' unit (11010) — derive it from the inputs'
    // keysets rather than trusting any caller-supplied value.
    std::string unit;
    if (!proofs_unit(inputs, unit)) {
        ESP_LOGE(TAG, "swap: mixed-unit or unknown-keyset inputs");
        return false;
    }

    const Keyset* ks = active_keyset_for_mint(unit);
    if (!ks) {
        ESP_LOGE(TAG, "swap: no mintable %s keyset", unit.c_str());
        return false;
    }

    int fee = calculate_fee(inputs);
    int64_t input_sum = proofs_sum(inputs);

    int return_amount, change_amount;
    if (amount >= 0) {
        if (input_sum < amount + fee) {
            ESP_LOGE(TAG, "swap: insufficient inputs (%lld < %d + %d)",
                     (long long)input_sum, amount, fee);
            return false;
        }
        return_amount = amount;
        change_amount = (int)(input_sum - amount - fee);
    } else {
        return_amount = (int)(input_sum - fee);
        change_amount = 0;
    }

    auto send_dist = split_amount(return_amount);
    auto change_dist = split_amount(change_amount);

    std::vector<int> combined;
    combined.insert(combined.end(), send_dist.begin(), send_dist.end());
    combined.insert(combined.end(), change_dist.begin(), change_dist.end());
    std::sort(combined.begin(), combined.end());

    BlindingData blinding;
    if (!generate_outputs(combined, ks->id, blinding))
        return false;

    std::vector<Proof> stripped = strip_dleq_for_send(inputs);
    if (!attach_p2pk_witnesses(ctx_, stripped))
        return false;

    SwapRequest req{stripped, blinding.outputs};
    std::string body = serialize(req);
    if (body.empty()) {
        ESP_LOGE(TAG, "swap: request serialization failed");
        return false;
    }

    SwapResponse swap_resp;
    if (!mint_post("swap", mint_url_ + "/v1/swap", body.c_str(), swap_resp,
                   &last_error_))
        return false;

    std::vector<Proof> all_proofs;
    if (!unblind_signatures(swap_resp.signatures, blinding, *ks, all_proofs))
        return false;

    // Separate send proofs from change proofs
    new_proofs.clear();
    change.clear();
    auto remaining = all_proofs;

    for (int n : send_dist) {
        for (auto it = remaining.begin(); it != remaining.end(); ++it) {
            if (it->amount == n) {
                new_proofs.push_back(std::move(*it));
                remaining.erase(it);
                break;
            }
        }
    }
    change = std::move(remaining);

    ESP_LOGI(TAG, "swap: %d inputs -> %d new + %d change (fee=%d)",
             (int)inputs.size(), (int)new_proofs.size(),
             (int)change.size(), fee);

    return true;
}

// -------------------------------------------------------------------------
// Receive (swap a token for new proofs)
// -------------------------------------------------------------------------

bool Wallet::receive(const Token& token, std::vector<Proof>& proofs_out)
{
    last_error_ = {};
    if (token.proofs.empty()) {
        ESP_LOGE(TAG, "receive: token has no proofs");
        return false;
    }

    std::vector<Proof> inputs = token.proofs;
    if (!normalize_input_keyset_ids(inputs))
        return false;

    // Unit checks: all proofs must share one unit (mint error 11009) and
    // the token's declared unit must match the keyset-resolved one (11010).
    // The swap below then picks the same-unit active keyset, so any unit
    // the mint actively backs is accepted — not just the default.
    std::string unit;
    if (!proofs_unit(inputs, unit)) {
        ESP_LOGE(TAG, "receive: mixed-unit proofs in token");
        return false;
    }
    const std::string declared = normalize_unit(token.unit);
    if (!declared.empty() && declared != unit) {
        ESP_LOGE(TAG, "receive: token says '%s' but proofs are '%s'",
                 declared.c_str(), unit.c_str());
        return false;
    }

    if (!verify_forwarded_dleq(inputs))
        return false;

    std::vector<Proof> new_proofs, change;
    if (!swap(inputs, -1, new_proofs, change))
        return false;

    // All proofs go to us (no specific send amount)
    proofs_out.clear();
    proofs_out.insert(proofs_out.end(), new_proofs.begin(), new_proofs.end());
    proofs_out.insert(proofs_out.end(), change.begin(), change.end());

    int64_t got = adopt_proofs(proofs_out);

    char amt[48];
    format_amount(amt, sizeof(amt), got, unit.c_str());
    ESP_LOGI(TAG, "received %s (%d proofs)", amt, (int)proofs_out.size());
    save_proofs();
    return true;
}

// Normalize (possibly short-form) keyset ids on received proofs to our
// stored full ids, so DLEQ checks and the swap can locate the keyset and
// the mint receives full ids in the request. Refresh from the mint once
// if a keyset is unknown.
bool Wallet::normalize_input_keyset_ids(std::vector<Proof>& inputs)
{
    for (int attempt = 0; attempt < 2; ++attempt) {
        bool unknown = false;
        for (auto& p : inputs) {
            bool amb = false;
            const Keyset* ks = resolve_keyset(keysets_, p.id, &amb);
            if (amb) {
                ESP_LOGE(TAG, "receive: ambiguous keyset id %.16s", p.id.c_str());
                return false;
            }
            if (!ks) { unknown = true; continue; }
            p.id = ks->id;  // normalize to the full stored id
        }
        if (!unknown) return true;
        if (attempt == 0) {
            ESP_LOGW(TAG, "receive: unknown keyset, refreshing from mint");
            load_keysets();
        }
    }
    ESP_LOGE(TAG, "receive: unknown keyset id (after refresh)");
    return false;
}

// NUT-12 (Carol-side): if a transferred proof carries a DLEQ with the
// sender's blinding factor `r`, verify it against the keyset's pubkey for
// that amount before swapping. A missing DLEQ is allowed (warn only)
// since senders are not required to forward it.
bool Wallet::verify_forwarded_dleq(const std::vector<Proof>& inputs) const
{
    for (size_t i = 0; i < inputs.size(); i++) {
        const auto& p = inputs[i];
        if (!p.dleq || !p.dleq->r) {
            ESP_LOGW(TAG, "receive: proof[%d] has no DLEQ (accepting)", (int)i);
            continue;
        }
        const cashu_suite_t* suite = suite_for_id(p.id);
        const Keyset* ks = keyset_for_id(p.id);
        if (!suite || !ks) {
            ESP_LOGE(TAG, "receive: no suite/keyset for id %s on proof[%d]",
                     p.id.c_str(), (int)i);
            return false;
        }
        if (!suite->has_dleq)
            continue;  // scheme carries no DLEQ to verify
        const size_t plen = suite->pubkey_len;
        if (plen > CASHU_MAX_POINT_LEN)
            return false;

        std::string A_hex;
        if (!keyset_key_hex_for_amount(*ks, (uint64_t)p.amount, A_hex))
            return false;
        unsigned char A_bytes[CASHU_MAX_POINT_LEN];
        if (A_hex.size() != plen * 2 || !hex_to_bytes(A_hex.c_str(), A_bytes, plen)) {
            ESP_LOGE(TAG, "receive: invalid mint key hex on proof[%d]", (int)i);
            return false;
        }
        unsigned char C_bytes[CASHU_MAX_POINT_LEN];
        if (p.C.size() != plen * 2 || !hex_to_bytes(p.C.c_str(), C_bytes, plen)) {
            ESP_LOGE(TAG, "receive: invalid C hex on proof[%d]", (int)i);
            return false;
        }
        unsigned char e_b[32], s_b[32], r_b[32];
        if (!hex_to_bytes(p.dleq->e.c_str(), e_b, 32) ||
            !hex_to_bytes(p.dleq->s.c_str(), s_b, 32) ||
            !hex_to_bytes(p.dleq->r->c_str(), r_b, 32)) {
            ESP_LOGE(TAG, "receive: invalid dleq hex on proof[%d]", (int)i);
            return false;
        }
        if (!suite->verify_dleq_unblinded((void*)ctx_, A_bytes, plen,
                                          C_bytes, plen,
                                          (const unsigned char*)p.secret.c_str(),
                                          p.secret.size(), e_b, s_b, r_b)) {
            ESP_LOGE(TAG, "dleq verification failed for proof[%d] amount=%d",
                     (int)i, p.amount);
            return false;
        }
    }
    return true;
}

// -------------------------------------------------------------------------
// NUT-04: Mint tokens (method-generic)
// -------------------------------------------------------------------------

bool Wallet::request_mint_quote(int amount, const std::string& unit,
                                const std::string& method, MintQuote& quote_out)
{
    last_error_ = {};
    // Both strings reach the URL/body — enforce the NUT-04 charset before
    // interpolation (console input flows through here).
    if (!unit_token_valid(unit.c_str()) || !unit_token_valid(method.c_str())) {
        ESP_LOGE(TAG, "mint quote: invalid unit '%s' or method '%s'",
                 unit.c_str(), method.c_str());
        return false;
    }

    // Lazy NUT-06 fetch off the sat/bolt11 hot path only — the common case
    // never pays an extra round-trip, and absent info never blocks.
    if ((method != "bolt11" || unit != "sat") && !info_)
        load_mint_info();
    if (!method_supported(false, method, unit, amount)) {
        ESP_LOGE(TAG, "mint quote: %s/%s rejected by mint info",
                 method.c_str(), unit.c_str());
        return false;
    }

    cJSON* body = cJSON_CreateObject();
    cJSON_AddNumberToObject(body, "amount", amount);
    cJSON_AddStringToObject(body, "unit", unit.c_str());
    char* body_str = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    if (!body_str) {
        ESP_LOGE(TAG, "mint quote: request serialization failed");
        return false;
    }

    bool ok = mint_post("mint quote", mint_url_ + "/v1/mint/quote/" + method,
                        body_str, quote_out, &last_error_);
    cJSON_free(body_str);
    if (!ok)
        return false;

    // Stamp what we asked for when the mint omits the echo, so mint_tokens
    // targets the right keyset and endpoint.
    if (quote_out.unit.empty())
        quote_out.unit = unit;
    if (quote_out.method.empty())
        quote_out.method = method;

    ESP_LOGI(TAG, "mint quote: id=%s amount=%d unit=%s method=%s state=%s",
             quote_out.quote.c_str(), quote_out.amount, quote_out.unit.c_str(),
             quote_out.method.c_str(), quote_out.state.c_str());
    return true;
}

bool Wallet::check_mint_quote(const std::string& quote_id,
                              const std::string& method, MintQuote& quote_out)
{
    last_error_ = {};
    if (!unit_token_valid(method.c_str())) {
        ESP_LOGE(TAG, "check mint quote: invalid method '%s'", method.c_str());
        return false;
    }

    if (!mint_get("check mint quote",
                  mint_url_ + "/v1/mint/quote/" + method + "/" + quote_id,
                  quote_out, &last_error_, /*quiet=*/true))
        return false;

    if (quote_out.method.empty())
        quote_out.method = method;

    ESP_LOGI(TAG, "mint quote %s: state=%s amount=%d mintable=%d",
             quote_id.c_str(), quote_out.state.c_str(), quote_out.amount,
             quote_out.mintable());
    return true;
}

bool Wallet::mint_tokens(const MintQuote& quote, int amount)
{
    last_error_ = {};
    const std::string unit = quote.unit.empty() ? std::string("sat") : quote.unit;
    const std::string method = quote.method.empty() ? std::string("bolt11")
                                                    : quote.method;
    if (!unit_token_valid(method.c_str())) {
        ESP_LOGE(TAG, "mint_tokens: invalid method '%s'", method.c_str());
        return false;
    }

    const Keyset* ks = active_keyset_for_mint(unit);
    if (!ks) {
        ESP_LOGE(TAG, "mint_tokens: no mintable %s keyset", unit.c_str());
        return false;
    }

    auto amounts = split_amount(amount);
    BlindingData blinding;
    if (!generate_outputs(amounts, ks->id, blinding))
        return false;

    MintRequest req{quote.quote, blinding.outputs};
    std::string body = serialize(req);
    if (body.empty()) {
        ESP_LOGE(TAG, "mint: request serialization failed");
        return false;
    }

    MintResponse mint_resp;
    if (!mint_post("mint", mint_url_ + "/v1/mint/" + method, body.c_str(),
                   mint_resp, &last_error_))
        return false;

    std::vector<Proof> new_proofs;
    if (!unblind_signatures(mint_resp.signatures, blinding, *ks, new_proofs))
        return false;

    int64_t got = adopt_proofs(new_proofs);

    char amt[48];
    format_amount(amt, sizeof(amt), got, unit.c_str());
    ESP_LOGI(TAG, "minted %s (%d proofs)", amt, (int)new_proofs.size());
    save_proofs();
    return true;
}

// -------------------------------------------------------------------------
// NUT-05: Melt tokens (method-generic)
// -------------------------------------------------------------------------

bool Wallet::request_melt_quote(const std::string& request, const std::string& unit,
                                const std::string& method, MeltQuote& quote_out,
                                std::optional<int> amount)
{
    last_error_ = {};
    if (!unit_token_valid(unit.c_str()) || !unit_token_valid(method.c_str())) {
        ESP_LOGE(TAG, "melt quote: invalid unit '%s' or method '%s'",
                 unit.c_str(), method.c_str());
        return false;
    }

    // Lazy NUT-06 fetch off the sat/bolt11 hot path only. The bolt11 amount
    // lives in the invoice, so bounds are checked only when the caller
    // passed an explicit amount.
    if ((method != "bolt11" || unit != "sat") && !info_)
        load_mint_info();
    if (!method_supported(true, method, unit, amount ? *amount : -1)) {
        ESP_LOGE(TAG, "melt quote: %s/%s rejected by mint info",
                 method.c_str(), unit.c_str());
        return false;
    }

    cJSON* body = cJSON_CreateObject();
    cJSON_AddStringToObject(body, "request", request.c_str());
    cJSON_AddStringToObject(body, "unit", unit.c_str());
    if (amount)   // PR#382: amountless payment targets (custom methods)
        cJSON_AddNumberToObject(body, "amount", *amount);
    char* body_str = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    if (!body_str) {
        ESP_LOGE(TAG, "melt quote: request serialization failed");
        return false;
    }

    bool ok = mint_post("melt quote", mint_url_ + "/v1/melt/quote/" + method,
                        body_str, quote_out, &last_error_);
    cJSON_free(body_str);
    if (!ok)
        return false;

    if (quote_out.unit.empty())
        quote_out.unit = unit;
    if (quote_out.method.empty())
        quote_out.method = method;

    ESP_LOGI(TAG, "melt quote: id=%s amount=%d fee_reserve=%d unit=%s method=%s state=%s",
             quote_out.quote.c_str(), quote_out.amount, quote_out.fee_reserve,
             quote_out.unit.c_str(), quote_out.method.c_str(),
             quote_out.state.c_str());
    return true;
}

bool Wallet::check_melt_quote(const std::string& quote_id,
                              const std::string& method, MeltQuote& quote_out)
{
    last_error_ = {};
    if (!unit_token_valid(method.c_str())) {
        ESP_LOGE(TAG, "check melt quote: invalid method '%s'", method.c_str());
        return false;
    }

    if (!mint_get("check melt quote",
                  mint_url_ + "/v1/melt/quote/" + method + "/" + quote_id,
                  quote_out, &last_error_))
        return false;

    if (quote_out.method.empty())
        quote_out.method = method;

    ESP_LOGI(TAG, "melt quote %s: state=%s", quote_id.c_str(), quote_out.state.c_str());
    return true;
}

bool Wallet::melt_tokens(const MeltQuote& quote, int& change_amount)
{
    last_error_ = {};
    change_amount = 0;

    const std::string unit = quote.unit.empty() ? std::string("sat") : quote.unit;
    const std::string method = quote.method.empty() ? std::string("bolt11")
                                                    : quote.method;
    if (!unit_token_valid(method.c_str())) {
        ESP_LOGE(TAG, "melt: invalid method '%s'", method.c_str());
        return false;
    }

    const Keyset* ks = active_keyset_for_mint(unit);
    if (!ks) {
        ESP_LOGE(TAG, "melt: no mintable %s keyset", unit.c_str());
        return false;
    }

    int needed = quote.amount + quote.fee_reserve;
    std::vector<Proof> selected, leftover;
    if (!select_proofs(needed, unit, selected, leftover))
        return false;

    int input_sum = 0;
    for (const auto& p : selected)
        input_sum += p.amount;
    int input_fee = calculate_fee(selected);

    // Max possible change: if actual LN fee is 0, we get back fee_reserve + excess
    int max_change = input_sum - quote.amount - input_fee;
    if (max_change < 0) max_change = 0;

    // NUT-08 blank outputs for change (amount=0, mint assigns values)
    int n_blank = blank_output_count(max_change);
    BlindingData change_blinding;
    if (n_blank > 0) {
        std::vector<int> blank_amounts(n_blank, 0);
        if (!generate_outputs(blank_amounts, ks->id, change_blinding))
            return false;
    }

    MeltRequest req;
    req.quote = quote.quote;
    req.inputs = strip_dleq_for_send(selected);
    if (n_blank > 0)
        req.outputs = change_blinding.outputs;

    std::string body = serialize(req);
    if (body.empty()) {
        ESP_LOGE(TAG, "melt: request serialization failed");
        return false;
    }

    MeltQuote melt_resp;
    if (!mint_post("melt", mint_url_ + "/v1/melt/" + method, body.c_str(),
                   melt_resp, &last_error_, /*timeout_ms=*/120000))
        return false;

    if (melt_resp.state != "PAID" && melt_resp.state != "PENDING") {
        ESP_LOGE(TAG, "melt: unexpected state: %s", melt_resp.state.c_str());
        return false;
    }

    // Remove spent proofs
    proofs_ = leftover;

    change_amount = unblind_melt_change(melt_resp, change_blinding, *ks, unit);

    save_proofs();

    ESP_LOGI(TAG, "melt: state=%s input=%d change=%d",
             melt_resp.state.c_str(), input_sum, change_amount);
    return true;
}

// Unblind whatever change the mint signed. It may return fewer signatures
// than the blank outputs we sent (only enough to cover the actual change),
// so the blinding data is truncated to match. Returns the change amount
// adopted into proofs_; unblind failure only forfeits change (logged),
// never the melt itself.
int Wallet::unblind_melt_change(const MeltQuote& resp,
                                const BlindingData& blinding,
                                const Keyset& ks, const std::string& unit)
{
    if (!resp.change || resp.change->empty() || blinding.outputs.empty())
        return 0;

    BlindingData truncated = blinding;
    size_t sig_count = resp.change->size();
    if (sig_count < truncated.outputs.size()) {
        truncated.outputs.resize(sig_count);
        truncated.secrets.resize(sig_count);
        truncated.blinding_factors.resize(sig_count);
    }
    std::vector<Proof> change_proofs;
    if (!unblind_signatures(*resp.change, truncated, ks, change_proofs)) {
        ESP_LOGW(TAG, "melt: failed to unblind change signatures");
        return 0;
    }
    int change_amount = (int)adopt_proofs(change_proofs);
    char amt[48];
    format_amount(amt, sizeof(amt), change_amount, unit.c_str());
    ESP_LOGI(TAG, "melt: received %s change (%d proofs)",
             amt, (int)change_proofs.size());
    return change_amount;
}

} // namespace cashu
