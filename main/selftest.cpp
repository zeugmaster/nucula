#include "selftest.hpp"

#include "base64url.hpp"
#include "cashu.hpp"
#include "cashu_cbor.hpp"
#include "cashu_json.hpp"
#include "hex.h"
#include "nut10.hpp"
#include "wallet.hpp"

#include <cstring>
#include <esp_log.h>

#define TAG "selftest"

bool nucula_pure_selftests()
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

    { // hex round-trip, both edge bytes and case-normalization on decode
        const unsigned char bytes[4] = {0x00, 0x7f, 0x80, 0xff};
        char hex[9];
        bytes_to_hex(bytes, 4, hex);
        unsigned char back[4] = {};
        expect("hex round-trip",
               strcmp(hex, "007f80ff") == 0 &&
               hex_to_bytes(hex, back, 4) &&
               memcmp(bytes, back, 4) == 0 &&
               hex_to_bytes("007F80FF", back, 4) &&
               memcmp(bytes, back, 4) == 0);
    }
    { // base64url round-trip, plus a known unpadded vector
        const char* msg = "cashu?&=/+test";
        std::string enc = cashu::base64url_encode(
            (const unsigned char*)msg, strlen(msg));
        std::string dec;
        expect("base64url round-trip",
               enc.find('=') == std::string::npos &&
               cashu::base64url_decode(enc.c_str(), enc.size(), dec) &&
               dec == msg);
        std::string hello;
        expect("base64url unpadded",
               cashu::base64url_decode("aGVsbG8", 7, hello) && hello == "hello");
    }
    { // binary amount split: exact powers of two, ascending
        auto v13 = cashu::Wallet::split_amount(13);
        auto v1  = cashu::Wallet::split_amount(1);
        auto v0  = cashu::Wallet::split_amount(0);
        expect("split_amount",
               v13.size() == 3 && v13[0] == 1 && v13[1] == 4 && v13[2] == 8 &&
               v1.size() == 1 && v1[0] == 1 &&
               v0.empty());
    }
    { // NUT-10 structured secret: well-formed P2PK parses, raw hex does not
        cashu::NUT10Secret s;
        bool parsed = cashu::parse_nut10_secret(
            R"(["P2PK",{"nonce":"n1","data":"02aa","tags":[["sigflag","SIG_INPUTS"]]}])",
            s);
        cashu::NUT10Secret raw;
        expect("nut10 parse",
               parsed && s.kind == "P2PK" && s.nonce == "n1" && s.data == "02aa" &&
               s.tags.size() == 1 && s.tags[0].size() == 2 &&
               s.tags[0][1] == "SIG_INPUTS" &&
               !cashu::parse_nut10_secret("deadbeef", raw));
    }
    { // V4 (CBOR) token round-trip — the NFC hot path had no coverage
        cashu::Token t;
        t.mint = "https://mint.example";
        t.unit = "sat";
        t.memo = "roundtrip";
        cashu::Proof p1;
        p1.id = "0184237e63ce3423df7db2dcedc7329cff722a12b90206db53185fc31a4ca5ed96";
        p1.amount = 2;
        p1.secret = "sec-one";
        p1.C = "02c02b73fee0e5e0ee89ac9e0b60950a0973b873bbf4f8153c451c4536173b1b0b";
        cashu::DLEQ d;
        d.e = "aa11223344556677889900aabbccddeeff00112233445566778899aabbccddee";
        d.s = "bb11223344556677889900aabbccddeeff00112233445566778899aabbccddee";
        d.r = "cc11223344556677889900aabbccddeeff00112233445566778899aabbccddee";
        p1.dleq = d;
        cashu::Proof p2 = p1;
        p2.amount = 8;
        p2.secret = "sec-two";
        p2.dleq = std::nullopt;
        t.proofs = {p1, p2};

        std::string tok = cashu::serialize_token_v4(t);
        cashu::Token back;
        bool decoded = !tok.empty() &&
                       tok.rfind("cashuB", 0) == 0 &&
                       cashu::deserialize_token(tok.c_str(), back);
        expect("cbor v4 round-trip",
               decoded &&
               back.mint == t.mint && back.unit == t.unit &&
               back.memo && *back.memo == "roundtrip" &&
               back.proofs.size() == 2 &&
               back.proofs[0].id == p1.id &&
               back.proofs[0].amount + back.proofs[1].amount == 10 &&
               back.proofs[0].secret == "sec-one" &&
               back.proofs[0].C == p1.C &&
               back.proofs[0].dleq &&
               back.proofs[0].dleq->e == d.e &&
               back.proofs[0].dleq->r && *back.proofs[0].dleq->r == *d.r &&
               !back.proofs[1].dleq);
    }
    return ok;
}
