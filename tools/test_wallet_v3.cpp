#include "wallet.hpp"
#include "cashu_json.hpp"
#include "cashu_cbor.hpp"
#include "keyset.hpp"
#include "nutroot_wallet.hpp"
#include "cashu_suite.h"
#include "hex.h"
#include "http.h"
#include "nvs.h"
#include <blst.h>
#include <openssl/rand.h>
#include <cassert>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <map>
#include <set>
#include <functional>

using namespace cashu;
struct Value { unsigned type; std::string bytes; };
static std::map<std::string,Value> disk;
static std::map<unsigned,std::map<std::string,Value>> transactions;
static bool fail_commit=false,fail_journal=false;
esp_err_t nvs_open(const char*,int,nvs_handle_t* h) { static unsigned next=0;*h=++next;transactions[*h]=disk;return ESP_OK; }
void nvs_close(nvs_handle_t h) {transactions.erase(h);}
esp_err_t nvs_commit(nvs_handle_t h) {if(fail_commit)return ESP_FAIL;disk=transactions.at(h);return ESP_OK;}
esp_err_t nvs_erase_key(nvs_handle_t h,const char* k) {return transactions.at(h).erase(k)?ESP_OK:ESP_ERR_NVS_NOT_FOUND;}
static esp_err_t get(nvs_handle_t h,const char* k,unsigned type,void* out,size_t* n) {
    auto& values=transactions.at(h);auto it=values.find(k);
    if(it==values.end())return ESP_ERR_NVS_NOT_FOUND;
    if(it->second.type!=type)return ESP_ERR_NVS_TYPE_MISMATCH;
    if(!out){*n=it->second.bytes.size();return ESP_OK;}
    if(*n<it->second.bytes.size())return ESP_ERR_NVS_INVALID_LENGTH;
    *n=it->second.bytes.size();memcpy(out,it->second.bytes.data(),*n);return ESP_OK;
}
static esp_err_t put(nvs_handle_t h,const char* k,unsigned type,const void* bytes,size_t n) {
    transactions.at(h)[k]={type,std::string(static_cast<const char*>(bytes),n)};return ESP_OK;
}
esp_err_t nvs_get_blob(nvs_handle_t h,const char* k,void* b,size_t* n){return get(h,k,0,b,n);}
esp_err_t nvs_set_blob(nvs_handle_t h,const char* k,const void* b,size_t n){if(fail_journal&&strncmp(k,"op_",3)==0)return ESP_FAIL;return put(h,k,0,b,n);}
esp_err_t nvs_get_str(nvs_handle_t h,const char* k,char* b,size_t* n){return get(h,k,1,b,n);}
esp_err_t nvs_set_str(nvs_handle_t h,const char* k,const char* b){return put(h,k,1,b,strlen(b)+1);}
esp_err_t nvs_get_u8(nvs_handle_t h,const char* k,uint8_t* b){size_t n=1;return get(h,k,2,b,&n);}
esp_err_t nvs_set_u8(nvs_handle_t h,const char* k,uint8_t b){return put(h,k,2,&b,1);}
esp_err_t nvs_get_u32(nvs_handle_t h,const char* k,uint32_t* b){size_t n=4;return get(h,k,3,b,&n);}
esp_err_t nvs_get_u64(nvs_handle_t h,const char* k,uint64_t* b){size_t n=8;return get(h,k,4,b,&n);}
esp_err_t nvs_set_u64(nvs_handle_t h,const char* k,uint64_t b){return put(h,k,4,&b,8);}
void esp_fill_random(void* out,size_t n){assert(RAND_bytes(static_cast<unsigned char*>(out),static_cast<int>(n))==1);}
static std::string hex(const unsigned char* b,size_t n) {std::string s(n*2+1,'\0');bytes_to_hex(b,n,s.data());s.resize(n*2);return s;}
static std::string json(cJSON* j) {assert(j);char* p=cJSON_PrintUnformatted(j);assert(p);std::string s=p;cJSON_free(p);cJSON_Delete(j);return s;}
static Keyset mint_keyset;
static MintQuote mint_quote;
static std::map<int,unsigned> mint_scalars={{1,7},{2,13},{4,29},{8,71}};
static secp256k1_context* ctx;
static bool bad_signature=false,drop_reply=false,fail_after_reply=false;
static std::map<std::string,BlindSignature> restorable;
static std::string paid_melt;
static unsigned posts=0;
static std::set<std::string> spent;
static std::vector<BlindSignature> issue(const std::vector<BlindedMessage>& outputs,bool change=false) {
    std::vector<BlindSignature> signatures;
    for(size_t i=0;i<outputs.size();i++) {
        const auto& o=outputs[i];assert(o.id==mint_keyset.id);
        int amount=change?1:o.amount;assert(mint_scalars.count(amount));
        unsigned char compressed[48],scalar[32]={0};assert(hex_to_bytes(o.B_.c_str(),compressed,48));
        blst_p1_affine affine;assert(blst_p1_uncompress(&affine,compressed)==BLST_SUCCESS);
        blst_p1 point,result;blst_p1_from_affine(&point,&affine);scalar[0]=mint_scalars.at(amount);
        blst_p1_mult(&result,&point,scalar,256);blst_p1_compress(compressed,&result);
        restorable[o.B_]={o.id,amount,hex(compressed,48),std::nullopt};
        if(bad_signature)compressed[20]^=1;
        signatures.push_back({o.id,amount,hex(compressed,48),std::nullopt});
        if(change)break;
    }
    return signatures;
}
static void verify_request(const std::vector<Proof>& inputs,const std::vector<BlindedMessage>& outputs,const nutroot_quote_t* quote=nullptr) {
    struct Bytes {unsigned char id[33],secret[33],C[48],Y[48];};
    std::vector<Bytes> data(inputs.size());std::vector<nutroot_input_t> in(inputs.size());
    std::vector<Bytes> outdata(outputs.size());std::vector<nutroot_output_t> out(outputs.size());
    unsigned char one[32]={0};one[31]=1;
    for(size_t i=0;i<inputs.size();i++) {
        const auto& p=inputs[i];assert(!p.spend_info&&!p.dleq&&p.witness&&p.id==mint_keyset.id);
        assert(!spent.count(p.secret));auto& b=data[i];size_t len=48;
        assert(hex_to_bytes(p.id.c_str(),b.id,33)&&hex_to_bytes(p.secret.c_str(),b.secret,33)&&hex_to_bytes(p.C.c_str(),b.C,48));
        assert(cashu_suite_bls.blind(nullptr,b.secret,33,one,32,b.Y,&len));
        unsigned char K[96];assert(hex_to_bytes(mint_keyset.keys.at(p.amount).c_str(),K,96));
        const unsigned char* secret=b.secret;size_t size=33;
        assert(cashu_suite_bls.verify_proofs(nullptr,1,K,b.C,&secret,&size));
        in[i]={static_cast<uint64_t>(p.amount),b.id,33,b.secret,33,b.C,48,p.witness->c_str(),b.Y,48};
    }
    for(size_t i=0;i<outputs.size();i++) {
        const auto& o=outputs[i];auto& b=outdata[i];
        assert(hex_to_bytes(o.id.c_str(),b.id,33)&&hex_to_bytes(o.B_.c_str(),b.C,48));
        out[i]={static_cast<uint64_t>(o.amount),b.id,33,b.C,48};
    }
    nutroot_tx_t tx={};tx.proof_inputs=in.data();tx.n_proof_inputs=in.size();tx.blinded_outputs=out.data();tx.n_blinded_outputs=out.size();
    tx.melt_quote_outputs=quote;tx.n_melt_quote_outputs=quote?1:0;
    assert(nutroot_verify_transaction(ctx,&tx,2000000000));
    for(const auto& p:inputs)assert(spent.insert(p.secret).second);
}
static esp_err_t reply(http_response_t* r,const std::string& body) {r->status=200;r->body=strdup(body.c_str());r->body_len=body.size();return ESP_OK;}
extern "C" void http_response_free(http_response_t* r){free(r->body);r->body=nullptr;}
extern "C" esp_err_t http_get(const char* url,http_response_t* r) {
    std::string path=url;
    if(path.find("/v1/melt/quote/")!=std::string::npos) { assert(!paid_melt.empty());return reply(r,paid_melt); }
    if(path.find("/v1/mint/quote/")!=std::string::npos) {
        cJSON* j=to_json(mint_quote);return reply(r,json(j));
    }
    if(path.find("/v1/info")!=std::string::npos)return reply(r,R"({"name":"test","nuts":{}})");
    if(path.find("/v1/keys")!=std::string::npos) {
        cJSON* j=cJSON_CreateObject();cJSON* a=cJSON_AddArrayToObject(j,"keysets");cJSON_AddItemToArray(a,to_json(mint_keyset));return reply(r,json(j));
    }
    assert(false);return ESP_FAIL;
}
extern "C" esp_err_t http_post_json(const char* url,const char* body,http_response_t* r) {
    posts++;cJSON* j=cJSON_Parse(body);assert(j&&json_unique_members(j));std::string path=url;
    std::vector<BlindedMessage> outputs;std::vector<Proof> inputs;
    auto* out=cJSON_GetObjectItemCaseSensitive(j,"outputs");if(out)assert(from_json_array(out,outputs));
    auto* in=cJSON_GetObjectItemCaseSensitive(j,"inputs");if(in)assert(from_json_array(in,inputs));
    std::string response;
    if(path.find("/v1/restore")!=std::string::npos) {
        std::vector<BlindedMessage> restored;std::vector<BlindSignature> signatures;
        for(const auto& o:outputs)if(restorable.count(o.B_)){restored.push_back(o);signatures.push_back(restorable.at(o.B_));}
        cJSON* result=cJSON_CreateObject();cJSON_AddItemToObject(result,"outputs",to_json_array(restored));
        cJSON_AddItemToObject(result,"signatures",to_json_array(signatures));cJSON_Delete(j);return reply(r,json(result));
    }
    if(path.find("/v1/mint/quote/")!=std::string::npos) {
        const auto* key=cJSON_GetObjectItemCaseSensitive(j,"pubkey");assert(cJSON_IsString(key));
        mint_quote={};mint_quote.quote="q1";mint_quote.request="ln-test";mint_quote.amount=8;mint_quote.amount_paid=8;mint_quote.amount_issued=0;mint_quote.updated_at=100;
        mint_quote.unit="sat";mint_quote.method="bolt11";mint_quote.pubkey=key->valuestring;mint_quote.state="PAID";
        cJSON* result=to_json(mint_quote);response=json(result);
    } else if(path.find("/v1/mint/")!=std::string::npos) {
        unsigned char lock[33];assert(hex_to_bytes(mint_quote.pubkey.c_str(),lock,33));
        int amount=0;std::vector<std::array<unsigned char,48>> b(outputs.size());std::vector<std::array<unsigned char,33>> ids(outputs.size());
        std::vector<nutroot_output_t> encoded(outputs.size());
        for(size_t i=0;i<outputs.size();i++) {const auto& o=outputs[i];amount+=o.amount;assert(hex_to_bytes(o.id.c_str(),ids[i].data(),33)&&hex_to_bytes(o.B_.c_str(),b[i].data(),48));encoded[i]={static_cast<uint64_t>(o.amount),ids[i].data(),33,b[i].data(),48};}
        nutroot_quote_t q={};q.amount=amount;q.quote_id=mint_quote.quote.c_str();q.lock_key=lock;q.issued=*mint_quote.amount_issued;
        nutroot_tx_t tx={};tx.mint_quote_inputs=&q;tx.n_mint_quote_inputs=1;tx.blinded_outputs=encoded.data();tx.n_blinded_outputs=encoded.size();
        unsigned char transaction[32],digest[32];assert(nutroot_tx_digest(&tx,transaction)&&nutroot_quote_input_digest(transaction,&q,digest));
        auto* sig=cJSON_GetObjectItemCaseSensitive(j,"signature");assert(cJSON_IsString(sig));
        std::string witness=std::string("{\"signatures\":[\"")+sig->valuestring+"\"]}";
        assert(nutroot_verify_witness(ctx,lock,digest,witness.c_str(),2000000000));
        mint_quote.amount_issued=*mint_quote.amount_issued+amount;response=serialize(MintResponse{issue(outputs)});
    } else if(path.find("/v1/swap")!=std::string::npos) {
        verify_request(inputs,outputs);response=serialize(SwapResponse{issue(outputs)});
    } else if(path.find("/v1/melt/")!=std::string::npos) {
        nutroot_quote_t q={};q.amount=4;q.quote_id="m1";verify_request(inputs,outputs,&q);
        MeltQuote melt;melt.quote="m1";melt.amount=3;melt.fee_reserve=1;melt.state="PAID";melt.change=issue(outputs,true);response=serialize(melt);paid_melt=response;
    } else assert(false);
    cJSON_Delete(j);
    if(fail_after_reply){fail_commit=true;fail_after_reply=false;}
    if(drop_reply){drop_reply=false;return ESP_FAIL;}
    return reply(r,response);
}
extern "C" esp_err_t http_post_json_timeout(const char* url,const char* body,http_response_t* r,int timeout) {(void)timeout;return http_post_json(url,body,r);}

static int allocation_countdown=-1;
static void* failing_allocate(size_t n) {
    if(allocation_countdown==0)return nullptr;
    if(allocation_countdown>0)--allocation_countdown;
    return malloc(n);
}
template<class T> static void allocation_test(const T& value) {
    const std::string expected=serialize(value);assert(!expected.empty());
    for(int i=0;i<120;i++) {
        allocation_countdown=i;cJSON_Hooks hooks={failing_allocate,free};cJSON_InitHooks(&hooks);
        const std::string result=serialize(value);
        cJSON_InitHooks(nullptr);allocation_countdown=-1;
        assert(result.empty()||result==expected);
    }
}
static void receiver_test() {
    Proof proof;proof.id=mint_keyset.id;
    proof.secret="03a3e12cc077e5605f36441046f50c114fcc883b079a34028bed66732e3a419e51";
    proof.spend_info=R"({"E":"022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4"})";
    unsigned char receiver[32]={0},key[32];receiver[31]=3;
    assert(nutroot_spend_key(ctx,proof,receiver,key,true));
    assert(hex(key,32)=="7dfb649b0edda814f7cf0feb889e5657eb2083a528aa60a3a943fe0cea066184");
    assert(!nutroot_spend_key(ctx,proof,nullptr,key));
    proof.spend_info=R"({"E":"022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4","tree":["00020200010104002102e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd1306000468a3be80"]})";
    unsigned char internal[33],leaf[49],root[32],point[33];
    assert(hex_to_bytes(proof.secret.c_str(),internal,33)&&hex_to_bytes("00020200010104002102e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd1306000468a3be80",leaf,49));
    assert(nutroot_leaf_hash(leaf,49,root)&&nutroot_tweak_pubkey(ctx,internal,root,point));proof.secret=hex(point,33);
    assert(nutroot_spend_key(ctx,proof,receiver,key));
    assert(!nutroot_spend_key(ctx,proof,receiver,key,true));
}

int main() {
    ctx=secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    mint_keyset.id="02"+std::string(64,'0');mint_keyset.unit="sat";mint_keyset.active=true;mint_keyset.input_fee_ppk=0;
    for(const auto& entry:mint_scalars){unsigned char scalar[32]={0},key[96];scalar[0]=entry.second;blst_p2 point;blst_p2_mult(&point,blst_p2_generator(),scalar,256);blst_p2_compress(key,&point);mint_keyset.keys[entry.first]=hex(key,96);}
    mint_keyset.id=derive_keyset_id(mint_keyset);assert(mint_keyset.id=="022546ab0a2dee9f79510f4e20a4e3d9e894a97361047c594902573a7e64f9d701");
    assert(keyset_run_tests()&&cashu_json_run_tests()&&cashu_cbor_run_tests());
    receiver_test();
    Keyset large_keyset=mint_keyset;large_keyset.final_expiry=1893456000;
    for(unsigned i=0;i<32;i++)large_keyset.keys[uint64_t{1}<<i]=mint_keyset.keys.begin()->second;
    allocation_test(large_keyset);
    unsigned char seed[64]={1};assert(Wallet::save_seed(seed,"test mnemonic"));
    Wallet wallet("https://mint.test",ctx,0);assert(wallet.load_keysets());
    uint64_t counter=0;assert(Wallet::load_counter(mint_keyset.id,counter)&&counter==0);
    Wallet::BlindingData generated;fail_commit=true;assert(!wallet.generate_outputs({1},mint_keyset.id,generated));fail_commit=false;
    assert(Wallet::load_counter(mint_keyset.id,counter)&&counter==0);
    assert(Wallet::save_counter(mint_keyset.id,UINT64_MAX));assert(!wallet.generate_outputs({1},mint_keyset.id,generated));
    assert(Wallet::save_counter(mint_keyset.id,0));
    uint32_t old_counter=42;disk["c_"+mint_keyset.id.substr(0,13)]={3,std::string(reinterpret_cast<char*>(&old_counter),4)};
    assert(Wallet::load_counter(mint_keyset.id,counter)&&counter==42);
    assert(Wallet::save_counter(mint_keyset.id,0));
    assert(wallet.generate_outputs({1},mint_keyset.id,generated));
    auto signatures=issue(generated.outputs);std::vector<Proof> checked;
    assert(wallet.unblind_signatures(signatures,generated,mint_keyset,checked));
    auto wrong=signatures;wrong[0].amount=2;assert(!wallet.unblind_signatures(wrong,generated,mint_keyset,checked));
    wrong=signatures;wrong[0].id="02"+std::string(64,'0');assert(!wallet.unblind_signatures(wrong,generated,mint_keyset,checked));
    wrong=signatures;wrong[0].dleq=DLEQ{"00","00",std::nullopt};assert(!wallet.unblind_signatures(wrong,generated,mint_keyset,checked));
    MintQuote quote;assert(wallet.request_mint_quote(8,"sat","bolt11",quote));
    Wallet reboot("https://mint.test",ctx,0);assert(reboot.load_from_nvs());
    assert(reboot.check_mint_quote(quote.quote,"bolt11",quote));
    mint_quote.updated_at=99;assert(!reboot.check_mint_quote(quote.quote,"bolt11",quote)&&quote.updated_at==100);
    mint_quote.updated_at=100;
    fail_journal=true;unsigned before=posts;
    assert(!reboot.mint_tokens(quote,8)&&posts==before&&!reboot.has_pending_operation());fail_journal=false;
    fail_after_reply=true;
    assert(!reboot.mint_tokens(quote,8)&&reboot.has_pending_operation()&&reboot.balance()==0);
    fail_commit=false;
    Wallet recovery("https://mint.test",ctx,0);assert(recovery.load_from_nvs());
    assert(recovery.recover_pending_operation()&&recovery.balance()==8&&!recovery.has_pending_operation());
    assert(reboot.load_from_nvs());
    assert(reboot.balance()==8&&reboot.proofs()[0].spend_info);
    Wallet loaded("https://mint.test",ctx,0);assert(loaded.load_from_nvs()&&loaded.balance()==8);
    assert(loaded.proofs()[0].spend_info==reboot.proofs()[0].spend_info);
    std::vector<Proof> inputs=loaded.proofs(),send,change;
    assert(loaded.swap(inputs,4,send,change)&&proofs_sum(send)==4&&proofs_sum(change)==4);
    assert(loaded.balance()==8&&loaded.remove_proofs(send)&&loaded.balance()==4);
    Token token;token.mint="https://mint.test";token.unit="sat";token.proofs=send;
    token.proofs[0].witness="must not be transferred";
    allocation_test(token);allocation_test(token.proofs.front());
    allocation_test(SwapRequest{token.proofs,generated.outputs});
    allocation_test(MintRequest{"q",generated.outputs,std::string(128,'0')});
    allocation_test(MeltRequest{"m",token.proofs,generated.outputs});
    auto malformed=serialize(token.proofs.front());
    auto amount_pos=malformed.find("\"amount\":4");assert(amount_pos!=std::string::npos);
    malformed.replace(amount_pos,10,"\"amount\":4.5");Proof invalid;assert(!deserialize(malformed.c_str(),invalid));
    Token received;const std::string encoded=serialize_token_v4(token);assert(!encoded.empty()&&deserialize_token_v4(encoded.c_str(),received));
    assert(received.proofs[0].spend_info==send[0].spend_info&&!received.proofs[0].witness);
    Token legacy;assert(deserialize_token_v3(serialize_token_v3(token).c_str(),legacy));assert(legacy.proofs[0].spend_info&&!legacy.proofs[0].witness);
    std::string request=serialize(SwapRequest{token.proofs,{}});assert(request.find("spend_info")==std::string::npos&&request.find("\"k\"")==std::string::npos);
    Wallet recipient("https://mint.test",ctx,1);assert(recipient.load_keysets());
    auto bad=received.proofs;bad[0].spend_info=R"({"k":"00"})";assert(!recipient.verify_incoming_proofs(bad));
    bad=received.proofs;bad[0].secret[0]='A';assert(!recipient.verify_incoming_proofs(bad));
    bad=received.proofs;bad[0].C[30]^=1;assert(!recipient.verify_incoming_proofs(bad));
    bad=received.proofs;bad.push_back(bad[0]);assert(!recipient.verify_incoming_proofs(bad,true));
    std::vector<Proof> ours;drop_reply=true;
    assert(!recipient.receive(received,ours)&&recipient.has_pending_operation());
    Wallet recipient_reboot("https://mint.test",ctx,1);assert(recipient_reboot.load_from_nvs());
    assert(recipient_reboot.recover_pending_operation()&&recipient_reboot.balance()==4);
    Wallet restored("https://mint.test",ctx,1);assert(restored.load_from_nvs()&&restored.balance()==4);
    MeltQuote melt;melt.quote="m1";melt.amount=3;melt.fee_reserve=1;melt.unit="sat";melt.method="bolt11";
    int returned=0;drop_reply=true;
    assert(!restored.melt_tokens(melt,returned)&&restored.has_pending_operation());
    Wallet melt_reboot("https://mint.test",ctx,1);assert(melt_reboot.load_from_nvs());
    assert(melt_reboot.recover_pending_operation()&&melt_reboot.balance()==1);
    // Invalid response signatures leave the original outputs recoverable.
    inputs=loaded.proofs();bad_signature=true;
    assert(!loaded.swap(inputs,-1,send,change)&&loaded.has_pending_operation());bad_signature=false;
    assert(loaded.recover_pending_operation()&&loaded.balance()==4);
    disk["proofs_2"]={0,"malformed stored proofs"};
    Wallet corrupt("https://mint.test",ctx,2);corrupt.load_from_nvs();
    assert(corrupt.has_pending_operation()&&!corrupt.recover_pending_operation()&&!corrupt.clear_proofs());
    assert(disk.at("proofs_2").bytes=="malformed stored proofs");
    printf("PASS: v3 quote locking, mint, NVS reload, swap, send/receive, melt/change, private-data isolation, counter failure/overflow, malformed proofs, lost responses, failed proof save, recovery (%u requests)\n",posts);
    secp256k1_context_destroy(ctx);
}
