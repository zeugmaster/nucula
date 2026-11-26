#include "nutroot_wallet.hpp"
#include "cashu_json.hpp"
#include "cashu_suite.h"
#include "keyset.hpp"
#include "crypto.h"
#include "hex.h"
#include <cstring>
#include <memory>
#include <set>

namespace cashu {
namespace {
using Json = std::unique_ptr<cJSON, decltype(&cJSON_Delete)>;
struct PrivateKey {
    unsigned char bytes[32] = {};
    ~PrivateKey() { volatile unsigned char* p=bytes; for (unsigned i=0;i<32;i++) p[i]=0; }
};
bool decode(const std::string& hex, unsigned char* bytes, size_t size) {
    return hex.find_first_not_of("0123456789abcdef")==std::string::npos &&
           hex_to_bytes(hex.c_str(),bytes,size);
}
bool field(const cJSON* json, const char* name, unsigned char* bytes, size_t size) {
    const cJSON* value=cJSON_GetObjectItemCaseSensitive(json,name);
    return cJSON_IsString(value)&&decode(value->valuestring,bytes,size);
}
bool public_key(const secp256k1_context* ctx, const unsigned char key[32], unsigned char out[33]) {
    secp256k1_pubkey point;size_t len=33;
    return secp256k1_ec_pubkey_create(ctx,&point,key)&&
           secp256k1_ec_pubkey_serialize(ctx,out,&len,&point,SECP256K1_EC_COMPRESSED);
}
struct OutputBytes {
    std::array<unsigned char,33> id;
    std::array<unsigned char,48> point;
};
bool transaction_outputs(const std::vector<BlindedMessage>& outputs,
                         std::vector<OutputBytes>& bytes, std::vector<nutroot_output_t>& encoded) {
    bytes.resize(outputs.size());encoded.resize(outputs.size());
    for(size_t i=0;i<outputs.size();i++) {
        const auto& o=outputs[i];size_t id_len=o.id.size()/2;
        const auto* suite=suite_for_id(o.id);
        if(o.amount<0||!suite||keyset_version(o.id)==KeysetVersion::unknown||id_len>33||!decode(o.id,bytes[i].id.data(),id_len)||
           !decode(o.B_,bytes[i].point.data(),suite->point_len))return false;
        encoded[i]={static_cast<uint64_t>(o.amount),bytes[i].id.data(),id_len,bytes[i].point.data(),suite->point_len};
    }
    return true;
}
}

bool proof_secret_bytes(const Proof& proof, std::vector<unsigned char>& bytes) {
    if(proof.id.compare(0,2,"02")!=0) {bytes.assign(proof.secret.begin(),proof.secret.end());return true;}
    bytes.resize(33);
    return decode(proof.secret,bytes.data(),33)&&(bytes[0]==2||bytes[0]==3);
}

bool nutroot_spend_key(const secp256k1_context* ctx, const Proof& proof,
                      const unsigned char* receiver_key, unsigned char out[32], bool offline) {
    if(!ctx||!out)return false;
    memset(out,0,32);
    std::vector<unsigned char> secret;
    if(!proof.spend_info||!proof_secret_bytes(proof,secret)||secret.size()!=33)return false;
    secp256k1_pubkey point;
    if(!secp256k1_ec_pubkey_parse(ctx,&point,secret.data(),33))return false;
    Json si(cJSON_ParseWithOpts(proof.spend_info->c_str(),nullptr,true),cJSON_Delete);
    if(!cJSON_IsObject(si.get())||!json_unique_members(si.get()))return false;
    auto has=[&](const char* name){return cJSON_GetObjectItemCaseSensitive(si.get(),name)!=nullptr;};
    if(has("u")||(has("k")&&has("E")))return false; // NUMS has no key path.
    PrivateKey key,shared,tweak;
    unsigned char internal[33],disclosed[33],expected[33];
    if(has("k")) {
        if(!field(si.get(),"k",key.bytes,32)||!secp256k1_ec_seckey_verify(ctx,key.bytes))return false;
    } else if(has("E")&&receiver_key) {
        unsigned char ephemeral[33];
        if(!field(si.get(),"E",ephemeral,33)||!nutroot_ecdh_x(ctx,receiver_key,ephemeral,shared.bytes)||
           !nutroot_p2bk_scalar(ctx,shared.bytes,0,tweak.bytes))return false;
        memcpy(key.bytes,receiver_key,32);
        if(!secp256k1_ec_seckey_tweak_add(ctx,key.bytes,tweak.bytes))return false;
    } else return false;
    if(!public_key(ctx,key.bytes,internal))return false;
    if(has("K")&&(!field(si.get(),"K",disclosed,33)||memcmp(disclosed,internal,33)))return false;
    const cJSON* tree=cJSON_GetObjectItemCaseSensitive(si.get(),"tree");
    if(tree) {
        if(offline)return false; // shortcut: only bare/empty-tree offline reception until policy UI exists.
        int count=cJSON_GetArraySize(tree);
        if(!cJSON_IsArray(tree)||count<1||count>8)return false;
        unsigned char hashes[8*32],root[32];
        for(int i=0;i<count;i++) {
            const cJSON* leaf=cJSON_GetArrayItem(tree,i);
            if(!cJSON_IsString(leaf))return false;
            size_t len=strlen(leaf->valuestring)/2;unsigned char serialized[513];nutroot_leaf_t parsed;
            if(len>sizeof(serialized)||!decode(leaf->valuestring,serialized,len)||
               !nutroot_leaf_parse(ctx,serialized,len,&parsed)||!nutroot_leaf_hash(serialized,len,hashes+i*32))return false;
        }
        if(!nutroot_merkle_root(hashes,count,root)||!nutroot_tweak_pubkey(ctx,internal,root,expected)||
           memcmp(expected,secret.data(),33)||!nutroot_tweak_seckey(ctx,key.bytes,root))return false;
    } else if(memcmp(internal,secret.data(),33)) {
        if(!nutroot_tweak_pubkey(ctx,internal,nullptr,expected)||memcmp(expected,secret.data(),33)||
           !nutroot_tweak_seckey(ctx,key.bytes,nullptr))return false;
    }
    memcpy(out,key.bytes,32);return true;
}

bool nutroot_sign_proofs(const secp256k1_context* ctx, std::vector<Proof>& inputs,
                        const std::vector<BlindedMessage>& outputs,
                        const unsigned char* receiver_key, const nutroot_quote_t* melt) {
    bool v3=false;for(const auto& p:inputs)v3|=p.id.compare(0,2,"02")==0;
    if(!v3)return true;
    struct InputBytes {
        std::array<unsigned char,33> id;
        std::array<unsigned char,48> C,Y;
        std::vector<unsigned char> secret;
    };
    std::vector<InputBytes> bytes(inputs.size());std::vector<nutroot_input_t> encoded(inputs.size());
    std::set<std::string> seen;
    for(size_t i=0;i<inputs.size();i++) {
        const Proof& p=inputs[i];auto& b=bytes[i];size_t id_len=p.id.size()/2;
        const auto* suite=suite_for_id(p.id);
        if(p.amount<=0||!suite||keyset_version(p.id)==KeysetVersion::unknown||id_len>33||!decode(p.id,b.id.data(),id_len)||
           !decode(p.C,b.C.data(),suite->point_len)||!proof_secret_bytes(p,b.secret))return false;
        if(b.id[0]==2) {
            unsigned char one[32]={0};one[31]=1;size_t len=48;
            if(!cashu_suite_bls.blind(nullptr,b.secret.data(),b.secret.size(),one,32,b.Y.data(),&len))return false;
        } else {
            secp256k1_pubkey point;size_t len=33;
            if(!cashu_hash_to_curve(ctx,&point,b.secret.data(),b.secret.size())||
               !secp256k1_ec_pubkey_serialize(ctx,b.Y.data(),&len,&point,SECP256K1_EC_COMPRESSED))return false;
        }
        if(!seen.insert(std::string(reinterpret_cast<const char*>(b.Y.data()),suite->point_len)).second)return false;
        encoded[i]={static_cast<uint64_t>(p.amount),b.id.data(),id_len,b.secret.data(),b.secret.size(),
                    b.C.data(),suite->point_len,nullptr,b.Y.data(),suite->point_len};
    }
    std::vector<OutputBytes> outbytes;std::vector<nutroot_output_t> out;
    if(!transaction_outputs(outputs,outbytes,out))return false;
    nutroot_tx_t tx={};tx.proof_inputs=encoded.data();tx.n_proof_inputs=encoded.size();
    tx.blinded_outputs=out.data();tx.n_blinded_outputs=out.size();tx.melt_quote_outputs=melt;tx.n_melt_quote_outputs=melt?1:0;
    unsigned char transaction[32],digest[32],sig[64];
    if(!nutroot_tx_digest(&tx,transaction))return false;
    for(size_t i=0;i<inputs.size();i++) {
        if(bytes[i].id[0]!=2)continue;
        PrivateKey key;
        if(!nutroot_spend_key(ctx,inputs[i],receiver_key,key.bytes)||
           !nutroot_input_digest(transaction,&encoded[i],digest)||!nutroot_sign_digest(ctx,key.bytes,digest,sig))return false;
        char hex[129];bytes_to_hex(sig,64,hex);
        inputs[i].witness=std::string("{\"signatures\":[\"")+hex+"\"]}";
    }
    return true;
}

bool nutroot_sign_quote(const secp256k1_context* ctx, const MintQuote& quote, int amount,
                       const std::vector<BlindedMessage>& outputs,
                       const unsigned char key[32], std::string& signature) {
    if(amount<=0||!quote.amount_issued||!quote.amount_paid||amount>quote.mintable())return false;
    unsigned char lock[33],expected[33];
    if(!decode(quote.pubkey,lock,33)||!public_key(ctx,key,expected)||memcmp(lock,expected,33))return false;
    std::vector<OutputBytes> bytes;std::vector<nutroot_output_t> out;
    if(!transaction_outputs(outputs,bytes,out))return false;
    int64_t total=0;for(const auto& o:outputs)total+=o.amount;
    if(total!=amount)return false;
    nutroot_quote_t input={};input.amount=amount;input.quote_id=quote.quote.c_str();input.lock_key=lock;input.issued=*quote.amount_issued;
    nutroot_tx_t tx={};tx.mint_quote_inputs=&input;tx.n_mint_quote_inputs=1;tx.blinded_outputs=out.data();tx.n_blinded_outputs=out.size();
    unsigned char transaction[32],digest[32],sig[64];
    if(!nutroot_tx_digest(&tx,transaction)||!nutroot_quote_input_digest(transaction,&input,digest)||
       !nutroot_sign_digest(ctx,key,digest,sig))return false;
    char hex[129];bytes_to_hex(sig,64,hex);signature=hex;return true;
}
}
