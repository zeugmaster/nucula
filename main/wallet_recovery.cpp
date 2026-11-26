#include "wallet.hpp"
#include "cashu_json.hpp"
#include "http.h"
#include <nvs.h>
#include <esp_log.h>
#include <algorithm>
#include <cstring>
#include <memory>

namespace cashu {
namespace {
using Json = std::unique_ptr<cJSON, decltype(&cJSON_Delete)>;
std::string operation_key(int slot) { return "op_" + std::to_string(slot); }
// An empty string means no operation; read failures never mean an empty journal.
bool read_operation(int slot, std::string& body) {
    nvs_handle_t h;
    if(nvs_open("wallet",NVS_READWRITE,&h)!=ESP_OK)return false;
    auto key=operation_key(slot);size_t n=0;
    esp_err_t err=nvs_get_blob(h,key.c_str(),nullptr,&n);
    if(err==ESP_ERR_NVS_NOT_FOUND){body.clear();nvs_close(h);return true;}
    if(err==ESP_OK){body.resize(n);err=nvs_get_blob(h,key.c_str(),body.data(),&n);}
    nvs_close(h);return err==ESP_OK&&!body.empty();
}
const char* string_field(const cJSON* j,const char* key) {
    const cJSON* v=cJSON_GetObjectItemCaseSensitive(j,key);
    return cJSON_IsString(v)?v->valuestring:nullptr;
}
}

bool Wallet::has_pending_operation() const {
    if(proof_storage_error_)return true;
    std::string body;
    return !read_operation(nvs_slot_,body)||!body.empty();
}

bool Wallet::clear_operation() {
    nvs_handle_t h;
    if(nvs_open("wallet",NVS_READWRITE,&h)!=ESP_OK)return false;
    auto key=operation_key(nvs_slot_);esp_err_t err=nvs_erase_key(h,key.c_str());
    if(err==ESP_ERR_NVS_NOT_FOUND)err=ESP_OK;
    if(err==ESP_OK)err=nvs_commit(h);
    nvs_close(h);return err==ESP_OK;
}

bool Wallet::begin_operation(const std::string& path,const std::string& body,
                             const std::vector<Proof>& inputs,const BlindingData& blinding) {
    if(has_pending_operation()||blinding.outputs.size()!=blinding.secrets.size()||
       blinding.outputs.size()!=blinding.blinding_factors.size()||
       blinding.outputs.size()!=blinding.spend_info.size())return false;
    Json j(cJSON_CreateObject(),cJSON_Delete);
    if(!j||!cJSON_AddStringToObject(j.get(),"path",path.c_str())||
       !cJSON_AddStringToObject(j.get(),"request",body.c_str()))return false;
    cJSON* in=to_json_array(inputs);
    if(!in||!cJSON_AddItemToObject(j.get(),"inputs",in)){cJSON_Delete(in);return false;}
    cJSON* out=cJSON_AddArrayToObject(j.get(),"outputs");if(!out)return false;
    for(size_t i=0;i<blinding.outputs.size();i++) {
        Json item(to_json(blinding.outputs[i]),cJSON_Delete);
        if(!item||!cJSON_AddStringToObject(item.get(),"secret",blinding.secrets[i].c_str())||
           !cJSON_AddStringToObject(item.get(),"r",blinding.blinding_factors[i].c_str())||
           (blinding.spend_info[i]&&!cJSON_AddStringToObject(item.get(),"si",blinding.spend_info[i]->c_str()))||
           !cJSON_AddItemToArray(out,item.get()))return false;
        item.release();
    }
    char* text=cJSON_PrintUnformatted(j.get());if(!text)return false;
    nvs_handle_t h;esp_err_t err=nvs_open("wallet",NVS_READWRITE,&h);
    if(err==ESP_OK){
        auto key=operation_key(nvs_slot_);err=nvs_set_blob(h,key.c_str(),text,strlen(text));
        if(err==ESP_OK)err=nvs_commit(h);
        nvs_close(h);
    }
    cJSON_free(text);return err==ESP_OK;
}

bool Wallet::finish_operation(const std::vector<Proof>& inputs,const std::vector<Proof>& outputs) {
    auto updated=proofs_;
    for(const auto& input:inputs)
        updated.erase(std::remove_if(updated.begin(),updated.end(),[&](const Proof& p){return p.secret==input.secret&&p.id==input.id;}),updated.end());
    for(const auto& output:outputs) {
        if(std::none_of(updated.begin(),updated.end(),[&](const Proof& p){return p.secret==output.secret&&p.id==output.id;}))
            updated.push_back(output);
    }
    auto previous=std::move(proofs_);proofs_=std::move(updated);
    if(!save_proofs()){proofs_=std::move(previous);return false;}
    // Save first: a reboot before clearing the journal repeats an idempotent merge.
    return clear_operation();
}

bool Wallet::recover_pending_operation() {
    if(proof_storage_error_){ESP_LOGE("wallet","stored proofs are unreadable; preserve NVS and restore a backup");return false;}
    std::string saved;if(!read_operation(nvs_slot_,saved))return false;
    if(saved.empty())return true;
    Json j(cJSON_ParseWithOpts(saved.c_str(),nullptr,true),cJSON_Delete);
    if(!j||!json_unique_members(j.get()))return false;
    const char* path=string_field(j.get(),"path"),*body=string_field(j.get(),"request");
    if(!path||!body)return false;
    bool melt=std::string(path).compare(0,9,"/v1/melt/")==0;
    std::vector<Proof> inputs;BlindingData blinding;
    const cJSON* rows=cJSON_GetObjectItemCaseSensitive(j.get(),"outputs");
    if(!from_json_array(cJSON_GetObjectItemCaseSensitive(j.get(),"inputs"),inputs)||
       !from_json_array(rows,blinding.outputs))return false;
    const cJSON* row;
    cJSON_ArrayForEach(row,rows) {
        const char* secret=string_field(row,"secret"),*r=string_field(row,"r"),*si=string_field(row,"si");
        if(!secret||!r)return false;
        blinding.secrets.emplace_back(secret);blinding.blinding_factors.emplace_back(r);
        blinding.spend_info.push_back(si?std::optional<std::string>(si):std::nullopt);
    }
    auto finish=[&](const std::vector<BlindSignature>& signatures,const BlindingData& data) {
        std::vector<Proof> recovered;
        if(!signatures.empty()) {
            const Keyset* ks=keyset_for_id(signatures.front().id);
            if(!ks||!unblind_signatures(signatures,data,*ks,recovered))return false;
        }
        if(!finish_operation(inputs,recovered))return false;
        ESP_LOGI("wallet","recovered interrupted operation; retry with current wallet/quote state");
        return true;
    };
    if(melt) {
        Json request(cJSON_ParseWithOpts(body,nullptr,true),cJSON_Delete);
        const char* quote_id=string_field(request.get(),"quote");
        if(!quote_id)return false;
        MeltQuote quote;
        if(check_melt_quote(quote_id,std::string(path).substr(9),quote)) {
            if(quote.state=="PENDING")return false;
            if(quote.state=="PAID") {
                std::vector<BlindSignature> signatures=quote.change.value_or(std::vector<BlindSignature>{});
                if(signatures.size()>blinding.outputs.size())return false;
                blinding.outputs.resize(signatures.size());blinding.secrets.resize(signatures.size());
                blinding.blinding_factors.resize(signatures.size());blinding.spend_info.resize(signatures.size());
                return finish(signatures,blinding);
            }
        }
    }
    // NUT-09 recovers a lost mint/swap response without replaying a spend.
    if(!melt&&!blinding.outputs.empty()) {
        Json request(cJSON_CreateObject(),cJSON_Delete);
        cJSON* out=to_json_array(blinding.outputs);
        if(!request||!out||!cJSON_AddItemToObject(request.get(),"outputs",out)){cJSON_Delete(out);return false;}
        char* text=cJSON_PrintUnformatted(request.get());if(!text)return false;
        http_response_t response={};
        esp_err_t err=http_post_json((mint_url_+"/v1/restore").c_str(),text,&response);cJSON_free(text);
        Json restored(response.body?cJSON_ParseWithOpts(response.body,nullptr,true):nullptr,cJSON_Delete);
        bool ok=err==ESP_OK&&response.status==200&&restored&&json_unique_members(restored.get());
        http_response_free(&response);
        std::vector<BlindedMessage> outputs;std::vector<BlindSignature> signatures;
        if(ok&&from_json_array(cJSON_GetObjectItemCaseSensitive(restored.get(),"outputs"),outputs)&&
           from_json_array(cJSON_GetObjectItemCaseSensitive(restored.get(),"signatures"),signatures)&&
           outputs.size()==blinding.outputs.size()&&outputs.size()==signatures.size()) {
            std::vector<BlindSignature> ordered;std::vector<bool> used(outputs.size());
            for(const auto& wanted:blinding.outputs) {
                bool found=false;
                for(size_t i=0;i<outputs.size();i++)if(!used[i]&&outputs[i].B_==wanted.B_&&outputs[i].id==wanted.id){
                    ordered.push_back(signatures[i]);used[i]=true;found=true;break;
                }
                if(!found)return false;
            }
            return finish(ordered,blinding);
        }
    }
    // Retry exactly the saved request, never fresh outputs. Mints may replay
    // NUT-19 responses; a failed/ambiguous retry keeps the journal and funds locked.
    http_response_t response={};
    esp_err_t err=http_post_json_timeout((mint_url_+path).c_str(),body,&response,120000);
    bool ok=err==ESP_OK&&response.status==200&&response.body;
    std::vector<BlindSignature> signatures;
    if(ok&&melt) {
        MeltQuote quote;ok=deserialize(response.body,quote)&&quote.state=="PAID";
        if(ok&&quote.change)signatures=*quote.change;
        if(signatures.size()>blinding.outputs.size())ok=false;
        if(ok){blinding.outputs.resize(signatures.size());blinding.secrets.resize(signatures.size());
               blinding.blinding_factors.resize(signatures.size());blinding.spend_info.resize(signatures.size());}
    } else if(ok) {
        SwapResponse reply;ok=deserialize(response.body,reply)&&reply.signatures.size()==blinding.outputs.size();
        signatures=std::move(reply.signatures);
    }
    http_response_free(&response);
    return ok&&finish(signatures,blinding);
}
}
