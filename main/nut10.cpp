#include "nut10.hpp"
#include <cJSON.h>

namespace cashu {

std::string serialize_nut10_secret(const NUT10Secret& s)
{
    cJSON* arr = cJSON_CreateArray();
    cJSON_AddItemToArray(arr, cJSON_CreateString(s.kind.c_str()));

    cJSON* obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "nonce", s.nonce.c_str());
    cJSON_AddStringToObject(obj, "data",  s.data.c_str());
    if (!s.tags.empty()) {
        cJSON* tags = cJSON_CreateArray();
        for (const auto& tag : s.tags) {
            cJSON* row = cJSON_CreateArray();
            for (const auto& v : tag)
                cJSON_AddItemToArray(row, cJSON_CreateString(v.c_str()));
            cJSON_AddItemToArray(tags, row);
        }
        cJSON_AddItemToObject(obj, "tags", tags);
    }
    cJSON_AddItemToArray(arr, obj);

    char* str = cJSON_PrintUnformatted(arr);
    std::string out(str ? str : "");
    if (str) cJSON_free(str);
    cJSON_Delete(arr);
    return out;
}

bool parse_nut10_secret(const std::string& s, NUT10Secret& out)
{
    cJSON* root = cJSON_Parse(s.c_str());
    if (!root) return false;

    bool ok = false;
    if (cJSON_IsArray(root) && cJSON_GetArraySize(root) == 2) {
        cJSON* kind = cJSON_GetArrayItem(root, 0);
        cJSON* obj  = cJSON_GetArrayItem(root, 1);
        if (cJSON_IsString(kind) && cJSON_IsObject(obj)) {
            cJSON* nonce = cJSON_GetObjectItemCaseSensitive(obj, "nonce");
            cJSON* data  = cJSON_GetObjectItemCaseSensitive(obj, "data");
            if (cJSON_IsString(nonce) && cJSON_IsString(data)) {
                out.kind  = kind->valuestring;
                out.nonce = nonce->valuestring;
                out.data  = data->valuestring;
                out.tags.clear();
                cJSON* tags = cJSON_GetObjectItemCaseSensitive(obj, "tags");
                if (cJSON_IsArray(tags)) {
                    cJSON* row = nullptr;
                    cJSON_ArrayForEach(row, tags) {
                        if (!cJSON_IsArray(row)) continue;
                        std::vector<std::string> vec;
                        cJSON* v = nullptr;
                        cJSON_ArrayForEach(v, row) {
                            if (cJSON_IsString(v))
                                vec.emplace_back(v->valuestring);
                        }
                        if (!vec.empty())
                            out.tags.push_back(std::move(vec));
                    }
                }
                ok = true;
            }
        }
    }
    cJSON_Delete(root);
    return ok;
}

} // namespace cashu
