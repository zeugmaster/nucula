#include "nut10.hpp"
#include <cJSON.h>

namespace cashu {

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
