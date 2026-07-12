#include "wallet_store.hpp"

#include <esp_log.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#define TAG "wallet_store"

static cashu::Wallet *s_wallets[MAX_MINTS] = {};
static secp256k1_context *s_ctx = nullptr;
static SemaphoreHandle_t s_mutex = nullptr;

bool wallet_store_init(secp256k1_context *ctx)
{
    s_ctx = ctx;
    s_mutex = xSemaphoreCreateRecursiveMutex();
    if (!s_mutex) {
        ESP_LOGE(TAG, "mutex create failed");
        return false;
    }

    for (int i = 0; i < MAX_MINTS; i++) {
        std::string url = cashu::Wallet::load_mint_url_for_slot(i);
        if (url.empty()) continue;
        auto *w = new cashu::Wallet(url, s_ctx, i);
        w->load_from_nvs();
        s_wallets[i] = w;
        ESP_LOGI(TAG, "restored wallet [%d] %s (%d keysets, %d proofs)",
                 i, url.c_str(), (int)w->keysets().size(),
                 (int)w->proofs().size());
    }
    return true;
}

secp256k1_context *wallet_store_ctx()
{
    return s_ctx;
}

void wallet_store_lock()
{
    if (s_mutex)
        xSemaphoreTakeRecursive(s_mutex, portMAX_DELAY);
}

void wallet_store_unlock()
{
    if (s_mutex)
        xSemaphoreGiveRecursive(s_mutex);
}

bool wallet_store_try_lock(uint32_t timeout_ms)
{
    if (!s_mutex)
        return true;
    return xSemaphoreTakeRecursive(s_mutex, pdMS_TO_TICKS(timeout_ms)) == pdTRUE;
}

cashu::Wallet *wallet_store_get(int slot)
{
    if (slot < 0 || slot >= MAX_MINTS)
        return nullptr;
    return s_wallets[slot];
}

cashu::Wallet *wallet_store_find(const char *mint_url)
{
    if (!mint_url)
        return nullptr;
    for (int i = 0; i < MAX_MINTS; i++)
        if (s_wallets[i] && s_wallets[i]->mint_url() == mint_url)
            return s_wallets[i];
    return nullptr;
}

cashu::Wallet *wallet_store_get_or_create(const std::string &mint_url)
{
    cashu::Wallet *w = wallet_store_find(mint_url.c_str());
    if (w)
        return w;

    int slot = -1;
    for (int i = 0; i < MAX_MINTS; i++)
        if (!s_wallets[i]) { slot = i; break; }
    if (slot < 0) {
        ESP_LOGE(TAG, "no free mint slots (max %d)", MAX_MINTS);
        return nullptr;
    }

    w = new cashu::Wallet(mint_url, s_ctx, slot);
    s_wallets[slot] = w;
    w->save_mint_url();
    ESP_LOGI(TAG, "added mint [%d]: %s", slot, mint_url.c_str());
    return w;
}

bool wallet_store_remove(int slot)
{
    cashu::Wallet *w = wallet_store_get(slot);
    if (!w)
        return false;
    w->erase_nvs();
    delete w;
    s_wallets[slot] = nullptr;
    return true;
}

void wallet_store_remove_all()
{
    for (int i = 0; i < MAX_MINTS; i++)
        wallet_store_remove(i);
}

int wallet_store_count()
{
    int n = 0;
    for (int i = 0; i < MAX_MINTS; i++)
        if (s_wallets[i]) n++;
    return n;
}

long long wallet_store_total_balance()
{
    long long total = 0;
    for (int i = 0; i < MAX_MINTS; i++)
        if (s_wallets[i]) total += s_wallets[i]->balance();
    return total;
}

int wallet_store_total_pending()
{
    int total = 0;
    for (int i = 0; i < MAX_MINTS; i++)
        if (s_wallets[i]) total += s_wallets[i]->pending_count();
    return total;
}
