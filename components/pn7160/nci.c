#include "nci.h"
#include "esp_log.h"
#include "esp_check.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>

static const char *TAG = "nci";

// Single waiter (the nfc task) parked in nci_wait_for_irq.
static TaskHandle_t s_irq_waiter;

// The PN7160 holds IRQ HIGH while data is pending (level-driven), so the
// ISR must quench the interrupt itself; nci_wait_for_irq re-enables it.
static void IRAM_ATTR nci_irq_isr(void *arg)
{
    (void)arg;
    gpio_intr_disable(PN7160_IRQ_PIN);
    BaseType_t woken = pdFALSE;
    if (s_irq_waiter)
        vTaskNotifyGiveFromISR(s_irq_waiter, &woken);
    portYIELD_FROM_ISR(woken);
}

static void log_hex(const char *prefix, const uint8_t *data, uint32_t len)
{
    char buf[NCI_MAX_FRAME_SIZE * 3 + 1];
    uint32_t pos = 0;
    for (uint32_t i = 0; i < len && pos < sizeof(buf) - 4; i++)
        pos += snprintf(&buf[pos], sizeof(buf) - pos, "%02X ", data[i]);
    ESP_LOGD(TAG, "%s [%lu]: %s", prefix, (unsigned long)len, buf);
}

esp_err_t nci_init(nci_context_t *ctx, i2c_master_bus_handle_t bus)
{
    if (ctx->i2c_dev != NULL) {
        ESP_LOGI(TAG, "device already added, HW reset only");
        goto hw_reset;
    }

    memset(ctx, 0, sizeof(nci_context_t));
    ctx->i2c_bus = bus;
    if (ctx->i2c_bus == NULL) {
        ESP_LOGW(TAG, "no I2C bus");
        return ESP_ERR_INVALID_ARG;
    }

    // IRQ: input with pull-down (PN7160 drives HIGH when data ready).
    // Level-triggered interrupt; installed disabled, armed only while a
    // task waits in nci_wait_for_irq.
    gpio_config_t irq_cfg = {
        .pin_bit_mask   = (1ULL << PN7160_IRQ_PIN),
        .mode           = GPIO_MODE_INPUT,
        .pull_up_en     = GPIO_PULLUP_DISABLE,
        .pull_down_en   = GPIO_PULLDOWN_ENABLE,
        .intr_type      = GPIO_INTR_HIGH_LEVEL,
    };
    ESP_RETURN_ON_ERROR(gpio_config(&irq_cfg), TAG, "IRQ gpio_config");

    esp_err_t isr_err = gpio_install_isr_service(0);
    if (isr_err != ESP_OK && isr_err != ESP_ERR_INVALID_STATE)  // may exist already
        ESP_RETURN_ON_ERROR(isr_err, TAG, "gpio_install_isr_service");
    ESP_RETURN_ON_ERROR(gpio_isr_handler_add(PN7160_IRQ_PIN, nci_irq_isr, NULL),
                        TAG, "gpio_isr_handler_add");
    gpio_intr_disable(PN7160_IRQ_PIN);

    // VEN + DWL: outputs
    gpio_config_t out_cfg = {
        .pin_bit_mask   = (1ULL << PN7160_VEN_PIN) | (1ULL << PN7160_DWL_PIN),
        .mode           = GPIO_MODE_OUTPUT,
        .pull_up_en     = GPIO_PULLUP_DISABLE,
        .pull_down_en   = GPIO_PULLDOWN_DISABLE,
        .intr_type      = GPIO_INTR_DISABLE,
    };
    ESP_RETURN_ON_ERROR(gpio_config(&out_cfg), TAG, "out gpio_config");

    // DWL low = NCI mode (not firmware-download mode)
    gpio_set_level(PN7160_DWL_PIN, 0);

hw_reset:
    // VEN power cycle
    gpio_set_level(PN7160_VEN_PIN, 1);
    vTaskDelay(pdMS_TO_TICKS(10));
    gpio_set_level(PN7160_VEN_PIN, 0);
    vTaskDelay(pdMS_TO_TICKS(50));
    gpio_set_level(PN7160_VEN_PIN, 1);
    vTaskDelay(pdMS_TO_TICKS(50));

    ESP_LOGI(TAG, "PN7160 HW reset done (IRQ=%d)", gpio_get_level(PN7160_IRQ_PIN));

    // Probe before adding the device so absent hardware fails fast and
    // callers can tell "not there" from "there but misbehaving".
    if (i2c_master_probe(ctx->i2c_bus, PN7160_I2C_ADDR, 50) != ESP_OK) {
        ESP_LOGW(TAG, "no PN7160 at 0x%02X", PN7160_I2C_ADDR);
        return ESP_ERR_NOT_FOUND;
    }

    if (ctx->i2c_dev == NULL) {
        i2c_device_config_t dev_cfg = {
            .dev_addr_length = I2C_ADDR_BIT_LEN_7,
            .device_address  = PN7160_I2C_ADDR,
            .scl_speed_hz    = 100000,
        };
        ESP_RETURN_ON_ERROR(i2c_master_bus_add_device(ctx->i2c_bus, &dev_cfg, &ctx->i2c_dev),
                            TAG, "i2c_master_bus_add_device");
    }
    return ESP_OK;
}

bool nci_wait_for_irq(uint32_t timeout_ms)
{
    // TODO(hw-verify): interrupt-driven wait replaces the 10 ms GPIO poll
    // (~100 wakeups/s for the whole 120 s payment window, up to 10 ms
    // added latency per NCI exchange). Validate against a PN7160.
    if (gpio_get_level(PN7160_IRQ_PIN))
        return true;

    s_irq_waiter = xTaskGetCurrentTaskHandle();
    ulTaskNotifyTake(pdTRUE, 0);            // clear any stale notification
    gpio_intr_enable(PN7160_IRQ_PIN);       // level-trigger closes the race:
                                            // line already high -> ISR fires now
    uint32_t got = ulTaskNotifyTake(pdTRUE,
                                    timeout_ms > 0 ? pdMS_TO_TICKS(timeout_ms)
                                                   : portMAX_DELAY);
    gpio_intr_disable(PN7160_IRQ_PIN);
    s_irq_waiter = NULL;
    return got > 0 || gpio_get_level(PN7160_IRQ_PIN);
}

static esp_err_t nci_wait_and_read(nci_context_t *ctx, uint32_t timeout_ms)
{
    if (!nci_wait_for_irq(timeout_ms)) {
        ESP_LOGE(TAG, "IRQ timeout (%lums)", (unsigned long)timeout_ms);
        return ESP_ERR_TIMEOUT;
    }
    return nci_read(ctx, ctx->rx_buf, &ctx->rx_len);
}

esp_err_t nci_write(nci_context_t *ctx, const uint8_t *data, uint32_t len)
{
    log_hex("TX>>", data, len);
    esp_err_t ret = i2c_master_transmit(ctx->i2c_dev, data, len, 500);
    if (ret != ESP_OK)
        ESP_LOGE(TAG, "I2C write failed: %s", esp_err_to_name(ret));
    return ret;
}

esp_err_t nci_read(nci_context_t *ctx, uint8_t *data, uint32_t *len)
{
    // Read 3-byte NCI header
    uint8_t hdr[3];
    esp_err_t ret = i2c_master_receive(ctx->i2c_dev, hdr, 3, 500);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "I2C read header failed: %s", esp_err_to_name(ret));
        *len = 0;
        return ret;
    }

    data[0] = hdr[0];
    data[1] = hdr[1];
    data[2] = hdr[2];
    *len = 3;

    uint8_t payload_len = hdr[2];
    if (payload_len > 0) {
        ret = i2c_master_receive(ctx->i2c_dev, &data[3], payload_len, 500);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "I2C read payload failed: %s", esp_err_to_name(ret));
            return ret;
        }
        *len = 3 + payload_len;
    }

    log_hex("RX<<", data, *len);
    return ESP_OK;
}

esp_err_t nci_transceive(nci_context_t *ctx, const uint8_t *cmd, uint32_t cmd_len,
                         uint32_t timeout_ms)
{
    esp_err_t ret = nci_write(ctx, cmd, cmd_len);
    if (ret != ESP_OK) return ret;
    ctx->rx_len = 0;
    return nci_wait_and_read(ctx, timeout_ms > 0 ? timeout_ms : 1000);
}

esp_err_t nci_core_reset(nci_context_t *ctx)
{
    const uint8_t cmd[] = {0x20, 0x00, 0x01, 0x01};
    ESP_LOGI(TAG, "CORE_RESET");
    esp_err_t ret = nci_transceive(ctx, cmd, sizeof(cmd), 1000);
    if (ret != ESP_OK) return ret;

    if (ctx->rx_len < 4 || ctx->rx_buf[0] != 0x40 || ctx->rx_buf[1] != 0x00) {
        ESP_LOGE(TAG, "Invalid CORE_RESET_RSP");
        return ESP_ERR_INVALID_RESPONSE;
    }

    // NCI 2.0: CORE_RESET_NTF follows RSP
    if (nci_wait_for_irq(200)) {
        nci_read(ctx, ctx->rx_buf, &ctx->rx_len);
        if (ctx->rx_buf[0] == 0x60 && ctx->rx_buf[1] == 0x00)
            ESP_LOGI(TAG, "CORE_RESET_NTF ok");
        else if (ctx->rx_buf[0] == 0x60 && ctx->rx_buf[1] == 0x07)
            ESP_LOGW(TAG, "CORE_GENERIC_ERROR_NTF (anti-tearing)");
        else
            ESP_LOGI(TAG, "post-reset NTF %02X %02X", ctx->rx_buf[0], ctx->rx_buf[1]);
    }
    return ESP_OK;
}

esp_err_t nci_core_init(nci_context_t *ctx)
{
    // NCI 2.0 CORE_INIT requires 2 parameter bytes
    const uint8_t cmd[] = {0x20, 0x01, 0x02, 0x00, 0x00};
    ESP_LOGI(TAG, "CORE_INIT");

    // Flush any stale NTFs from reset
    for (int i = 0; i < 3; i++) {
        if (nci_wait_for_irq(30))
            nci_read(ctx, ctx->rx_buf, &ctx->rx_len);
        else
            break;
    }

    esp_err_t ret = nci_transceive(ctx, cmd, sizeof(cmd), 1000);
    if (ret != ESP_OK) return ret;

    if (ctx->rx_len < 4 || ctx->rx_buf[0] != 0x40 || ctx->rx_buf[1] != 0x01 ||
        ctx->rx_buf[3] != 0x00) {
        ESP_LOGE(TAG, "CORE_INIT_RSP bad (status=0x%02X)",
                 ctx->rx_len > 3 ? ctx->rx_buf[3] : 0xFF);
        return ESP_ERR_INVALID_RESPONSE;
    }

    ESP_LOGI(TAG, "CORE_INIT ok");

    // TC1 probe: PN7160 needs TC1=0x00 for plain ISO-DEP (no DID, no NAD)
    const uint8_t set_tc1[] = {0x20, 0x02, 0x04, 0x01, 0x52, 0x01, 0x00};
    nci_transceive(ctx, set_tc1, sizeof(set_tc1), 500);

    return ESP_OK;
}

esp_err_t nci_configure_settings(nci_context_t *ctx)
{
    ESP_LOGI(TAG, "configure settings");
    esp_err_t ret;

    // TOTAL_DURATION
    const uint8_t total_dur[] = {0x20, 0x02, 0x05, 0x01, 0x00, 0x02, 0xFE, 0x01};
    ret = nci_transceive(ctx, total_dur, sizeof(total_dur), 500);
    if (ret != ESP_OK) return ret;

    // NXP standby enable
    const uint8_t standby[] = {0x2F, 0x00, 0x01, 0x01};
    ret = nci_transceive(ctx, standby, sizeof(standby), 500);
    if (ret != ESP_OK) return ret;

    // TAG_DETECTOR_CFG
    const uint8_t tag_det[] = {0x20, 0x02, 0x05, 0x01, 0xA0, 0x40, 0x01, 0x00};
    ret = nci_transceive(ctx, tag_det, sizeof(tag_det), 500);
    if (ret != ESP_OK) return ret;

    // NFC Forum Profile (helps iOS)
    const uint8_t nfc_profile[] = {0x20, 0x02, 0x05, 0x01, 0xA0, 0x44, 0x01, 0x01};
    nci_transceive(ctx, nfc_profile, sizeof(nfc_profile), 500);

    // LI_A_RATS_TB1: FWI=7 (77 ms), SFGI=0
    const uint8_t tb1[] = {0x20, 0x02, 0x04, 0x01, 0x50, 0x01, 0x70};
    ret = nci_transceive(ctx, tb1, sizeof(tb1), 500);
    if (ret != ESP_OK) return ret;

    // LA_HIST_BY: historical bytes for T4T ATS
    const uint8_t hist[] = {0x20, 0x02, 0x06, 0x01, 0x59, 0x03, 0x80, 0x77, 0x80};
    ret = nci_transceive(ctx, hist, sizeof(hist), 500);
    if (ret != ESP_OK) return ret;

    ESP_LOGI(TAG, "settings ok");
    return ESP_OK;
}

esp_err_t nci_configure_cardemu_mode(nci_context_t *ctx)
{
    ESP_LOGI(TAG, "configure card-emulation mode");
    esp_err_t ret;

    // RF_DISCOVER_MAP: ISO-DEP → LISTEN, ISO-DEP interface
    const uint8_t disc_map[] = {0x21, 0x00, 0x04, 0x01, 0x04, 0x02, 0x02};
    ret = nci_transceive(ctx, disc_map, sizeof(disc_map), 500);
    if (ret != ESP_OK) return ret;
    if (ctx->rx_buf[0] != 0x41 || ctx->rx_buf[1] != 0x00 || ctx->rx_buf[3] != 0x00) {
        ESP_LOGE(TAG, "RF_DISCOVER_MAP failed");
        return ESP_ERR_INVALID_RESPONSE;
    }

    // LA_SEL_INFO (SAK) = 0x20: ISO-DEP capable T4T
    const uint8_t sel_rsp[] = {0x20, 0x02, 0x04, 0x01, 0x32, 0x01, 0x20};
    ret = nci_transceive(ctx, sel_rsp, sizeof(sel_rsp), 500);
    if (ret != ESP_OK) return ret;
    if (ctx->rx_buf[0] != 0x40 || ctx->rx_buf[1] != 0x02 || ctx->rx_buf[3] != 0x00) {
        ESP_LOGE(TAG, "SET LA_SEL_INFO failed");
        return ESP_ERR_INVALID_RESPONSE;
    }

    // RF_SET_LISTEN_MODE_ROUTING: ISO-DEP → DH (device host)
    const uint8_t routing[] = {
        0x21, 0x01, 0x07, 0x00, 0x01,
        0x01, 0x03, 0x00, 0x01, 0x04
    };
    ret = nci_transceive(ctx, routing, sizeof(routing), 500);
    if (ret != ESP_OK) return ret;
    if (ctx->rx_buf[0] != 0x41 || ctx->rx_buf[1] != 0x01 || ctx->rx_buf[3] != 0x00) {
        ESP_LOGE(TAG, "RF_SET_ROUTING failed");
        return ESP_ERR_INVALID_RESPONSE;
    }

    ESP_LOGI(TAG, "card-emu mode ok");
    return ESP_OK;
}

esp_err_t nci_start_discovery_cardemu(nci_context_t *ctx)
{
    ESP_LOGI(TAG, "start discovery");

    // RF_DISCOVER: NFC-A passive listen
    const uint8_t discover[] = {0x21, 0x03, 0x03, 0x01, 0x80, 0x01};
    memcpy(ctx->discovery_cmd, discover, sizeof(discover));
    ctx->discovery_cmd_len = sizeof(discover);

    esp_err_t ret = nci_transceive(ctx, discover, sizeof(discover), 500);
    if (ret != ESP_OK) return ret;

    if (ctx->rx_buf[0] != 0x41 || ctx->rx_buf[1] != 0x03 || ctx->rx_buf[3] != 0x00) {
        ESP_LOGE(TAG, "RF_DISCOVER failed (status=0x%02X)",
                 ctx->rx_len > 3 ? ctx->rx_buf[3] : 0xFF);
        return ESP_ERR_INVALID_RESPONSE;
    }

    ESP_LOGI(TAG, "listening for NFC readers");
    return ESP_OK;
}

esp_err_t nci_setup_cardemu(nci_context_t *ctx, i2c_master_bus_handle_t bus)
{
    esp_err_t ret;
    if ((ret = nci_init(ctx, bus))             != ESP_OK) return ret;
    if ((ret = nci_core_reset(ctx))            != ESP_OK) return ret;
    if ((ret = nci_core_init(ctx))             != ESP_OK) return ret;
    if ((ret = nci_configure_settings(ctx))    != ESP_OK) return ret;
    if ((ret = nci_configure_cardemu_mode(ctx)) != ESP_OK) return ret;
    if ((ret = nci_start_discovery_cardemu(ctx)) != ESP_OK) return ret;
    return ESP_OK;
}
