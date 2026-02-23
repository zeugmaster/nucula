idf_component_register(SRCS "nucula.cpp" "crypto.c" "crypto_test.c" "cashu_json.cpp" "wifi.c"
                    INCLUDE_DIRS "."
                    REQUIRES secp256k1
                    PRIV_REQUIRES log mbedtls esp_timer json esp_wifi esp_event esp_netif nvs_flash)
