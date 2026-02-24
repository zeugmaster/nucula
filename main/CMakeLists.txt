idf_component_register(SRCS "nucula.cpp" "crypto.c" "crypto_test.c" "cashu_json.cpp"
                            "cashu_cbor.cpp" "wifi.c" "http.c" "hex.c" "wallet.cpp"
                            "console.cpp" "display.cpp"
                    INCLUDE_DIRS "."
                    REQUIRES secp256k1
                    PRIV_REQUIRES log mbedtls esp_timer json cbor esp_wifi esp_event
                                 esp_netif nvs_flash esp_http_client
                                 esp_driver_usb_serial_jtag vfs esp_lcd
                                 esp_driver_gpio esp_driver_ledc)
