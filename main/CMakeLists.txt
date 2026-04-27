idf_component_register(SRCS "nucula.cpp" "crypto.c" "crypto_test.c" "cashu_json.cpp"
                            "cashu_cbor.cpp" "wifi.c" "http.c" "hex.c" "wallet.cpp"
                            "console.cpp" "display.cpp" "nfc.cpp" "ndef.cpp" "keypad.c"
                            "bip39.c" "nut10.cpp"
                    INCLUDE_DIRS "."
                    REQUIRES secp256k1 pn7160
                    PRIV_REQUIRES log mbedtls esp_timer json cbor esp_wifi esp_event
                                 esp_netif nvs_flash esp_http_client
                                 esp_driver_usb_serial_jtag vfs
                                 esp_driver_gpio driver)
