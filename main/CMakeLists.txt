idf_component_register(SRCS "nucula.cpp" "commands_common.cpp" "commands_wallet.cpp" "commands_seed.cpp" "commands_system.cpp" "crypto.c" "crypto_bls.c" "crypto_test.c" "cashu_json.cpp"
                            "cashu_cbor.cpp" "wifi.c" "http.c" "hex.c" "keyset.cpp"
                            "wallet.cpp" "wallet_nvs.cpp" "wallet_identity.cpp"
                            "wallet_keysets.cpp" "wallet_blind.cpp" "wallet_flows.cpp"
                            "selftest.cpp" "wallet_selftest.cpp"
                            "console.cpp" "display.cpp" "nfc.cpp" "ndef.cpp" "keypad.c" "i2c_bus.c"
                            "bip39.c" "nut10.cpp" "base64url.cpp" "wallet_store.cpp" "ui.cpp"
                            "unit.cpp" "web_setup.cpp"
                    INCLUDE_DIRS "."
                    REQUIRES secp256k1 pn7160
                    PRIV_REQUIRES log mbedtls esp_timer json cbor esp_wifi esp_event
                                 esp_netif nvs_flash esp_http_client
                                 esp_driver_usb_serial_jtag vfs
                                 esp_driver_gpio driver esp_app_format)

# Tight inner-loop codecs and display primitives get -O2 on top of -Os;
# template-heavy C++ translation units stay at -Os to fit the 16 KB flash cache.
set_source_files_properties("crypto.c" "hex.c" "base64url.cpp"
                            "display.cpp" "bip39.c"
                            PROPERTIES COMPILE_OPTIONS "-O2")
