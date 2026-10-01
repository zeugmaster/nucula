idf_component_register(SRCS "nucula.cpp" "crypto.c" "crypto_bls.c" "crypto_test.c"
                            "crypto_bls_test.c" "crypto_concurrency_test.c" "nutroot.c" "nutroot_prepare.c" "nutroot_test.c" "nutroot_current_test.c" "cashu_json.cpp"
                            "cashu_cbor.cpp" "wifi.c" "http.c" "hex.c" "wallet.cpp" "keyset.cpp"
                            "console.cpp" "display.cpp" "nfc.cpp" "ndef.cpp" "keypad.c" "i2c_bus.c"
                            "bip39.c" "nut10.cpp" "base64url.cpp" "wallet_store.cpp" "ui.cpp"
                            "unit.cpp"
                    INCLUDE_DIRS "."
                    REQUIRES secp256k1 pn7160 blst
                    PRIV_REQUIRES log mbedtls esp_timer json cbor esp_wifi esp_event
                                 esp_netif nvs_flash esp_http_client
                                 esp_driver_usb_serial_jtag vfs
                                 esp_driver_gpio driver)

# Hot-path files get -O2 on top of the project-wide -Os.
set_source_files_properties("crypto.c" "hex.c" "cashu_cbor.cpp" "nutroot.c" "nutroot_prepare.c"
                            PROPERTIES COMPILE_OPTIONS "-O2")
set(NUCULA_BLS_CALLER_OPT Os CACHE STRING "BLS protocol caller compiler optimization")
set(bls_caller_options "-${NUCULA_BLS_CALLER_OPT}")
if(NUCULA_BLS_LTO)
    list(APPEND bls_caller_options -flto)
endif()
set_source_files_properties("crypto_bls.c" PROPERTIES COMPILE_OPTIONS "${bls_caller_options}")
set(NUCULA_Y_CACHE_SIZE 64 CACHE STRING "Number of deterministic hash-to-G1 mappings")
set(NUCULA_Y_CACHE_AFFINE ON CACHE BOOL "Store affine Y points to reduce cache RAM")
if(NOT NUCULA_Y_CACHE_SIZE MATCHES "^(16|32|64)$")
    message(FATAL_ERROR "NUCULA_Y_CACHE_SIZE must be 16, 32 or 64")
endif()
target_compile_definitions(${COMPONENT_LIB} PRIVATE NUCULA_Y_CACHE_SIZE=${NUCULA_Y_CACHE_SIZE}
                          NUCULA_Y_CACHE_AFFINE=$<BOOL:${NUCULA_Y_CACHE_AFFINE}>)
