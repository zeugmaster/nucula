idf_component_register(SRCS "nucula.cpp" "crypto.c" "crypto_test.c"
                    INCLUDE_DIRS "."
                    REQUIRES secp256k1
                    PRIV_REQUIRES log mbedtls esp_timer)
