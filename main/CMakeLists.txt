idf_component_register(SRCS "nucula.c"
                    INCLUDE_DIRS "."
                    REQUIRES secp256k1
                    PRIV_REQUIRES log)
