set(S ${CMAKE_CURRENT_SOURCE_DIR}/libsecp256k1)

idf_component_register(
    SRCS "secp256k1_cashu.c"
         "${S}/src/precomputed_ecmult.c"
         "${S}/src/precomputed_ecmult_gen.c"
    INCLUDE_DIRS "${S}/include" "${CMAKE_CURRENT_SOURCE_DIR}"
    PRIV_INCLUDE_DIRS "${S}/src" "${CMAKE_CURRENT_SOURCE_DIR}"
    PRIV_REQUIRES mbedtls
    LDFRAGMENTS "linker.lf"
)

# COMB_BLOCKS=2 / COMB_TEETH=5 keeps the generator comb table at 2 KB (down
# from 22.5 KB), so it fits inside the ESP32-C3's 16 KB unified flash cache
# instead of evicting the cache on every ecmult_gen step.
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    ENABLE_MODULE_SCHNORRSIG=1
    ENABLE_MODULE_EXTRAKEYS=1
    ECMULT_WINDOW_SIZE=8
    COMB_BLOCKS=2
    COMB_TEETH=5
)

# -Os keeps secp256k1 compact inside ESP32-C3's 16 KB unified flash cache
# while linker.lf pins the hot 10x26 field inner loops (fe_mul/fe_sqr) in IRAM.
target_compile_options(${COMPONENT_LIB} PRIVATE -Os -Wno-unused-function)