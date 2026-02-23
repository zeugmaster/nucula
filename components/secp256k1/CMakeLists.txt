set(S ${CMAKE_CURRENT_SOURCE_DIR}/libsecp256k1)

idf_component_register(
    SRCS "${S}/src/secp256k1.c"
         "${S}/src/precomputed_ecmult.c"
         "${S}/src/precomputed_ecmult_gen.c"
    INCLUDE_DIRS "${S}/include"
    PRIV_INCLUDE_DIRS "${S}/src" "${CMAKE_CURRENT_SOURCE_DIR}"
)

target_compile_definitions(${COMPONENT_LIB} PRIVATE
    ENABLE_MODULE_SCHNORRSIG=1
    ENABLE_MODULE_EXTRAKEYS=1
    ECMULT_GEN_PREC_BITS=4
    ECMULT_WINDOW_SIZE=8
)

target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-unused-function)