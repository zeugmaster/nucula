set(S ${CMAKE_CURRENT_SOURCE_DIR}/libsecp256k1)

set(NUCULA_SECP_HOT_IRAM OFF CACHE BOOL "Place field multiply/square in instruction RAM")
set(NUCULA_SECP_IRAM OFF CACHE BOOL "Place secp arithmetic in instruction RAM")
set(NUCULA_SECP_RAM_VERIFY OFF CACHE BOOL "Place public generator table in RAM")
set(NUCULA_SECP_RAM_SIGN OFF CACHE BOOL "Place secret generator table in RAM")
set(secp_linker)
if(NUCULA_SECP_IRAM)
    list(APPEND secp_linker "iram.lf")
elseif(NUCULA_SECP_HOT_IRAM)
    list(APPEND secp_linker "hot_iram.lf")
endif()
if(NUCULA_SECP_RAM_VERIFY)
    list(APPEND secp_linker "ram_verify.lf")
endif()
if(NUCULA_SECP_RAM_SIGN)
    list(APPEND secp_linker "ram_sign.lf")
endif()
idf_component_register(
    LDFRAGMENTS ${secp_linker}
    SRCS "port/secp256k1_port.c"
         "${S}/src/precomputed_ecmult.c"
         "${S}/src/precomputed_ecmult_gen.c"
    INCLUDE_DIRS "${S}/include" "port/include"
    PRIV_INCLUDE_DIRS "${S}/src" "${CMAKE_CURRENT_SOURCE_DIR}"
    PRIV_REQUIRES blst
)

set(NUCULA_SECP_BLOCKS 2 CACHE STRING "Secret generator comb blocks")
set(NUCULA_SECP_TEETH 5 CACHE STRING "Secret generator comb teeth")
set(NUCULA_SECP_WINDOW 12 CACHE STRING "Public verification generator window")
set(NUCULA_SECP_OPT Os CACHE STRING "secp256k1 compiler optimization")

target_compile_definitions(${COMPONENT_LIB} PRIVATE
    ENABLE_MODULE_SCHNORRSIG=1
    ENABLE_MODULE_EXTRAKEYS=1
    ENABLE_MODULE_ECDH=1
    COMB_BLOCKS=${NUCULA_SECP_BLOCKS}
    COMB_TEETH=${NUCULA_SECP_TEETH}
    ECMULT_WINDOW_SIZE=${NUCULA_SECP_WINDOW}
)

target_compile_options(${COMPONENT_LIB} PRIVATE -${NUCULA_SECP_OPT} -Wno-unused-function)


if(NUCULA_CRYPTO_LTO)
    target_compile_options(${COMPONENT_LIB} PRIVATE -flto)
    target_link_options(${COMPONENT_LIB} INTERFACE -flto)
endif()

# Keep the upstream submodule clean. Generate a one-function compression hook
# from its exact current source; fail configuration if the signature changes.
file(READ "${S}/src/hash_impl.h" secp_hash_source)
set(secp_hash_signature "static void secp256k1_sha256_transform(uint32_t* s, const unsigned char* buf) {")
string(FIND "${secp_hash_source}" "${secp_hash_signature}" secp_hash_position)
if(secp_hash_position EQUAL -1)
    message(FATAL_ERROR "Review the secp256k1 SHA compression hook after upstream changes")
endif()
string(REPLACE "${secp_hash_signature}" "${secp_hash_signature}
    if (blst_mpi_options() & BLST_MPI_SECP_SHA256) {
        unsigned int h[8];
        for (unsigned i=0;i<8;i++) h[i]=s[i];
        if (blst_esp_sha256_compress(h,buf,1)) {
            for (unsigned i=0;i<8;i++) s[i]=h[i];
            return;
        }
    }" secp_hash_source "${secp_hash_source}")
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/nucula_hash_impl.h" "${secp_hash_source}")
target_include_directories(${COMPONENT_LIB} PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")

set(NUCULA_SECP_WINDOW_A 4 CACHE STRING "Variable-base public verification window")
file(READ "${S}/src/ecmult_impl.h" secp_ecmult_source)
if(NOT NUCULA_SECP_WINDOW_A MATCHES "^[345]$")
    message(FATAL_ERROR "NUCULA_SECP_WINDOW_A must be 3, 4 or 5")
endif()
string(FIND "${secp_ecmult_source}" "define WINDOW_A 5" secp_window_position)
if(secp_window_position EQUAL -1)
    message(FATAL_ERROR "Review the secp256k1 verification window after upstream changes")
endif()
string(REPLACE "define WINDOW_A 5" "define WINDOW_A ${NUCULA_SECP_WINDOW_A}" secp_ecmult_source "${secp_ecmult_source}")
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/nucula_ecmult_impl.h" "${secp_ecmult_source}")
file(READ "${S}/src/secp256k1.c" secp_translation_unit)
string(REPLACE "#include \"ecmult_impl.h\"" "#include \"nucula_ecmult_impl.h\"" secp_translation_unit "${secp_translation_unit}")
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/nucula_secp_impl.c" "${secp_translation_unit}")
