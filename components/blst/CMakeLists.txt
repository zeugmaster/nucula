set(B ${CMAKE_CURRENT_SOURCE_DIR}/blst)

set(NUCULA_MPI_OPT O3 CACHE STRING "MPI driver compiler optimization")
set(NUCULA_BLST_OPT O3 CACHE STRING "blst compiler optimization")
set(NUCULA_CRYPTO_LTO OFF CACHE BOOL "Link-time optimize the two crypto libraries")
set(NUCULA_BLS_LTO OFF CACHE BOOL "LTO BLS caller and arithmetic only, preserving MPI placement")
set(NUCULA_MPI_IRAM ON CACHE BOOL "Place MPI driver in instruction RAM")
set(NUCULA_MPI_HOT_ONLY ON CACHE BOOL "Keep infrequent MPI/calibration routines in flash")
set(NUCULA_RV32_COPY OFF CACHE BOOL "Build the experimental fixed-width MMIO assembly transfers")
set(blst_linker)
if(NUCULA_MPI_IRAM)
    if(NUCULA_MPI_HOT_ONLY)
        list(APPEND blst_linker "hot_iram.lf")
    else()
        list(APPEND blst_linker "iram.lf")
    endif()
endif()
idf_component_register(
    LDFRAGMENTS ${blst_linker}
    SRCS "${B}/src/server.c"
         "port/blst_mpi.c"
         "port/blst_sha.c"
    INCLUDE_DIRS "${B}/bindings" "port/include"
    PRIV_INCLUDE_DIRS "${B}/src"
    # esp_crypto_mpi_enable_periph_clk lives in esp_security; the lock and
    # HAL come from common-required components (esp_hw_support, hal, soc).
    PRIV_REQUIRES esp_security mbedtls
)

# rv32 has no blst assembly: __BLST_NO_ASM__ selects the portable C path in
# no_asm.h (the define blst's own build.rs uses for non-x86_64/aarch64).
target_compile_definitions(${COMPONENT_LIB} PRIVATE __BLST_NO_ASM__)
target_compile_definitions(${COMPONENT_LIB} PUBLIC NUCULA_RV32_COPY=$<BOOL:${NUCULA_RV32_COPY}>)

# -O3: measured on-device against -O2 — see the commit message for numbers.
# (secp256k1's -Os-beats-O2 icache result, eb53f21, does NOT repeat here.)
target_compile_options(${COMPONENT_LIB} PRIVATE -${NUCULA_BLST_OPT} -fno-strict-aliasing -Wno-unused-function)

if(NUCULA_CRYPTO_LTO)
    target_compile_options(${COMPONENT_LIB} PRIVATE -flto)
    target_link_options(${COMPONENT_LIB} INTERFACE -flto)
endif()

set_source_files_properties("port/blst_mpi.c" PROPERTIES COMPILE_OPTIONS "-${NUCULA_MPI_OPT}")
if(NUCULA_BLS_LTO)
    set_source_files_properties("${B}/src/server.c" PROPERTIES COMPILE_OPTIONS "-flto")
    target_link_options(${COMPONENT_LIB} INTERFACE -flto -O3)
endif()
