set(B ${CMAKE_CURRENT_SOURCE_DIR}/blst)

idf_component_register(
    SRCS "${B}/src/server.c"
         "port/blst_mpi.c"
    INCLUDE_DIRS "${B}/bindings" "port/include"
    PRIV_INCLUDE_DIRS "${B}/src"
    # esp_crypto_mpi_enable_periph_clk lives in esp_security; the lock and
    # HAL come from common-required components (esp_hw_support, hal, soc).
    PRIV_REQUIRES esp_security
)

# rv32 has no blst assembly: __BLST_NO_ASM__ selects the portable C path in
# no_asm.h (the define blst's own build.rs uses for non-x86_64/aarch64).
target_compile_definitions(${COMPONENT_LIB} PRIVATE __BLST_NO_ASM__)

# -O2 on top of the project-wide -Os, matching the mbedtls/crypto.c precedent.
# NOTE: bench before trusting this — secp256k1 measured SLOWER at -O2 on the
# C3 (icache thrashing, see eb53f21); blst may or may not behave the same.
target_compile_options(${COMPONENT_LIB} PRIVATE -O2 -Wno-unused-function)
