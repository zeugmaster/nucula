#pragma once

/* blst's RV32 limb type and newlib's uint32_t use different C typedefs.
 * Byte-addressed hooks avoid incompatible declarations in its amalgamation. */
#define BLST_MPI_SQRT_EXP       (1u << 6)
#define BLST_MPI_INVERSE_EXP    (1u << 7)
#define BLST_MPI_SQUARE_CHAIN   (1u << 8)
#define BLST_MPI_SECP_SQRT      (1u << 9)
#define BLST_MPI_FP2_FUSED      (1u << 10)
#define BLST_MPI_FP2_PIPELINE   (1u << 11)


#define BLST_MPI_SHA256 (1u << 12)
#define BLST_MPI_SECP_SHA256 (1u << 13)
#define BLST_MPI_RV32_COPY (1u << 14)
#ifndef NUCULA_RV32_COPY
#define NUCULA_RV32_COPY 0
#endif
#ifdef __cplusplus
extern "C" {
#endif
int blst_esp_sha256_compress(unsigned int h[8], const void *input, __SIZE_TYPE__ blocks);
int blst_esp_sha256_blocks(unsigned int h[8], const void *input, __SIZE_TYPE__ blocks);
int blst_mpi_fp2(void *out, const void *a, const void *b, const void *modulus, unsigned int n0, int square);
int blst_mpi_fixed_exp_384(void *out, const void *in, unsigned which);
int blst_mpi_square_chain_384(void *out, const void *in, __SIZE_TYPE__ count);
#ifdef __cplusplus
}
#endif
