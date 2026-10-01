#pragma once
#include <blst.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Local bounded-memory extensions. Scratch must be naturally aligned.
 * Inputs to these arithmetic functions must already be validated. */
size_t blst_miller_workspace_sizeof(size_t capacity);
int blst_miller_loop_workspace(blst_fp12 *out,
                              const blst_p2_affine *const qs[],
                              const blst_p1_affine *const ps[], size_t n,
                              void *scratch, size_t capacity);
int blst_miller_loop_prepared_workspace(blst_fp12 *out,
                              const blst_p2_affine *const qs[],
                              const blst_p1_affine *const ps[],
                              const void *const prepared[], size_t n,
                              void *scratch, size_t capacity);
/* Public scalar < r, validated subgroup point; output scalars are 16B LE. */
void blst_p1_glv_expand(blst_p1_affine out[2], byte split[32],
                        const blst_p1_affine *point, const byte scalar[32]);
void blst_p1s_mult_bucket(blst_p1 *out, const blst_p1_affine *const points[],
                         size_t n, const byte *const scalars[], size_t nbits,
                         void *scratch);
size_t blst_p1s_window_workspace_sizeof(size_t n, size_t wbits);
int blst_p1s_precompute_window_workspace(blst_p1_affine *table, size_t wbits,
                                        const blst_p1_affine *const points[],
                                        size_t n, void *scratch, size_t bytes);
#ifdef __cplusplus
}
#endif
