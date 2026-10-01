#pragma once
#include <secp256k1.h>
#ifdef __cplusplus
extern "C" {
#endif
int nutroot_current_run_tests(const secp256k1_context *ctx);
void nutroot_current_benchmark(const secp256k1_context *ctx);
#ifdef __cplusplus
}
#endif
