#ifndef CASHU_CRYPTO_TEST_H
#define CASHU_CRYPTO_TEST_H

#include "secp256k1.h"

int crypto_run_tests(const secp256k1_context *ctx);
void crypto_run_benchmark(const secp256k1_context *ctx);

#endif
