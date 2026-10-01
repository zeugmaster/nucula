/* Host-only differential test. Compile with the portable 32-bit blst build. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <blst.h>
#include <blst_aux.h>

static size_t fail_after = (size_t)-1;
static size_t fail_once = (size_t)-1;
static void *checked_malloc(size_t n) {
    if (!fail_once) { fail_once=(size_t)-1;return NULL; }
    if (fail_once!=(size_t)-1) --fail_once;
    if (!fail_after) return NULL;
    if (fail_after != (size_t)-1) --fail_after;
    return malloc(n);
}
static void *checked_calloc(size_t n, size_t size) {
    if (!fail_once) { fail_once=(size_t)-1;return NULL; }
    if (fail_once!=(size_t)-1) --fail_once;
    if (!fail_after) return NULL;
    if (fail_after != (size_t)-1) --fail_after;
    return calloc(n, size);
}
#define malloc checked_malloc
#define calloc checked_calloc
#include "../main/crypto_bls.c"
#undef malloc
#undef calloc

int cashu_nut13_hmac(const unsigned char *seed, size_t seed_len,
                    const char *id, uint32_t counter, unsigned char type,
                    const unsigned char *suffix, size_t suffix_len,
                    unsigned char out[32]) {
    (void)seed; (void)seed_len; (void)id; (void)counter; (void)type;
    (void)suffix; (void)suffix_len; (void)out;
    abort(); /* Derivation is outside this test's scope. */
}

int main(void) {
    enum {N = 64};
    unsigned char keys[N*96], signatures[N*48], messages[N][33];
    const unsigned char *secrets[N];
    size_t lengths[N];
    unsigned cases = 0;
    for (unsigned shape = 0; shape < 3; shape++) {
        for (unsigned i = 0; i < N; i++) {
            for (unsigned j = 0; j < 33; j++) messages[i][j] = (unsigned char)(i*71+j*53+shape);
            secrets[i] = messages[i]; lengths[i] = 33;
            unsigned char scalar[32] = {0};
            scalar[0] = 2+(shape == 0 ? i%17 : shape == 1 ? i%3 : 0);
            blst_p2 key;
            blst_p2_mult(&key, blst_p2_generator(), scalar, 256);
            blst_p2_compress(keys+96*i, &key);
            blst_p1 y, sig;
            hash_to_g1(&y, secrets[i], lengths[i]);
            blst_p1_mult(&sig, &y, scalar, 256);
            blst_p1_compress(signatures+48*i, &sig);
        }
        #if defined(NUCULA_WORKSPACE_TEST)
        static const unsigned counts[] = {1,10,17};
        static const unsigned flags[] = {1,17,247,8047};
        static const unsigned capacities[] = {1,4,11,16};
        #elif defined(NUCULA_CACHE_TEST)
        static const unsigned counts[] = {1,10,16,17,32,33,64};
        static const unsigned flags[] = {8047};
        static const unsigned capacities[] = {11};
        #else
        #ifdef NUCULA_GLV_TEST
        static const unsigned counts[] = {1,10,17};
#else
        static const unsigned counts[] = {1,2,10,11,16,17,32};
#endif
        static const unsigned flags[] = {1,3,5,9,17,33,43,47,51,55,119,247,265,311,375,495,879,887,1007,4975,8047};
        #ifdef NUCULA_GLV_TEST
        static const unsigned capacities[] = {4,11};
#else
        static const unsigned capacities[] = {1,4,8,11,16};
#endif
        #endif
        for (size_t count = 0; count < sizeof(counts)/sizeof(counts[0]); count++) {
            size_t n = counts[count];
            if (!bls_verify_proofs_reference(NULL,n,keys,signatures,secrets,lengths)) return 1;
            for (size_t f = 0; f < sizeof(flags)/sizeof(flags[0]); f++) {
#ifdef NUCULA_GLV_TEST
                if (!(flags[f] & 256)) continue;
#endif
                for (size_t c = 0; c < sizeof(capacities)/sizeof(capacities[0]); c++) {
                    cashu_bls_configure(flags[f],capacities[c]);
                    cashu_bls_clear_key_cache();
                    if (!bls_verify_proofs(NULL,n,keys,signatures,secrets,lengths)) {
                        fprintf(stderr,"valid failed shape=%u n=%zu flags=%u cap=%u\n",shape,n,flags[f],capacities[c]);return 2;
                    }
                    messages[n-1][15] ^= 1;
                    if (bls_verify_proofs(NULL,n,keys,signatures,secrets,lengths)) return 3;
                    messages[n-1][15] ^= 1;
                    cases += 2;
                }
            }
        }
        printf("shape %u passed\n",shape);fflush(stdout);
    }
    cashu_bls_configure(55,11);
    for (size_t allocation = 0; allocation < 3; allocation++) {
        fail_after = allocation;
        if (bls_verify_proofs(NULL,10,keys,signatures,secrets,lengths)) return 4;
    }
    fail_after = (size_t)-1;
    for (size_t failure=1;failure<3;failure++) {
        fail_once=failure;
        if (!bls_verify_proofs(NULL,10,keys,signatures,secrets,lengths)) return 14;
        fail_once=failure;messages[9][15]^=1;
        if (bls_verify_proofs(NULL,10,keys,signatures,secrets,lengths)) return 15;
        messages[9][15]^=1;
    }
    fail_once=(size_t)-1;
    if (!bls_verify_proofs(NULL,10,keys,signatures,secrets,lengths)) return 5;
    keys[0] ^= 0x80;
    if (bls_verify_proofs(NULL,10,keys,signatures,secrets,lengths)) return 6;
    keys[0] ^= 0x80;
    if (bls_verify_proofs(NULL,(size_t)-1,keys,signatures,secrets,lengths)) return 7;
    unsigned char rs[N*32], blinded[N*48], combined[N*48];
    for (size_t i = 0; i < N; i++) {
        for (size_t j = 0; j < 32; j++) rs[32*i+j] = (unsigned char)(53*i+79*j);
        rs[32*i] = 0x40;
        blst_scalar r;
        blst_p1_affine affine;
        blst_p1 point, product;
        if (!scalar_from_be_checked(&r, rs+32*i) || !validate_g1(&affine, signatures+48*i)) return 8;
        blst_p1_from_affine(&point, &affine);p1_mul(&product, &point, &r);
        blst_p1_compress(blinded+48*i, &product);
    }
    cashu_bls_configure(8047,11);
    if (!cashu_bls_unblind_verify(N,keys,blinded,rs,secrets,lengths,combined) || memcmp(combined,signatures,sizeof(combined))) return 9;
    messages[0][0]^=1;
    if (cashu_bls_unblind_verify(N,keys,blinded,rs,secrets,lengths,combined)) return 10;
    for (size_t i=0;i<sizeof(combined);i++) if (combined[i]) return 11;
    messages[0][0]^=1;
    memcpy(combined,blinded,sizeof(combined));
    if (!cashu_bls_unblind_verify(N,keys,combined,rs,secrets,lengths,combined) || memcmp(combined,signatures,sizeof(combined))) return 12;
    messages[N-1][0]^=1;
    if(cashu_bls_unblind_verify(N,keys,blinded,rs,secrets,lengths,combined))return 17;
    for(size_t i=0;i<sizeof(combined);i++)if(combined[i])return 18;
    messages[N-1][0]^=1;
    memset(rs,0,32);
    if (cashu_bls_unblind_verify(N,keys,blinded,rs,secrets,lengths,combined)) return 13;
    /* Different-length secrets cannot hit a cached mapping. */
    lengths[0]=32;
    if (bls_verify_proofs(NULL,1,keys,signatures,secrets,lengths)) return 16;
    printf("PASS: combined unblind/verify n=64, chunk boundaries, full-width factors, aliased buffers, tamper, changed length and zero-factor rejection\n");
    printf("PASS: %u differential valid/tampered cases, cache mutation, allocation failures, count overflow\n",cases);
    return 0;
}
