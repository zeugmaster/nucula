#include "cashu_suite.h"
#include "crypto_bls.h"
#include <stdlib.h>
#include <limits.h>
#include <blst_esp.h>

#include <stdbool.h>
#include <string.h>

#include <blst.h>
#include <blst_aux.h>
#include <blst_mpi.h>
#include <mbedtls/sha256.h>
#ifdef ESP_PLATFORM
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#endif

/*
 * BLS12-381 crypto suite (keyset v3, version byte 0x02) over the vendored
 * blst component, per nuts PR #371:
 *
 *   - token points Y, B_, C_, C: compressed G1 (48 B); mint keys K:
 *     compressed G2 (96 B); scalars: 32-byte big-endian in (0, Fr order).
 *   - blinding is multiplicative: B_ = r*Y with Y = hash_to_G1(secret);
 *     unblinding C = r^-1 * C_. The mint key plays no role in unblinding
 *     (unlike secp's C = C_ - r*K), so unblind ignores K.
 *   - NUT-12 DLEQ is abolished: verification is the intrinsic pairing check
 *     e(C, g2) == e(Y, K), exposed through verify_proofs and batched over
 *     all n proofs via the Cashu_BLS_Batch_v1 Fiat-Shamir transcript.
 *
 * Every operation runs inside a blst_hw_acquire()/release() window so the
 * C3's RSA/MPI peripheral accelerates the field arithmetic (~4x); on other
 * targets those are no-ops and blst computes in software.
 */

/* NUT-00: hash-to-curve DST for the v3 G1 random-oracle suite. */
static const unsigned char DST[] = "CASHU_BLS12_381_G1_XMD:SHA-256_SSWU_RO_";
#define DST_LEN (sizeof(DST) - 1)

/* NUT-00: Fiat-Shamir transcript DST for batch verification. */
static const unsigned char BATCH_DST[] = "Cashu_BLS_Batch_v1";
#define BATCH_DST_LEN (sizeof(BATCH_DST) - 1)

static unsigned bls_options = CASHU_BLS_WORKSPACE | CASHU_BLS_KEY_CACHE |
    CASHU_BLS_GROUP_KEYS | CASHU_BLS_BUCKET_MSM | CASHU_BLS_BATCH_AFFINE |
    CASHU_BLS_PREPARED_GENERATOR | CASHU_BLS_GLV_MSM | CASHU_BLS_GROUP_MSM |
    CASHU_BLS_BATCH_INVERSE | CASHU_BLS_FAIR_YIELD | CASHU_BLS_HASH_CACHE;
#ifndef NUCULA_Y_CACHE_SIZE
#define NUCULA_Y_CACHE_SIZE 64
#endif
#ifndef NUCULA_Y_CACHE_AFFINE
#define NUCULA_Y_CACHE_AFFINE 1
#endif
#define BLS_Y_CACHE_SIZE NUCULA_Y_CACHE_SIZE
static struct { unsigned char digest[32];size_t length;
#if NUCULA_Y_CACHE_AFFINE
    blst_p1_affine point;
#else
    blst_p1 point;
#endif
    int valid;
} y_cache[BLS_Y_CACHE_SIZE];
static size_t y_cache_next;

#define G1_LEN 48
#define G2_LEN 96

/* BLS12-381 Fr order, big-endian. A 32-byte value is a valid scalar iff
 * 0 < OS2IP(x) < this, compared on the raw bytes: blst_scalar_from_be_bytes
 * REDUCES out-of-range inputs (reporting success), so its return value
 * cannot serve as the range check. */
static const unsigned char FR_ORDER_BE[32] = {
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48,
    0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
};

static int be_lt(const unsigned char a[32], const unsigned char b[32])
{
    for (int i = 0; i < 32; i++) {
        if (a[i] != b[i])
            return a[i] < b[i];
    }
    return 0;
}

/* 32 big-endian bytes -> blst_scalar, rejecting 0 and values >= Fr order. */
static int scalar_from_be_checked(blst_scalar *out, const unsigned char be[32])
{
    int nonzero = 0;
    for (int i = 0; i < 32; i++)
        if (be[i]) { nonzero = 1; break; }
    if (!nonzero || !be_lt(be, FR_ORDER_BE))
        return 0;
    blst_scalar_from_be_bytes(out, be, 32);
    return 1;
}

static void hash_to_g1_cached(blst_p1 *out, const unsigned char *msg, size_t len,int allow_eviction)
{
    unsigned char digest[32];
    size_t unused=BLS_Y_CACHE_SIZE;
    int cache=(bls_options & CASHU_BLS_HASH_CACHE) && mbedtls_sha256(msg,len,digest,0)==0;
    if (cache) {
        for(size_t i=0;i<BLS_Y_CACHE_SIZE;i++) {
            if(!y_cache[i].valid&&unused==BLS_Y_CACHE_SIZE)unused=i;
            if(y_cache[i].valid&&y_cache[i].length==len&&!memcmp(y_cache[i].digest,digest,32)) {
#if NUCULA_Y_CACHE_AFFINE
                blst_p1_from_affine(out,&y_cache[i].point);
#else
                *out=y_cache[i].point;
#endif
                return;
            }
        }
    }
    blst_hash_to_g1(out, msg, len, DST, DST_LEN, NULL, 0);
    if (cache && (allow_eviction || unused<BLS_Y_CACHE_SIZE)) {
        size_t slot=unused<BLS_Y_CACHE_SIZE?unused:y_cache_next++%BLS_Y_CACHE_SIZE;
        memcpy(y_cache[slot].digest,digest,32);y_cache[slot].length=len;
#if NUCULA_Y_CACHE_AFFINE
        blst_p1_to_affine(&y_cache[slot].point,out);
#else
        y_cache[slot].point=*out;
#endif
        y_cache[slot].valid=1;
    }
}
static void hash_to_g1(blst_p1 *out,const unsigned char *msg,size_t len)
{ hash_to_g1_cached(out,msg,len,1); }

/* blst_p1_mult takes the scalar as little-endian bytes. */
static void p1_mul(blst_p1 *out, const blst_p1 *p, const blst_scalar *s)
{
    unsigned char le[32];
    blst_lendian_from_scalar(le, s);
    blst_p1_mult(out, p, le, 256);
}

/* Full NUT-00 point validation: canonical encoding + on-curve (enforced by
 * uncompress), identity rejection, prime-order-subgroup membership (rejects
 * cofactor components — the Lim-Lee small-subgroup defense). */
static int validate_g1(blst_p1_affine *out, const unsigned char comp[G1_LEN])
{
    if (blst_p1_uncompress(out, comp) != BLST_SUCCESS)
        return 0;
    if (blst_p1_affine_is_inf(out))
        return 0;
    if (!blst_p1_affine_in_g1(out))
        return 0;
    return 1;
}

static int validate_g2(blst_p2_affine *out, const unsigned char comp[G2_LEN])
{
    if (blst_p2_uncompress(out, comp) != BLST_SUCCESS)
        return 0;
    if (blst_p2_affine_is_inf(out))
        return 0;
    if (!blst_p2_affine_in_g2(out))
        return 0;
    return 1;
}

/* --------------------------------------------------------------------------
 * Suite operations
 * ------------------------------------------------------------------------ */

static int bls_blind(void *ctx,
                     const unsigned char *secret, size_t secret_len,
                     const unsigned char *r, size_t r_len,
                     unsigned char *B_out, size_t *B_out_len)
{
    (void)ctx;
    if (r_len != 32 || !B_out_len || *B_out_len < G1_LEN)
        return 0;
    blst_scalar r_s;
    if (!scalar_from_be_checked(&r_s, r))
        return 0; /* r == 0 or >= Fr order: caller must supply a valid scalar */

    blst_hw_acquire();
    blst_p1 Y, B_;
    hash_to_g1(&Y, secret, secret_len);
    p1_mul(&B_, &Y, &r_s);
    blst_p1_compress(B_out, &B_);
    blst_hw_release();

    *B_out_len = G1_LEN;
    return 1;
}

static int bls_unblind(void *ctx,
                       const unsigned char *C_, size_t C__len,
                       const unsigned char *r, size_t r_len,
                       const unsigned char *K, size_t K_len,
                       unsigned char *C_out, size_t *C_out_len)
{
    (void)ctx;
    (void)K; (void)K_len; /* BLS unblinding is C = r^-1 * C_; K plays no role */
    if (C__len != G1_LEN || r_len != 32 || !C_out_len || *C_out_len < G1_LEN)
        return 0;
    blst_scalar r_s;
    if (!scalar_from_be_checked(&r_s, r))
        return 0;

    int ok = 0;
    blst_hw_acquire();

    blst_p1_affine C_aff;
    if (validate_g1(&C_aff, C_)) { /* attacker-visible input: full validation */
        blst_fr r_fr, r_inv_fr;
        blst_scalar r_inv;
        blst_fr_from_scalar(&r_fr, &r_s);
        blst_fr_inverse(&r_inv_fr, &r_fr);
        blst_scalar_from_fr(&r_inv, &r_inv_fr);

        blst_p1 C_pt, C_res;
        blst_p1_from_affine(&C_pt, &C_aff);
        p1_mul(&C_res, &C_pt, &r_inv);
        blst_p1_compress(C_out, &C_res);
        *C_out_len = G1_LEN;
        ok = 1;
    }

    blst_hw_release();
    return ok;
}

/* Derive the per-proof Fiat-Shamir weight w_i by rejection sampling:
 * first SHA256(challenge || u32_BE(i) || u32_BE(ctr)), ctr = 0,1,...,
 * whose value lies in (0, Fr order). */
static void derive_batch_weight(blst_scalar *w, const unsigned char challenge[32],
                                uint32_t i)
{
    unsigned char buf[40];
    memcpy(buf, challenge, 32);
    buf[32] = (unsigned char)(i >> 24);
    buf[33] = (unsigned char)(i >> 16);
    buf[34] = (unsigned char)(i >> 8);
    buf[35] = (unsigned char)i;
    for (uint32_t ctr = 0;; ctr++) {
        buf[36] = (unsigned char)(ctr >> 24);
        buf[37] = (unsigned char)(ctr >> 16);
        buf[38] = (unsigned char)(ctr >> 8);
        buf[39] = (unsigned char)ctr;
        unsigned char h[32];
        blst_sha256(h, buf, 40);
        if (scalar_from_be_checked(w, h))
            return;
    }
}

/* Pairings held per multi-miller call. Within one blst_miller_loop_n the
 * expensive fp12 accumulator squarings are shared across all pairings (the
 * spec's "single multi-miller loop" SHOULD); chunking bounds the stack.
 * Each slot costs ~0.7 KB: our affine copies (288 B) plus blst's internal
 * per-pair G2 accumulator VLA and line temporaries — chunks of 8 left only
 * 1.7 KB of console-stack margin. 4 keeps ~90% of the sharing (the saving
 * scales with sum(len-1)/n) at half the stack. */
#define MILLER_CHUNK 4

static void miller_flush(blst_fp12 *acc,
                         const blst_p2_affine *const qs[],
                         const blst_p1_affine *const ps[],
                         size_t len)
{
    if (len == 0)
        return;
    blst_fp12 ml;
    blst_miller_loop_n(&ml, qs, ps, len);
    blst_fp12_mul(acc, acc, &ml);
}

/*
 * NUT-00 batch verification:
 *
 *   e( sum_i w_i*C_i , g2 ) == prod_i e( w_i*Y_i , K_i )
 *
 * folded as  e( -sum_i w_i*C_i , g2 ) * prod_i e( w_i*Y_i , K_i ) == 1,
 * evaluated in chunked multi-miller loops under one final exponentiation.
 * n == 1 degenerates to the plain pairing check with w = 1 (the weight is
 * skipped entirely) — a single 2-pair multi-miller.
 *
 * The spec groups the right side by distinct mint key — but every AMOUNT has
 * a distinct key within a keyset (NUT-01 requires it), so a typical token's
 * keys are nearly all distinct and grouping saves close to nothing while
 * needing per-group accumulators. Per-proof pairs are constant-memory for
 * any batch size and compute the identical GT product; the last validated K
 * is cached so repeated denominations skip re-validation.
 *
 * The transcript challenge is streamed through mbedTLS SHA-256 so batches of
 * any size use constant memory; weights are consumed as they are derived.
 */
static int bls_verify_proofs_reference(void *ctx, size_t n,
                             const unsigned char *Ks,
                             const unsigned char *Cs,
                             const unsigned char *const *secrets,
                             const size_t *secret_lens)
{
    (void)ctx;
    if (n == 0)
        return 1;
    if (!Ks || !Cs || !secrets || !secret_lens)
        return 0;

    /* challenge = SHA256(BATCH_DST || (C_i || K_i || u32_BE(len) || secret_i)...) */
    unsigned char challenge[32];
    if (n > 1) {
        mbedtls_sha256_context sha;
        mbedtls_sha256_init(&sha);
        if (mbedtls_sha256_starts(&sha, 0) != 0) {
            mbedtls_sha256_free(&sha);
            return 0;
        }
        int hash_ok = mbedtls_sha256_update(&sha, BATCH_DST, BATCH_DST_LEN) == 0;
        for (size_t i = 0; hash_ok && i < n; i++) {
            unsigned char len_be[4] = {
                (unsigned char)(secret_lens[i] >> 24),
                (unsigned char)(secret_lens[i] >> 16),
                (unsigned char)(secret_lens[i] >> 8),
                (unsigned char)(secret_lens[i]),
            };
            hash_ok = mbedtls_sha256_update(&sha, Cs + i * G1_LEN, G1_LEN) == 0 &&
                      mbedtls_sha256_update(&sha, Ks + i * G2_LEN, G2_LEN) == 0 &&
                      mbedtls_sha256_update(&sha, len_be, 4) == 0 &&
                      mbedtls_sha256_update(&sha, secrets[i], secret_lens[i]) == 0;
        }
        if (hash_ok)
            hash_ok = mbedtls_sha256_finish(&sha, challenge) == 0;
        mbedtls_sha256_free(&sha);
        if (!hash_ok)
            return 0;
    }

    int ok = 0;
    blst_hw_acquire();

    /* One pass: validate C_i, accumulate sum_C += w_i*C_i in G1, and queue
     * the (K_i, w_i*Y_i) pair for the chunked multi-miller product. */
    blst_p2_affine k_aff;
    const unsigned char *k_valid = NULL; /* last validated K (into Ks) */
    blst_p1 sum_c;
    blst_fp12 acc = *blst_fp12_one();
    blst_p2_affine chunk_q[MILLER_CHUNK];
    blst_p1_affine chunk_p[MILLER_CHUNK];
    const blst_p2_affine *chunk_qp[MILLER_CHUNK];
    const blst_p1_affine *chunk_pp[MILLER_CHUNK];
    size_t chunk_len = 0;

    for (size_t i = 0; i < n; i++) {
        blst_p1_affine c_aff;
        if (!validate_g1(&c_aff, Cs + i * G1_LEN))
            goto out;

        blst_scalar w;
        if (n > 1)
            derive_batch_weight(&w, challenge, (uint32_t)i);

        blst_p1 c_pt, wc;
        blst_p1_from_affine(&c_pt, &c_aff);
        if (n > 1)
            p1_mul(&wc, &c_pt, &w);
        else
            wc = c_pt;
        if (i == 0)
            sum_c = wc;
        else
            blst_p1_add(&sum_c, &sum_c, &wc);

        blst_p1 y, wy;
        hash_to_g1(&y, secrets[i], secret_lens[i]);
        if (n > 1)
            p1_mul(&wy, &y, &w);
        else
            wy = y;

        const unsigned char *k_comp = Ks + i * G2_LEN;
        if (!k_valid || memcmp(k_valid, k_comp, G2_LEN) != 0) {
            if (!validate_g2(&k_aff, k_comp))
                goto out;
            k_valid = k_comp;
        }

        chunk_q[chunk_len] = k_aff; /* copy: k_aff is a reused cache slot */
        blst_p1_to_affine(&chunk_p[chunk_len], &wy);
        chunk_qp[chunk_len] = &chunk_q[chunk_len];
        chunk_pp[chunk_len] = &chunk_p[chunk_len];
        if (++chunk_len == MILLER_CHUNK) {
            miller_flush(&acc, chunk_qp, chunk_pp, chunk_len);
            chunk_len = 0;
        }
#ifdef ESP_PLATFORM
        if ((i & 3) == 3) vTaskDelay(2);
#endif
    }

    {
        /* Fold the left side into the product as e(-sum_C, g2) and check
         * the whole thing final-exponentiates to one. */
        blst_p1_cneg(&sum_c, true);
        chunk_q[chunk_len] = *blst_p2_affine_generator();
        blst_p1_to_affine(&chunk_p[chunk_len], &sum_c);
        chunk_qp[chunk_len] = &chunk_q[chunk_len];
        chunk_pp[chunk_len] = &chunk_p[chunk_len];
        chunk_len++;
        miller_flush(&acc, chunk_qp, chunk_pp, chunk_len);

        blst_fp12 gt;
        blst_final_exp(&gt, &acc);
        ok = blst_fp12_is_one(&gt) ? 1 : 0;
    }

out:
    blst_hw_release();
    return ok;
}


#define BLS_PAIR_CAPACITY 16
#define BLS_MSM_CAPACITY 10
#define BLS_KEY_CACHE_SIZE 16
#include "bls_generator_lines.h"
static blst_fp6 *hot_key_lines;
static unsigned char hot_key_bytes[G2_LEN];

static size_t bls_capacity = 11;
static struct {
    unsigned char compressed[G2_LEN];
    blst_p2_affine point;
    int valid;
} key_cache[BLS_KEY_CACHE_SIZE];
static size_t key_cache_next;

int cashu_bls_configure(unsigned flags, size_t capacity)
{
    if (flags > 8191 || !capacity || capacity > BLS_PAIR_CAPACITY) return 0;
    blst_hw_acquire();
    bls_options = flags;
    bls_capacity = capacity;
    blst_hw_release();
    return 1;
}
unsigned cashu_bls_options(void) { return bls_options; }
size_t cashu_bls_capacity(void) { return bls_capacity; }
void cashu_bls_clear_hash_cache(void)
{
    blst_hw_acquire();memset(y_cache,0,sizeof(y_cache));y_cache_next=0;blst_hw_release();
}
void cashu_bls_clear_key_cache(void)
{
    blst_hw_acquire();
    memset(key_cache, 0, sizeof(key_cache));
    memset(y_cache,0,sizeof(y_cache));y_cache_next=0;
    key_cache_next = 0;
    free(hot_key_lines);
    hot_key_lines = NULL;
    blst_hw_release();
}

static int cached_g2(blst_p2_affine *out, const unsigned char *compressed, unsigned flags)
{
    if (!(flags & CASHU_BLS_KEY_CACHE)) return validate_g2(out, compressed);
    for (size_t i = 0; i < BLS_KEY_CACHE_SIZE; i++) {
        if (key_cache[i].valid && !memcmp(key_cache[i].compressed, compressed, G2_LEN)) {
            *out = key_cache[i].point;
            return 1;
        }
    }
    if (!validate_g2(out, compressed)) return 0;
    size_t slot = key_cache_next++ % BLS_KEY_CACHE_SIZE;
    memcpy(key_cache[slot].compressed, compressed, G2_LEN);
    key_cache[slot].point = *out;
    key_cache[slot].valid = 1;
    return 1;
}

typedef struct {
    blst_p2_affine *q;
    blst_p1 *p;
    blst_p1_affine *pa;
    unsigned char (*keys)[G2_LEN];
    const blst_p2_affine **qp;
    const blst_p1_affine **pap;
    const blst_p1 **pp;
    blst_p1_affine c[2*BLS_MSM_CAPACITY];
    unsigned char scalars[2*BLS_MSM_CAPACITY][32];
    const blst_p1_affine *cp[2*BLS_MSM_CAPACITY];
    const unsigned char *sp[2*BLS_MSM_CAPACITY];
    const void **prepared;
    size_t pairs, c_count, capacity;
    unsigned flags;
    blst_p1 sum;
    blst_fp12 acc;
    int have_sum, have_acc;
    void *scratch;
    size_t scratch_bytes;
    blst_p1_affine *table;
} bls_workspace;

static bls_workspace *new_workspace(size_t capacity)
{
    const size_t pair_bytes=sizeof(blst_p2_affine)+sizeof(blst_p1)+sizeof(blst_p1_affine)+G2_LEN+
        sizeof(const blst_p2_affine *)+sizeof(const blst_p1_affine *)+sizeof(const blst_p1 *)+sizeof(const void *);
    bls_workspace *w=NULL;
    while(!(w=calloc(1,sizeof(*w)+capacity*pair_bytes))) {
        if(capacity==1)return NULL;
        capacity=capacity>4?4:1;
    }
    unsigned char *next=(void *)(w+1);
#define TAKE_PAIR_ARRAY(member,type) w->member=(void *)next;next+=capacity*sizeof(type)
    TAKE_PAIR_ARRAY(q,blst_p2_affine);TAKE_PAIR_ARRAY(p,blst_p1);TAKE_PAIR_ARRAY(pa,blst_p1_affine);
    TAKE_PAIR_ARRAY(keys,unsigned char[G2_LEN]);TAKE_PAIR_ARRAY(qp,const blst_p2_affine *);
    TAKE_PAIR_ARRAY(pap,const blst_p1_affine *);TAKE_PAIR_ARRAY(pp,const blst_p1 *);TAKE_PAIR_ARRAY(prepared,const void *);
#undef TAKE_PAIR_ARRAY
    w->capacity=capacity;return w;
}

static int compute_msm(bls_workspace *w, blst_p1 *out)
{
    if (!w->c_count) return 0;
    blst_p1 sum;
    size_t nbits = 256, window = 4;
    if (w->flags & CASHU_BLS_GLV_MSM) {
        for (size_t i = w->c_count; i-- > 0;) {
            unsigned char split[32];
            blst_p1_glv_expand(&w->c[2*i], split, &w->c[i], w->scalars[i]);
            memset(w->scalars[2*i], 0, 64);
            memcpy(w->scalars[2*i], split, 16);
            memcpy(w->scalars[2*i+1], split+16, 16);
        }
        w->c_count *= 2;
        nbits = 128; window = 3;
    }
    for (size_t i = 0; i < w->c_count; i++) {
        w->cp[i] = &w->c[i];
        w->sp[i] = w->scalars[i];
    }
    if ((w->flags & CASHU_BLS_WINDOW_MSM) && w->c_count > 1) {
        if (!blst_p1s_precompute_window_workspace(w->table, window, w->cp, w->c_count,
                                                  w->scratch, w->scratch_bytes)) return 0;
        blst_p1s_mult_wbits(&sum, w->table, window, w->c_count, w->sp, nbits, w->scratch);
    } else if ((w->flags & CASHU_BLS_BUCKET_MSM) && w->c_count > 1) {
        blst_p1s_mult_bucket(&sum, w->cp, w->c_count, w->sp, nbits, w->scratch);
    } else {
        for (size_t i = 0; i < w->c_count; i++) {
            blst_p1 point, product;
            blst_p1_from_affine(&point, &w->c[i]);
            blst_p1_mult(&product, &point, w->scalars[i], nbits);
            if (!i) sum = product;
            else blst_p1_add_or_double(&sum, &sum, &product);
        }
    }
    *out = sum;
    w->c_count = 0;
    return 1;
}

static int flush_signature_sum(bls_workspace *w)
{
    if (!w->c_count) return 1;
    blst_p1 sum;
    if (!compute_msm(w, &sum)) return 0;
    if (!w->have_sum) w->sum = sum;
    else blst_p1_add_or_double(&w->sum, &w->sum, &sum);
    w->have_sum = 1;
    w->c_count = 0;
    return 1;
}

static int flush_pairs(bls_workspace *w)
{
    if (!w->pairs) return 1;
    for (size_t i = 0; i < w->pairs; i++) {
        w->qp[i] = &w->q[i];
        w->pp[i] = &w->p[i];
        w->pap[i] = &w->pa[i];
    }
    if (w->flags & CASHU_BLS_BATCH_AFFINE)
        blst_p1s_to_affine(w->pa, w->pp, w->pairs);
    else
        for (size_t i = 0; i < w->pairs; i++) blst_p1_to_affine(&w->pa[i], &w->p[i]);
    blst_fp12 product;
    int prepared = 0;
    for (size_t i = 0; i < w->pairs; i++) prepared |= w->prepared[i] != NULL;
    int ok = prepared ?
        blst_miller_loop_prepared_workspace(&product, w->qp, w->pap, w->prepared,
                                            w->pairs, w->scratch, w->capacity) :
        blst_miller_loop_workspace(&product, w->qp, w->pap, w->pairs, w->scratch, w->capacity);
    if (!ok) return 0;
    memset(w->prepared, 0, w->capacity*sizeof(*w->prepared));
    if (!w->have_acc) w->acc = product;
    else blst_fp12_mul(&w->acc, &w->acc, &product);
    w->have_acc = 1;
    w->pairs = 0;
    return 1;
}

/* Two passes reuse the same bounded MSM arena for C and for each repeated
 * key's Y terms. Every C and K still receives individual subgroup validation;
 * the original full-width transcript weights are used in both sums. */
static void bls_pause(unsigned flags)
{
#ifdef ESP_PLATFORM
    /* Hot-key lines are owned by the global cache, so a workspace using them
     * must keep its pin (the peripheral lock). The default uses only the
     * immutable generator table and may release safely at completed bursts. */
    int release = (flags & CASHU_BLS_FAIR_YIELD) && !(flags & CASHU_BLS_PREPARED_HOT_KEY);
    if (release) blst_hw_release();
    vTaskDelay(2);
    if (release) blst_hw_acquire();
#else
    (void)flags;
#endif
}

static int grouped_msm(bls_workspace *w, size_t n, const unsigned char *Ks,
                       const unsigned char *Cs, const unsigned char *const *secrets,
                       const size_t *lens, const unsigned char challenge[32],
                       const blst_p1_affine *retained)
{
    for (size_t i = 0; i < n; i++) {
        if (retained) w->c[w->c_count] = retained[i];
        else if (!validate_g1(&w->c[w->c_count], Cs+48*i)) return 0;
        blst_scalar scalar; derive_batch_weight(&scalar, challenge, (uint32_t)i);
        blst_lendian_from_scalar(w->scalars[w->c_count++], &scalar);
        if (w->c_count == BLS_MSM_CAPACITY && !flush_signature_sum(w)) return 0;
#ifdef ESP_PLATFORM
        if ((i & 3) == 3) bls_pause(w->flags);
#endif
    }
    if (!flush_signature_sum(w)) return 0;
    for (size_t first = 0; first < n; first++) {
        const unsigned char *key = Ks+96*first;
        size_t previous = 0;
        while (previous < first && memcmp(Ks+96*previous, key, 96)) previous++;
        if (previous != first) continue;
        if (w->pairs == w->capacity && !flush_pairs(w)) return 0;
        size_t group = w->pairs;
        if (!cached_g2(&w->q[group], key, w->flags)) return 0;
        int have_y = 0;
        for (size_t i = first; i < n; i++) {
            if (memcmp(Ks+96*i, key, 96)) continue;
            blst_scalar scalar; derive_batch_weight(&scalar, challenge, (uint32_t)i);
            /* A scan larger than the cache must not evict every earlier Y.
             * Admit empty slots, retain existing hits, compute other misses. */
            blst_p1 y; hash_to_g1_cached(&y,secrets[i],lens[i],n<=BLS_Y_CACHE_SIZE);
            blst_p1_to_affine(&w->c[w->c_count], &y);
            blst_lendian_from_scalar(w->scalars[w->c_count++], &scalar);
            if (w->c_count == BLS_MSM_CAPACITY) {
                blst_p1 sum; if (!compute_msm(w, &sum)) return 0;
                if (!have_y) w->p[group] = sum;
                else blst_p1_add_or_double(&w->p[group], &w->p[group], &sum);
                have_y = 1;
            }
#ifdef ESP_PLATFORM
            if ((i & 3) == 3) bls_pause(w->flags);
#endif
        }
        if (w->c_count) {
            blst_p1 sum; if (!compute_msm(w, &sum)) return 0;
            if (!have_y) w->p[group] = sum;
            else blst_p1_add_or_double(&w->p[group], &w->p[group], &sum);
        }
        if (w->flags & CASHU_BLS_PREPARED_HOT_KEY) {
            if (!hot_key_lines && first == 0) {
                hot_key_lines = malloc(68*sizeof(*hot_key_lines));
                if (hot_key_lines) {
                    memcpy(hot_key_bytes, key, 96);
                    blst_precompute_lines(hot_key_lines, &w->q[group]);
                }
            }
            if (hot_key_lines && !memcmp(hot_key_bytes, key, 96)) w->prepared[group] = hot_key_lines;
        }
        w->pairs++;
    }
    return 1;
}

static int bls_verify_impl(void *ctx, size_t n,
                             const unsigned char *Ks, const unsigned char *Cs,
                             const unsigned char *const *secrets, const size_t *lens,
                             const blst_p1_affine *retained)
{
    if (!n) return 1;
    if (!Ks || !Cs || !secrets || !lens || n > UINT32_MAX || n > SIZE_MAX/G2_LEN) return 0;
    for (size_t i = 0; i < n; i++)
        if (lens[i] > UINT32_MAX || (!secrets[i] && lens[i])) return 0;
    if (!bls_options) return bls_verify_proofs_reference(ctx, n, Ks, Cs, secrets, lens);
    (void)ctx;
    unsigned char challenge[32];
    if (n > 1) {
        mbedtls_sha256_context sha;
        mbedtls_sha256_init(&sha);
        int ok = mbedtls_sha256_starts(&sha, 0) == 0 &&
                 mbedtls_sha256_update(&sha, BATCH_DST, BATCH_DST_LEN) == 0;
        for (size_t i = 0; ok && i < n; i++) {
            unsigned char len[4] = {lens[i] >> 24, lens[i] >> 16, lens[i] >> 8, lens[i]};
            ok = mbedtls_sha256_update(&sha, Cs+i*G1_LEN, G1_LEN) == 0 &&
                 mbedtls_sha256_update(&sha, Ks+i*G2_LEN, G2_LEN) == 0 &&
                 mbedtls_sha256_update(&sha, len, 4) == 0 &&
                 mbedtls_sha256_update(&sha, secrets[i], lens[i]) == 0;
        }
        ok = ok && mbedtls_sha256_finish(&sha, challenge) == 0;
        mbedtls_sha256_free(&sha);
        if (!ok) return 0;
    }
    int ok = 0;
    blst_hw_acquire();
    bls_workspace *w = new_workspace(n<bls_capacity?n+1:bls_capacity);
    if (!w) goto release;
    w->flags = bls_options;
    size_t msm_count = n<BLS_MSM_CAPACITY?n:BLS_MSM_CAPACITY;
    if(w->flags & CASHU_BLS_GLV_MSM)msm_count*=2;
    size_t window = (w->flags & CASHU_BLS_GLV_MSM) ? 3 : 4;
    for (unsigned attempt = 0; attempt < 3; attempt++) {
        size_t msm_scratch = blst_p1s_mult_pippenger_scratch_sizeof(msm_count);
        if (w->flags & CASHU_BLS_WINDOW_MSM) {
            msm_scratch = blst_p1s_window_workspace_sizeof(msm_count, window);
            w->table = malloc(blst_p1s_mult_wbits_precompute_sizeof(window, msm_count));
        }
        if (!(w->flags & (CASHU_BLS_WINDOW_MSM | CASHU_BLS_BUCKET_MSM))) msm_scratch = 0;
        w->scratch_bytes = blst_miller_workspace_sizeof(w->capacity);
        if (msm_scratch > w->scratch_bytes) w->scratch_bytes = msm_scratch;
        if (!(w->flags & CASHU_BLS_WINDOW_MSM) || w->table) w->scratch = malloc(w->scratch_bytes);
        if (w->scratch) break;
        free(w->table); w->table = NULL;
        if (!attempt) { w->flags &= ~CASHU_BLS_WINDOW_MSM; w->flags |= CASHU_BLS_BUCKET_MSM; }
        else { w->flags &= ~(CASHU_BLS_WINDOW_MSM | CASHU_BLS_BUCKET_MSM); w->capacity = 1; }
    }
    if (!w->scratch) goto cleanup;
    int repeated = 0;
    /* Quadratic byte comparisons are bounded; large batches use the linear
     * original path. No point arithmetic or proof is skipped by this test. */
    if ((w->flags & CASHU_BLS_GROUP_MSM) && n > 1 && n <= 128)
        for (size_t i = 1; i < n && !repeated; i++)
            for (size_t j = 0; j < i; j++)
                if (!memcmp(Ks+96*i, Ks+96*j, 96)) { repeated = 1; break; }
    if (repeated) {
        if (!grouped_msm(w, n, Ks, Cs, secrets, lens, challenge, retained)) goto cleanup;
        goto final_pair;
    }
    for (size_t i = 0; i < n; i++) {
        blst_p1_affine c;
        if (retained) c = retained[i];
        else if (!validate_g1(&c, Cs+i*G1_LEN)) goto cleanup;
        blst_scalar scalar;
        if (n > 1) derive_batch_weight(&scalar, challenge, (uint32_t)i);
        else { memset(&scalar, 0, sizeof(scalar)); scalar.b[0] = 1; }
        if (n == 1) {
            blst_p1_from_affine(&w->sum, &c);
            w->have_sum = 1;
        } else {
            w->c[w->c_count] = c;
            blst_lendian_from_scalar(w->scalars[w->c_count++], &scalar);
            if (w->c_count == BLS_MSM_CAPACITY && !flush_signature_sum(w)) goto cleanup;
        }
        blst_p1 y, weighted;
        hash_to_g1_cached(&y,secrets[i],lens[i],n<=BLS_Y_CACHE_SIZE);
        if (n > 1) p1_mul(&weighted, &y, &scalar);
        else weighted = y;
        const unsigned char *key = Ks+i*G2_LEN;
        size_t group = w->pairs;
        if (w->flags & CASHU_BLS_GROUP_KEYS)
            for (size_t j = 0; j < w->pairs; j++)
                if (!memcmp(w->keys[j], key, G2_LEN)) { group = j; break; }
        if (group < w->pairs) {
            blst_p1_add_or_double(&w->p[group], &w->p[group], &weighted);
        } else {
            if (w->pairs == w->capacity && !flush_pairs(w)) goto cleanup;
            group = w->pairs++;
            if (!cached_g2(&w->q[group], key, w->flags)) goto cleanup;
            if (w->flags & CASHU_BLS_PREPARED_HOT_KEY) {
                if (!hot_key_lines && i == 0) {
                    hot_key_lines = malloc(68 * sizeof(*hot_key_lines));
                    if (hot_key_lines) {
                        memcpy(hot_key_bytes, key, G2_LEN);
                        blst_precompute_lines(hot_key_lines, &w->q[group]);
                    }
                }
                if (hot_key_lines && !memcmp(hot_key_bytes, key, G2_LEN))
                    w->prepared[group] = hot_key_lines;
            }
            memcpy(w->keys[group], key, G2_LEN);
            w->p[group] = weighted;
        }
#ifdef ESP_PLATFORM
        /* All accelerator work is complete; optional fair ownership lets
         * TLS and other crypto tasks use the peripheral between bursts. */
        if ((i & 3) == 3) bls_pause(w->flags);
#endif
    }
final_pair:
    if (!flush_signature_sum(w)) goto cleanup;
    if (w->pairs == w->capacity && !flush_pairs(w)) goto cleanup;
    w->prepared[w->pairs] = (w->flags & CASHU_BLS_PREPARED_GENERATOR) ? bls_generator_lines : NULL;
    w->q[w->pairs] = *blst_p2_affine_generator();
    w->p[w->pairs] = w->sum;
    blst_p1_cneg(&w->p[w->pairs++], true);
    if (!flush_pairs(w)) goto cleanup;
    blst_fp12 gt;
    blst_final_exp(&gt, &w->acc);
    ok = blst_fp12_is_one(&gt);
cleanup:
    free(w->scratch);
    free(w->table);
    free(w);
release:
    blst_hw_release();
    return ok;
}

static int bls_verify_proofs(void *ctx, size_t n,
                             const unsigned char *Ks, const unsigned char *Cs,
                             const unsigned char *const *secrets, const size_t *lens)
{ return bls_verify_impl(ctx, n, Ks, Cs, secrets, lens, NULL); }

static void clear_private(void *p, size_t n)
{ volatile unsigned char *bytes = p; while (n--) *bytes++ = 0; }

/* Validate each external C_ exactly once, retaining the resulting unblinded
 * affine point through verification. The private entry to bls_verify_impl
 * cannot be invoked by a caller supplying supposedly validated points. */
int cashu_bls_unblind_verify(size_t n, const unsigned char *Ks,
                             const unsigned char *blinded, const unsigned char *rs,
                             const unsigned char *const *secrets, const size_t *lens,
                             unsigned char *out)
{
    if (!n) return 1;
    if (!Ks || !blinded || !rs || !secrets || !lens || !out || n > SIZE_MAX/96 || n > UINT32_MAX) return 0;
    /* Keep memory bounded for unusually large responses. Each chunk still
     * receives a complete independent cryptographic verification. */
    if (n > 32) {
        for (size_t offset = 0; offset < n; offset += 32) {
            size_t count = n-offset < 32 ? n-offset : 32;
            if (!cashu_bls_unblind_verify(count, Ks+96*offset, blinded+48*offset,
                    rs+32*offset, secrets+offset, lens+offset, out+48*offset)) {
                memset(out, 0, 48*n); return 0;
            }
        }
        return 1;
    }
    blst_p1_affine *points = malloc(n * sizeof(*points));
    if (!points) return 0;
    int ok = 1;
    blst_fr *inverses = NULL;
    if ((cashu_bls_options() & CASHU_BLS_BATCH_INVERSE) && n > 1)
        inverses = malloc(n*sizeof(*inverses));
    blst_hw_acquire();
    if (inverses) {
        struct { blst_scalar scalar; blst_fr factor, product, reciprocal, inverse; } private;
        for (size_t i=0;i<n&&ok;i++) {
            ok=scalar_from_be_checked(&private.scalar,rs+32*i);
            if (!ok) break;
            blst_fr_from_scalar(&private.factor,&private.scalar);
            if (!i) private.product=private.factor;
            else blst_fr_mul(&private.product,&private.product,&private.factor);
            inverses[i]=private.product;
        }
        if (ok) {
            blst_fr_inverse(&private.reciprocal,&private.product);
            for (size_t i=n;i-- > 0;) {
                if (i) blst_fr_mul(&private.inverse,&private.reciprocal,&inverses[i-1]);
                else private.inverse=private.reciprocal;
                inverses[i]=private.inverse;
                blst_scalar_from_bendian(&private.scalar,rs+32*i);
                blst_fr_from_scalar(&private.factor,&private.scalar);
                blst_fr_mul(&private.reciprocal,&private.reciprocal,&private.factor);
            }
        }
        clear_private(&private,sizeof(private));
    }
    for (size_t i = 0; i < n && ok; i++) {
        struct { blst_scalar r, inverse; blst_fr field, inverse_field; } private;
        blst_p1_affine affine;
        blst_p1 point, result;
        ok = scalar_from_be_checked(&private.r, rs+32*i) && validate_g1(&affine, blinded+48*i);
        if (ok) {
            blst_fr_from_scalar(&private.field, &private.r);
            if (inverses) private.inverse_field=inverses[i];
            else blst_fr_inverse(&private.inverse_field, &private.field);
            blst_scalar_from_fr(&private.inverse, &private.inverse_field);
            blst_p1_from_affine(&point, &affine);
            p1_mul(&result, &point, &private.inverse);
            blst_p1_to_affine(&points[i], &result);
            blst_p1_affine_compress(out+48*i, &points[i]);
        }
        clear_private(&private, sizeof(private));
#ifdef ESP_PLATFORM
        if ((i & 3) == 3) bls_pause(cashu_bls_options());
#endif
    }
    blst_hw_release();
    if (inverses) { clear_private(inverses,n*sizeof(*inverses));free(inverses); }
    if (ok) ok = bls_verify_impl(NULL, n, Ks, out, secrets, lens, points);
    free(points);
    if (!ok) memset(out, 0, n*48);
    return ok;
}

/* NUT-13 v3 secret derivation: identical to v2 — the raw 32 HMAC bytes. */
static int bls_derive_secret(const unsigned char *seed, size_t seed_len,
                             const char *keyset_id, uint32_t counter,
                             unsigned char *secret_out)
{
    return cashu_nut13_hmac(seed, seed_len, keyset_id, counter, 0x00,
                            NULL, 0, secret_out);
}

/* NUT-13 v3 blinding factor: rejection sampling against the Fr order (a
 * modular reduction would bias ~7.5% since Fr order is ~0.45*2^256). The
 * KDF message appends u32_BE(attempt), present from attempt 0. ~45%
 * acceptance per attempt; 64 attempts bounds p(fail) around 2^-55. */
static int bls_derive_r(const unsigned char *seed, size_t seed_len,
                        const char *keyset_id, uint32_t counter,
                        unsigned char *r_out)
{
    for (uint32_t attempt = 0; attempt < 64; attempt++) {
        unsigned char suffix[4] = {
            (unsigned char)(attempt >> 24), (unsigned char)(attempt >> 16),
            (unsigned char)(attempt >> 8), (unsigned char)attempt,
        };
        unsigned char x[32];
        if (!cashu_nut13_hmac(seed, seed_len, keyset_id, counter, 0x01,
                              suffix, 4, x))
            return 0;
        int nonzero = 0;
        for (int i = 0; i < 32; i++)
            if (x[i]) { nonzero = 1; break; }
        if (nonzero && be_lt(x, FR_ORDER_BE)) {
            memcpy(r_out, x, 32);
            return 1;
        }
    }
    return 0;
}

const cashu_suite_t cashu_suite_bls = {
    .version_byte = 0x02,
    .name = "bls12_381",
    .point_len = G1_LEN,    /* compressed G1: Y, B_, C_, C */
    .mint_key_len = G2_LEN, /* compressed G2: mint keys K  */
    .scalar_len = 32,
    .can_mint = 1,
    .has_dleq = 0,          /* NUT-12 does not apply to v3 — pairing verify instead */
    .blind = bls_blind,
    .unblind = bls_unblind,
    .verify_dleq = NULL,
    .verify_dleq_unblinded = NULL,
    .verify_proofs = bls_verify_proofs,
    .derive_secret = bls_derive_secret,
    .derive_r = bls_derive_r,
};
