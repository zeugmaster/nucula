/*
 * ESP32-C3 RSA/MPI driver for blst's 384-bit Fp Montgomery multiply.
 * C port of bls-bench's src/mpi.rs (github.com/zeugmaster/bls-bench),
 * on the IDF HAL instead of raw SYSTEM registers.
 *
 * The peripheral's native modular multiplication performs a double
 * Montgomery reduction (X*Y*R^-2 mod M). The single-reduction trick: run
 * a modexp with exponent Y = 0, CONSTANT_TIME = 0, SEARCH_ENABLE = 1,
 * SEARCH_POS = 0 — the peripheral computes X = X*Z*R^-1 mod M as its first
 * step and the search early-exits before any exponent bits are processed.
 * The canonical result lands in X memory (not Z).
 *
 * I/O is amortised within a blst_hw_acquire() hold window: the modulus,
 * n0 and the zero exponent stay resident across calls. The measured default
 * writes both operands without data-dependent cache comparisons; an optional
 * diagnostic path reuses resident X across t=t*x chains.
 */
#if __has_include("sdkconfig.h")
#include "sdkconfig.h"
#endif

#include "blst_mpi.h"
#include <string.h>

#define FP_WORDS 12 /* 384-bit Fp */

/* --------------------------------------------------------------------------
 * Software fallback: the exact blst portable mul_mont_n algorithm
 * (no_asm.h, v0.3.16) with 32-bit limbs. Used for 256-bit Fr on the C3 and
 * for everything on targets without the RSA peripheral. Also the
 * bit-exactness reference for the peripheral path.
 * ------------------------------------------------------------------------ */

static inline uint32_t launder32(uint32_t v)
{
#if defined(__GNUC__) || defined(__clang__)
    __asm__("" : "+r"(v));
#endif
    return v;
}

static void sw_mul_mont_n(uint32_t ret[], const uint32_t a[], const uint32_t b[],
                          const uint32_t p[], uint32_t n0, size_t n)
{
    uint64_t limbx;
    uint32_t mask, borrow, mx, hi, tmp[n + 1], carry;
    size_t i, j;

    for (mx = b[0], hi = 0, i = 0; i < n; i++) {
        limbx = (mx * (uint64_t)a[i]) + hi;
        tmp[i] = (uint32_t)limbx;
        hi = (uint32_t)(limbx >> 32);
    }
    mx = n0 * tmp[0];
    tmp[i] = hi;

    for (carry = 0, j = 0;;) {
        limbx = (mx * (uint64_t)p[0]) + tmp[0];
        hi = (uint32_t)(limbx >> 32);
        for (i = 1; i < n; i++) {
            limbx = (mx * (uint64_t)p[i] + hi) + tmp[i];
            tmp[i - 1] = (uint32_t)limbx;
            hi = (uint32_t)(limbx >> 32);
        }
        limbx = tmp[i] + (hi + (uint64_t)carry);
        tmp[i - 1] = (uint32_t)limbx;
        carry = (uint32_t)(limbx >> 32);

        if (++j == n)
            break;

        for (mx = b[j], hi = 0, i = 0; i < n; i++) {
            limbx = (mx * (uint64_t)a[i] + hi) + tmp[i];
            tmp[i] = (uint32_t)limbx;
            hi = (uint32_t)(limbx >> 32);
        }
        mx = n0 * tmp[0];
        limbx = hi + (uint64_t)carry;
        tmp[i] = (uint32_t)limbx;
        carry = (uint32_t)(limbx >> 32);
    }

    for (borrow = 0, i = 0; i < n; i++) {
        limbx = tmp[i] - (p[i] + (uint64_t)borrow);
        ret[i] = (uint32_t)limbx;
        borrow = (uint32_t)(limbx >> 32) & 1;
    }

    mask = launder32(carry - borrow);

    for (i = 0; i < n; i++)
        ret[i] = (ret[i] & ~mask) | (tmp[i] & mask);
}

void blst_mpi_sw_mul_mont_384(uint32_t ret[12], const uint32_t a[12],
                              const uint32_t b[12], const uint32_t p[12],
                              uint32_t n0)
{
    sw_mul_mont_n(ret, a, b, p, n0, 12);
}

/* --------------------------------------------------------------------------
 * ESP32-C3 hardware path
 * ------------------------------------------------------------------------ */
#if defined(CONFIG_IDF_TARGET_ESP32C3)

#include "esp_crypto_lock.h"       /* esp_crypto_mpi_lock_*            */
#include "esp_crypto_periph_clk.h" /* esp_crypto_mpi_enable_periph_clk */
#include "esp_log.h"
#include "hal/mpi_hal.h"
#include "hal/mpi_ll.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "soc/hwcrypto_reg.h" /* RSA_MEM_*_BLOCK_BASE */

extern const uint32_t BLS12_381_P[FP_WORDS];
extern const uint32_t BLS12_381_RR[FP_WORDS];

static struct {
    volatile int lock_held;
    TaskHandle_t owner;
    int warned_unlocked;
    int enabled;
    int mod_loaded;
    const uint32_t *mod_source;
    uint32_t mod[FP_WORDS];
    uint32_t n0;
    uint32_t resident_x[FP_WORDS];
    int resident_x_valid;
} s = { .enabled = 1 };

static unsigned mpi_options = BLST_MPI_SESSION | BLST_MPI_INLINE |
    BLST_MPI_CONST_MOD | BLST_MPI_NO_CACHE | BLST_MPI_SQRT_EXP |
    BLST_MPI_SECP_SQRT | BLST_MPI_FP2_PIPELINE | BLST_MPI_SHA256 |
    BLST_MPI_SECP_SHA256;

void blst_mpi_set_options(unsigned options)
{
    configASSERT(!(s.lock_held && s.owner == xTaskGetCurrentTaskHandle()));
    esp_crypto_mpi_lock_acquire();
    mpi_options = options;
    esp_crypto_mpi_lock_release();
}

unsigned blst_mpi_options(void) { return mpi_options; }

static inline void configure_montgomery(void)
{
    mpi_ll_set_mode(FP_WORDS - 1);
    mpi_ll_disable_constant_time();
    mpi_ll_enable_search();
    mpi_ll_set_search_position(0);
}

void blst_hw_acquire(void)
{
    esp_crypto_mpi_lock_acquire();
    /* Enabling the clock pulses the peripheral reset, which clears the
     * operand RAM — hence the caches are scoped to the hold window. */
    esp_crypto_mpi_enable_periph_clk(true);
    /* Waits for the post-reset memory clean and disables the RSA interrupt,
     * so polling here never trips mbedTLS's completion ISR. */
    mpi_hal_enable_hardware_hw_op();
    s.mod_loaded = 0;
    s.resident_x_valid = 0;
    if (mpi_options & BLST_MPI_SESSION)
        configure_montgomery();
    s.owner = xTaskGetCurrentTaskHandle();
    s.lock_held = 1;
}

void blst_hw_release(void)
{
    configASSERT(s.owner == xTaskGetCurrentTaskHandle());
    s.lock_held = 0;
    s.owner = NULL;
    esp_crypto_mpi_enable_periph_clk(false);
    esp_crypto_mpi_lock_release();
}

void blst_mpi_set_enabled(int enabled) { s.enabled = enabled; }
int blst_mpi_enabled(void) { return s.enabled; }

static inline int same_words(const uint32_t a[FP_WORDS], const uint32_t b[FP_WORDS])
{
    if (!(mpi_options & BLST_MPI_WORD_COMPARE))
        return memcmp(a, b, FP_WORDS * sizeof(uint32_t)) == 0;
    uint32_t different = 0;
    for (int i = 0; i < FP_WORDS; i++)
        different |= a[i] ^ b[i];
    return different == 0;
}

/* Fixed-width MMIO transfer keeps both addresses in registers. GCC's ordinary
 * unrolled volatile loop repeatedly rematerializes the APB base on RV32.
 * The clobber also orders the transfer against accelerator start/finish. */
static inline __attribute__((always_inline)) void mpi_copy12(volatile uint32_t *dst,const volatile uint32_t *src)
{
    uint32_t temporary;
#define COPY_WORD(offset) "lw %0," #offset "(%2)\n\tsw %0," #offset "(%1)\n\t"
    __asm__ volatile(COPY_WORD(0) COPY_WORD(4) COPY_WORD(8) COPY_WORD(12)
                     COPY_WORD(16) COPY_WORD(20) COPY_WORD(24) COPY_WORD(28)
                     COPY_WORD(32) COPY_WORD(36) COPY_WORD(40) COPY_WORD(44)
                     : "=&r"(temporary) : "r"(dst),"r"(src) : "memory");
#undef COPY_WORD
}

static void mpi_mont_mul_384(uint32_t ret[], const uint32_t a[],
                             const uint32_t b[], const uint32_t p[],
                             uint32_t n0)
{
    volatile uint32_t *m_mem = (volatile uint32_t *)RSA_MEM_M_BLOCK_BASE;
    volatile uint32_t *z_mem = (volatile uint32_t *)RSA_MEM_Z_BLOCK_BASE;
    volatile uint32_t *y_mem = (volatile uint32_t *)RSA_MEM_Y_BLOCK_BASE;
    volatile uint32_t *x_mem = (volatile uint32_t *)RSA_MEM_X_BLOCK_BASE;

    /* The acquired session has exclusive ownership; no TLS user can change
     * mode until release. Keep the old path for measured comparisons. */
    if (!(mpi_options & BLST_MPI_SESSION)) {
        if (mpi_options & BLST_MPI_INLINE) {
            configure_montgomery();
        } else {
            mpi_hal_set_mode(FP_WORDS - 1);
            mpi_hal_enable_constant_time(false);
            mpi_hal_enable_search(true);
            mpi_hal_set_search_position(0);
        }
    }

    /* Modulus + n0 + zero exponent: resident across the hold window. */
    int known_immutable = (mpi_options & BLST_MPI_CONST_MOD) &&
                          p == BLS12_381_P && s.mod_source == p;
    if (!s.mod_loaded || s.n0 != n0 ||
        (!known_immutable && !same_words(s.mod, p))) {
        for (int i = 0; i < FP_WORDS; i++) {
            m_mem[i] = p[i];
            y_mem[i] = 0; /* exponent = 0 */
        }
        mpi_hal_write_m_prime(n0);
        memcpy(s.mod, p, sizeof(s.mod));
        s.n0 = n0;
        s.mod_source = p;
        s.mod_loaded = 1;
        s.resident_x_valid = 0;
    }

    /* Operand A -> X, skipped when it matches the resident X (the previous
     * result), which is the common t = t*x chain in field towers. */
    int cached = !(mpi_options & BLST_MPI_NO_CACHE) && s.resident_x_valid &&
                 same_words(s.resident_x, a);
    if (!cached && (mpi_options & BLST_MPI_SWAP_CACHE) &&
        !(mpi_options & BLST_MPI_NO_CACHE) && s.resident_x_valid &&
        same_words(s.resident_x, b)) {
        const uint32_t *tmp = a;
        a = b;
        b = tmp;
        cached = 1;
    }
    if (!cached) {
        if(NUCULA_RV32_COPY && (mpi_options & BLST_MPI_RV32_COPY)) mpi_copy12(x_mem,a);
        else for (int i = 0; i < FP_WORDS; i++)
            x_mem[i] = a[i];
    }

    /* Operand B -> Z, always: the early exit clobbers Z each op. */
    if(NUCULA_RV32_COPY && (mpi_options & BLST_MPI_RV32_COPY)) mpi_copy12(z_mem,b);
    else for (int i = 0; i < FP_WORDS; i++)
        z_mem[i] = b[i];

    if (mpi_options & BLST_MPI_INLINE) {
        mpi_ll_clear_interrupt();
        mpi_ll_start_op(MPI_MODEXP);
        while (mpi_ll_get_int_status()) {}
        mpi_ll_clear_interrupt();
    } else {
        mpi_hal_start_op(MPI_MODEXP);
        mpi_hal_wait_op_complete();
    }

    /* Result is in X memory (there is no HAL reader for X; the operand RAM
     * is plain APB-mapped memory). Capture it as the new resident X. */
    if(NUCULA_RV32_COPY && (mpi_options & (BLST_MPI_RV32_COPY|BLST_MPI_NO_CACHE)) == (BLST_MPI_RV32_COPY|BLST_MPI_NO_CACHE))
        mpi_copy12(ret,x_mem);
    else for (int i = 0; i < FP_WORDS; i++) {
        uint32_t v = x_mem[i];
        ret[i] = v;
        if (!(mpi_options & BLST_MPI_NO_CACHE))
            s.resident_x[i] = v;
    }
    s.resident_x_valid = 1;
}

void mpi_mul_mont_n(uint32_t ret[], const uint32_t a[], const uint32_t b[],
                    const uint32_t p[], uint32_t n0, size_t n)
{
    if (n == FP_WORDS && s.enabled) {
        if (s.lock_held && s.owner == xTaskGetCurrentTaskHandle()) {
            mpi_mont_mul_384(ret, a, b, p, n0);
            return;
        }
        /* A call site forgot blst_hw_acquire(): correct-but-slow beats
         * silent corruption. Acquiring per call pulses the peripheral
         * reset, so the operand caches never help on this path. */
        if (!s.warned_unlocked) {
            s.warned_unlocked = 1;
            ESP_LOGW("blst_mpi", "mul_mont without blst_hw_acquire(); "
                                 "falling back to per-call locking");
        }
        blst_hw_acquire();
        mpi_mont_mul_384(ret, a, b, p, n0);
        blst_hw_release();
        return;
    }
    sw_mul_mont_n(ret, a, b, p, n0, n);
}

/* Native modexp consumes/returns ordinary integers. Two Montgomery products
 * bridge blst's representation. Never use this variable-time exponent mode
 * with a secret exponent. All callers below select public, fixed exponents. */
static void mpi_public_exp_384(uint32_t out[12], const uint32_t in[12],
                              const uint32_t exponent[12], unsigned bits)
{
    static const uint32_t one[12] = {1};
    uint32_t base[12], result[12];
    mpi_mont_mul_384(base, in, one, BLS12_381_P, 0xFFFCFFFDu);
    volatile uint32_t *m = (volatile uint32_t *)RSA_MEM_M_BLOCK_BASE;
    volatile uint32_t *x = (volatile uint32_t *)RSA_MEM_X_BLOCK_BASE;
    volatile uint32_t *y = (volatile uint32_t *)RSA_MEM_Y_BLOCK_BASE;
    volatile uint32_t *z = (volatile uint32_t *)RSA_MEM_Z_BLOCK_BASE;
    for (int i = 0; i < 12; i++) {
        m[i] = BLS12_381_P[i];
        x[i] = base[i];
        y[i] = exponent[i];
        z[i] = BLS12_381_RR[i];
    }
    mpi_ll_write_m_prime(0xFFFCFFFDu);
    mpi_ll_set_mode(11);
    mpi_ll_disable_constant_time();
    mpi_ll_enable_search();
    mpi_ll_set_search_position(bits - 1);
    mpi_ll_clear_interrupt();
    mpi_ll_start_op(MPI_MODEXP);
    while (mpi_ll_get_int_status()) {}
    mpi_ll_clear_interrupt();
    for (int i = 0; i < 12; i++)
        result[i] = z[i];
    /* Exponent, output residency, and mode were overwritten. */
    s.mod_loaded = 0;
    s.resident_x_valid = 0;
    configure_montgomery();
    mpi_mont_mul_384(out, result, BLS12_381_RR, BLS12_381_P, 0xFFFCFFFDu);
}

int blst_mpi_fixed_exp_384(void *out, const void *in, unsigned which)
{
    if (!(mpi_options & which) || !s.enabled || !s.lock_held ||
        s.owner != xTaskGetCurrentTaskHandle())
        return 0;
    uint32_t exponent[12];
    memcpy(exponent, BLS12_381_P, sizeof(exponent));
    if (which == BLST_MPI_SQRT_EXP) {
        exponent[0] -= 3;
        for (int i = 0; i < 11; i++)
            exponent[i] = (exponent[i] >> 2) | (exponent[i+1] << 30);
        exponent[11] >>= 2;
        mpi_public_exp_384(out, in, exponent, 379);
    } else if (which == BLST_MPI_INVERSE_EXP) {
        exponent[0] -= 2;
        mpi_public_exp_384(out, in, exponent, 381);
    } else {
        return 0;
    }
    return 1;
}

int blst_mpi_square_chain_384(void *out, const void *in, size_t count)
{
    if (!(mpi_options & BLST_MPI_SQUARE_CHAIN) || !s.enabled || !s.lock_held ||
        s.owner != xTaskGetCurrentTaskHandle() || count < 3 || count >= 384)
        return 0;
    uint32_t exponent[12] = {0};
    exponent[count / 32] = (uint32_t)1 << (count % 32);
    mpi_public_exp_384(out, in, exponent, (unsigned)count + 1);
    return 1;
}

/* Reduced 381-bit residues never carry out of the 384-bit sum. Both
 * selection and borrow correction use masks, including secret operands. */
static void fp_add_words(uint32_t out[12], const uint32_t a[12], const uint32_t b[12])
{
    uint32_t sum[12], difference[12]; uint64_t carry=0, borrow=0;
    for (unsigned i=0;i<12;i++) { uint64_t v=(uint64_t)a[i]+b[i]+carry;sum[i]=(uint32_t)v;carry=v>>32; }
    for (unsigned i=0;i<12;i++) { uint64_t v=(uint64_t)sum[i]-BLS12_381_P[i]-borrow;difference[i]=(uint32_t)v;borrow=v>>63; }
    uint32_t mask=0u-(uint32_t)borrow;
    for(unsigned i=0;i<12;i++)out[i]=(sum[i]&mask)|(difference[i]&~mask);
}
static void fp_sub_words(uint32_t out[12], const uint32_t a[12], const uint32_t b[12])
{
    uint32_t difference[12]; uint64_t borrow=0,carry=0;
    for(unsigned i=0;i<12;i++){uint64_t v=(uint64_t)a[i]-b[i]-borrow;difference[i]=(uint32_t)v;borrow=v>>63;}
    uint32_t mask=0u-(uint32_t)borrow;
    for(unsigned i=0;i<12;i++){uint64_t v=(uint64_t)difference[i]+(BLS12_381_P[i]&mask)+carry;out[i]=(uint32_t)v;carry=v>>32;}
}
static inline void mont_start(const uint32_t a[12],const uint32_t b[12])
{
    volatile uint32_t *x=(volatile uint32_t *)RSA_MEM_X_BLOCK_BASE;
    volatile uint32_t *z=(volatile uint32_t *)RSA_MEM_Z_BLOCK_BASE;
    if(NUCULA_RV32_COPY && (mpi_options & BLST_MPI_RV32_COPY)){mpi_copy12(x,a);mpi_copy12(z,b);}
    else for(unsigned i=0;i<12;i++){x[i]=a[i];z[i]=b[i];}
    mpi_ll_clear_interrupt();mpi_ll_start_op(MPI_MODEXP);
}
static inline void mont_finish(uint32_t out[12])
{
    volatile uint32_t *x=(volatile uint32_t *)RSA_MEM_X_BLOCK_BASE;
    while(mpi_ll_get_int_status()){}mpi_ll_clear_interrupt();
    if(NUCULA_RV32_COPY && (mpi_options & BLST_MPI_RV32_COPY))mpi_copy12(out,x);
    else for(unsigned i=0;i<12;i++)out[i]=x[i];
}
int blst_mpi_fp2(void *output,const void *input_a,const void *input_b,
                  const void *modulus,unsigned int n0,int square)
{
    if (!(mpi_options & (BLST_MPI_FP2_FUSED|BLST_MPI_FP2_PIPELINE)) || !s.enabled ||
        !s.lock_held || s.owner!=xTaskGetCurrentTaskHandle() || modulus!=BLS12_381_P || n0!=0xfffcfffdu) return 0;
    uint32_t *out=output;const uint32_t *a=input_a,*b=input_b;
    uint32_t aa[12],bb[12],ac[12],bd[12],cross[12],sum[12];
    int pipeline=!!(mpi_options & BLST_MPI_FP2_PIPELINE);
    if (square) {
        mpi_mont_mul_384(ac,a,a+12,BLS12_381_P,0xfffcfffdu);
        fp_add_words(aa,a,a+12);fp_sub_words(bb,a,a+12);
        if (pipeline) {
            mont_start(aa,bb);fp_add_words(out+12,ac,ac);mont_finish(out);
        } else {
            mont_start(aa,bb);mont_finish(out);fp_add_words(out+12,ac,ac);
        }
    } else {
        mpi_mont_mul_384(ac,a,b,BLS12_381_P,0xfffcfffdu);
        mont_start(a+12,b+12);
        if (pipeline) { fp_add_words(aa,a,a+12);fp_add_words(bb,b,b+12); }
        mont_finish(bd);
        if (!pipeline) { fp_add_words(aa,a,a+12);fp_add_words(bb,b,b+12); }
        mont_start(aa,bb);
        if (pipeline) { fp_sub_words(out,ac,bd);fp_add_words(sum,ac,bd); }
        mont_finish(cross);
        if (!pipeline) { fp_sub_words(out,ac,bd);fp_add_words(sum,ac,bd); }
        fp_sub_words(out+12,cross,sum);
    }
    s.resident_x_valid=0;
    return 1;
}

int blst_mpi_secp_sqrt(unsigned char out[32], const unsigned char in[32])
{
    if (!(mpi_options & BLST_MPI_SECP_SQRT) || !s.enabled) return 0;
    int owned = s.lock_held && s.owner == xTaskGetCurrentTaskHandle();
    if (!owned) blst_hw_acquire();
    static const uint32_t p[8] = {0xfffffc2fu,0xfffffffeu,0xffffffffu,0xffffffffu,0xffffffffu,0xffffffffu,0xffffffffu,0xffffffffu};
    static const uint32_t rr[8] = {0x000e90a1u,0x7a2u,1};
    static const uint32_t exponent[8] = {0xbfffff0cu,0xffffffffu,0xffffffffu,0xffffffffu,0xffffffffu,0xffffffffu,0xffffffffu,0x3fffffffu};
    volatile uint32_t *m = (volatile uint32_t *)RSA_MEM_M_BLOCK_BASE;
    volatile uint32_t *x = (volatile uint32_t *)RSA_MEM_X_BLOCK_BASE;
    volatile uint32_t *y = (volatile uint32_t *)RSA_MEM_Y_BLOCK_BASE;
    volatile uint32_t *z = (volatile uint32_t *)RSA_MEM_Z_BLOCK_BASE;
    for (unsigned i=0;i<8;i++) {
        const unsigned char *bytes=in+28-4*i;
        x[i]=((uint32_t)bytes[0]<<24)|((uint32_t)bytes[1]<<16)|((uint32_t)bytes[2]<<8)|bytes[3];
        m[i]=p[i];y[i]=exponent[i];z[i]=rr[i];
    }
    mpi_ll_write_m_prime(0xd2253531u);mpi_ll_set_mode(7);
    mpi_ll_disable_constant_time();mpi_ll_enable_search();mpi_ll_set_search_position(253);
    mpi_ll_clear_interrupt();mpi_ll_start_op(MPI_MODEXP);
    while(mpi_ll_get_int_status()){} mpi_ll_clear_interrupt();
    for(unsigned i=0;i<8;i++) { uint32_t value=z[i];unsigned char *bytes=out+28-4*i;bytes[0]=value>>24;bytes[1]=value>>16;bytes[2]=value>>8;bytes[3]=value; }
    s.mod_loaded=0;s.resident_x_valid=0;configure_montgomery();
    if(!owned)blst_hw_release();
    return 1;
}

int blst_mpi_raw_multiply(uint32_t *out, const uint32_t *a, const uint32_t *b, size_t words)
{
    if (!words || words > 48 || !s.lock_held || s.owner != xTaskGetCurrentTaskHandle()) return 0;
    volatile uint32_t *x = (volatile uint32_t *)RSA_MEM_X_BLOCK_BASE;
    volatile uint32_t *z = (volatile uint32_t *)RSA_MEM_Z_BLOCK_BASE;
    for (size_t i = 0; i < words; i++) { x[i] = a[i]; z[i] = 0; z[words+i] = b[i]; }
    mpi_ll_set_mode(words*2-1);
    mpi_ll_clear_interrupt(); mpi_ll_start_op(MPI_MULT);
    while (mpi_ll_get_int_status()) {}
    mpi_ll_clear_interrupt();
    for (size_t i = 0; i < words*2; i++) out[i] = z[i];
    s.mod_loaded = 0; s.resident_x_valid = 0; configure_montgomery();
    return 1;
}

/* Experimental secp256k1 product using the raw multiplier and fixed-count
 * pseudo-Mersenne reduction. Measured separately before considering a field
 * representation change in libsecp256k1. Input/output are canonical bytes. */
int blst_mpi_secp_multiply(unsigned char out[32],const unsigned char a[32],const unsigned char b[32])
{
    uint32_t aw[8],bw[8],wide[16],low[8],difference[8];
    for(unsigned i=0;i<8;i++) {
        const unsigned char *x=a+28-4*i,*y=b+28-4*i;
        aw[i]=((uint32_t)x[0]<<24)|((uint32_t)x[1]<<16)|((uint32_t)x[2]<<8)|x[3];
        bw[i]=((uint32_t)y[0]<<24)|((uint32_t)y[1]<<16)|((uint32_t)y[2]<<8)|y[3];
    }
    if(!blst_mpi_raw_multiply(wide,aw,bw,8))return 0;
    uint64_t carry=0;
    for(unsigned i=0;i<8;i++) {
        uint64_t value=(uint64_t)wide[i]+(uint64_t)wide[i+8]*977+(i?wide[i+7]:0)+carry;
        low[i]=(uint32_t)value;carry=value>>32;
    }
    uint64_t high=(uint64_t)wide[15]+carry;
    uint32_t h0=(uint32_t)high,h1=(uint32_t)(high>>32);
    carry=0;
    for(unsigned i=0;i<8;i++) {
        uint64_t add=i==0?(uint64_t)h0*977:i==1?(uint64_t)h0+(uint64_t)h1*977:i==2?h1:0;
        uint64_t value=(uint64_t)low[i]+add+carry;low[i]=(uint32_t)value;carry=value>>32;
    }
    /* Fixed second fold handles the possible carry at bit256. */
    uint32_t overflow=(uint32_t)carry;carry=0;
    for(unsigned i=0;i<8;i++) {
        uint64_t add=i==0?(uint64_t)overflow*977:i==1?overflow:0;
        uint64_t value=(uint64_t)low[i]+add+carry;low[i]=(uint32_t)value;carry=value>>32;
    }
    static const uint32_t p[8]={0xfffffc2fu,0xfffffffeu,0xffffffffu,0xffffffffu,0xffffffffu,0xffffffffu,0xffffffffu,0xffffffffu};
    uint64_t borrow=0;
    for(unsigned i=0;i<8;i++){uint64_t v=(uint64_t)low[i]-p[i]-borrow;difference[i]=(uint32_t)v;borrow=v>>63;}
    uint32_t mask=0u-(uint32_t)(carry || !borrow);
    for(unsigned i=0;i<8;i++) {
        uint32_t value=(difference[i]&mask)|(low[i]&~mask);unsigned char *x=out+28-4*i;
        x[0]=value>>24;x[1]=value>>16;x[2]=value>>8;x[3]=value;
    }
    return 1;
}

#else /* !CONFIG_IDF_TARGET_ESP32C3: pure software, no-op locking */

int blst_mpi_secp_multiply(unsigned char out[32],const unsigned char a[32],const unsigned char b[32])
{(void)out;(void)a;(void)b;return 0;}
int blst_mpi_fp2(void *out,const void *a,const void *b,const void *mod,unsigned int n0,int square)
{ (void)out;(void)a;(void)b;(void)mod;(void)n0;(void)square;return 0; }
int blst_mpi_secp_sqrt(unsigned char out[32], const unsigned char in[32])
{ (void)out; (void)in; return 0; }
int blst_mpi_raw_multiply(uint32_t *out, const uint32_t *a, const uint32_t *b, size_t words)
{ (void)out; (void)a; (void)b; (void)words; return 0; }

void blst_hw_acquire(void) {}
void blst_hw_release(void) {}
void blst_mpi_set_enabled(int enabled) { (void)enabled; }
int blst_mpi_enabled(void) { return 0; }
void blst_mpi_set_options(unsigned options) { (void)options; }
unsigned blst_mpi_options(void) { return 0; }
int blst_mpi_fixed_exp_384(void *out, const void *in, unsigned which)
{ (void)out; (void)in; (void)which; return 0; }
int blst_mpi_square_chain_384(void *out, const void *in, size_t count)
{ (void)out; (void)in; (void)count; return 0; }

void mpi_mul_mont_n(uint32_t ret[], const uint32_t a[], const uint32_t b[],
                    const uint32_t p[], uint32_t n0, size_t n)
{
    sw_mul_mont_n(ret, a, b, p, n0, n);
}

#endif
