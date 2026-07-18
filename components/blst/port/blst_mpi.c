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
 * n0 and the zero exponent stay resident across calls; operand A is only
 * rewritten when it differs from the resident X (t = t*x chains skip it);
 * operand B is always rewritten (the early exit clobbers Z memory).
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
#include "soc/hwcrypto_reg.h" /* RSA_MEM_*_BLOCK_BASE */

static struct {
    volatile int lock_held;
    int warned_unlocked;
    int enabled;
    int mod_loaded;
    uint32_t mod[FP_WORDS];
    uint32_t n0;
    uint32_t resident_x[FP_WORDS];
    int resident_x_valid;
} s = { .enabled = 1 };

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
    s.lock_held = 1;
}

void blst_hw_release(void)
{
    s.lock_held = 0;
    esp_crypto_mpi_enable_periph_clk(false);
    esp_crypto_mpi_lock_release();
}

void blst_mpi_set_enabled(int enabled) { s.enabled = enabled; }
int blst_mpi_enabled(void) { return s.enabled; }

static void mpi_mont_mul_384(uint32_t ret[], const uint32_t a[],
                             const uint32_t b[], const uint32_t p[],
                             uint32_t n0)
{
    volatile uint32_t *m_mem = (volatile uint32_t *)RSA_MEM_M_BLOCK_BASE;
    volatile uint32_t *z_mem = (volatile uint32_t *)RSA_MEM_Z_BLOCK_BASE;
    volatile uint32_t *y_mem = (volatile uint32_t *)RSA_MEM_Y_BLOCK_BASE;
    volatile uint32_t *x_mem = (volatile uint32_t *)RSA_MEM_X_BLOCK_BASE;

    /* Re-assert mode + the early-exit configuration every call: four cheap
     * register writes, and the driver stays correct even if another user
     * flipped them inside our hold window. */
    mpi_hal_set_mode(FP_WORDS - 1);
    mpi_hal_enable_constant_time(false);
    mpi_hal_enable_search(true);
    mpi_hal_set_search_position(0);

    /* Modulus + n0 + zero exponent: resident across the hold window. */
    if (!s.mod_loaded || s.n0 != n0 || memcmp(s.mod, p, sizeof(s.mod)) != 0) {
        for (int i = 0; i < FP_WORDS; i++) {
            m_mem[i] = p[i];
            y_mem[i] = 0; /* exponent = 0 */
        }
        mpi_hal_write_m_prime(n0);
        memcpy(s.mod, p, sizeof(s.mod));
        s.n0 = n0;
        s.mod_loaded = 1;
        s.resident_x_valid = 0;
    }

    /* Operand A -> X, skipped when it matches the resident X (the previous
     * result), which is the common t = t*x chain in field towers. */
    if (!s.resident_x_valid || memcmp(s.resident_x, a, sizeof(s.resident_x)) != 0) {
        for (int i = 0; i < FP_WORDS; i++)
            x_mem[i] = a[i];
    }

    /* Operand B -> Z, always: the early exit clobbers Z each op. */
    for (int i = 0; i < FP_WORDS; i++)
        z_mem[i] = b[i];

    mpi_hal_start_op(MPI_MODEXP);
    mpi_hal_wait_op_complete();

    /* Result is in X memory (there is no HAL reader for X; the operand RAM
     * is plain APB-mapped memory). Capture it as the new resident X. */
    for (int i = 0; i < FP_WORDS; i++) {
        uint32_t v = x_mem[i];
        ret[i] = v;
        s.resident_x[i] = v;
    }
    s.resident_x_valid = 1;
}

void mpi_mul_mont_n(uint32_t ret[], const uint32_t a[], const uint32_t b[],
                    const uint32_t p[], uint32_t n0, size_t n)
{
    if (n == FP_WORDS && s.enabled) {
        if (s.lock_held) {
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

#else /* !CONFIG_IDF_TARGET_ESP32C3: pure software, no-op locking */

void blst_hw_acquire(void) {}
void blst_hw_release(void) {}
void blst_mpi_set_enabled(int enabled) { (void)enabled; }
int blst_mpi_enabled(void) { return 0; }

void mpi_mul_mont_n(uint32_t ret[], const uint32_t a[], const uint32_t b[],
                    const uint32_t p[], uint32_t n0, size_t n)
{
    sw_mul_mont_n(ret, a, b, p, n0, n);
}

#endif
