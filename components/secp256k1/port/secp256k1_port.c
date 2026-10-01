/* Interpose one fixed-public-exponent primitive without modifying upstream.
 * field.h declares the original function; its implementation is compiled under
 * a reference name, then group arithmetic sees the checked wrapper below. */
#define SECP256K1_BUILD
#include "../libsecp256k1/include/secp256k1.h"
#include "../libsecp256k1/src/field.h"
static int secp256k1_fe_sqrt_reference(secp256k1_fe *r, const secp256k1_fe *a);
#define secp256k1_fe_sqrt secp256k1_fe_sqrt_reference
#include "../libsecp256k1/src/field_impl.h"
#undef secp256k1_fe_sqrt
#ifdef ESP_PLATFORM
#include <blst_mpi.h>
#endif
static int secp256k1_fe_sqrt(secp256k1_fe *r, const secp256k1_fe *a) {
#ifdef ESP_PLATFORM
    if (blst_mpi_options() & BLST_MPI_SECP_SQRT) {
        secp256k1_fe normal = *a, check;
        unsigned char input[32], output[32];
        secp256k1_fe_normalize(&normal);secp256k1_fe_get_b32(input,&normal);
        if (blst_mpi_secp_sqrt(output,input)) {
            if (!secp256k1_fe_set_b32_limit(r,output)) return 0;
            secp256k1_fe_sqr(&check,r);
            return secp256k1_fe_equal(&check,&normal);
        }
    }
#endif
    return secp256k1_fe_sqrt_reference(r,a);
}
#ifdef ESP_PLATFORM
#include "nucula_hash_impl.h"
#endif
/* Keep the upstream submodule unchanged; local additions share its internals. */
#ifdef ESP_PLATFORM
#include "nucula_secp_impl.c"
#else
#include "../libsecp256k1/src/secp256k1.c"
#endif
#ifdef ENABLE_MODULE_SCHNORRSIG
#include "schnorr_batch_impl.h"
#include "tweak_batch_impl.h"
#endif

/* Public synthetic arithmetic calibration; loop result is observable. */
void secp256k1_nucula_field_chain(unsigned char out[32], size_t count, unsigned operation) {
    if (operation < 2) {
        secp256k1_fe a=secp256k1_ge_const_g.x,b=secp256k1_ge_const_g.y;
        for (size_t i=0;i<count;i++) {
            if (operation) secp256k1_fe_sqr(&a,&a);
            else secp256k1_fe_mul(&a,&a,&b);
        }
        secp256k1_fe_normalize(&a);secp256k1_fe_get_b32(out,&a);
    } else {
        secp256k1_scalar a,b;
        secp256k1_scalar_set_int(&a,17);secp256k1_scalar_set_int(&b,31);
        for (size_t i=0;i<count;i++) secp256k1_scalar_mul(&a,&a,&b);
        secp256k1_scalar_get_b32(out,&a);
    }
}

int secp256k1_nucula_sqrt_compare(size_t count) {
    unsigned state=0x3c317b49u;
    for (size_t i=0;i<count;i++) {
        unsigned char bytes[32],candidate[32],reference[32];
        secp256k1_fe a,x,y;
        for (size_t j=0;j<32;j++) { state^=state<<13;state^=state>>17;state^=state<<5;bytes[j]=(unsigned char)state; }
        if (!i) memset(bytes,0,32);
        if (i==1) { memset(bytes,0,32);bytes[31]=1; }
        secp256k1_fe_set_b32_mod(&a,bytes);
        int got=secp256k1_fe_sqrt(&x,&a),want=secp256k1_fe_sqrt_reference(&y,&a);
        secp256k1_fe_normalize(&x);secp256k1_fe_get_b32(candidate,&x);
        secp256k1_fe_normalize(&y);secp256k1_fe_get_b32(reference,&y);
        if(got!=want || memcmp(candidate,reference,32))return 0;
    }
    return 1;
}

int secp256k1_nucula_hwfield_chain(unsigned char out[32],size_t count,int square) {
#ifdef ESP_PLATFORM
    secp256k1_fe a=secp256k1_ge_const_g.x,b=secp256k1_ge_const_g.y;
    unsigned char ab[32],bb[32];
    blst_hw_acquire();int ok=1;
    for(size_t i=0;i<count&&ok;i++) {
        secp256k1_fe_normalize(&a);secp256k1_fe_get_b32(ab,&a);
        secp256k1_fe_normalize(&b);secp256k1_fe_get_b32(bb,&b);
        ok=blst_mpi_secp_multiply(out,ab,square?ab:bb)&&secp256k1_fe_set_b32_limit(&a,out);
    }
    blst_hw_release();return ok;
#else
    (void)out;(void)count;(void)square;return 0;
#endif
}
int secp256k1_nucula_hwfield_compare(size_t count) {
#ifdef ESP_PLATFORM
    unsigned state=0x73518e43u;int ok=1;blst_hw_acquire();
    for(size_t i=0;i<count&&ok;i++) {
        unsigned char ab[32],bb[32],got[32],want[32];secp256k1_fe a,b,c;
        for(unsigned j=0;j<32;j++){state^=state<<13;state^=state>>17;state^=state<<5;ab[j]=(unsigned char)state;bb[j]=(unsigned char)(state>>8);}
        if(i<3){memset(ab,i?0xff:0,32);memset(bb,i==2?1:0xff,32);}
        if(i==3){memset(ab,255,32);ab[27]=0xfe;ab[30]=0xfc;ab[31]=0x2e;memcpy(bb,ab,32);} /* (p-1)^2 */
        secp256k1_fe_set_b32_mod(&a,ab);secp256k1_fe_set_b32_mod(&b,bb);secp256k1_fe_normalize(&a);secp256k1_fe_normalize(&b);
        secp256k1_fe_get_b32(ab,&a);secp256k1_fe_get_b32(bb,&b);secp256k1_fe_mul(&c,&a,&b);
        secp256k1_fe_normalize(&c);secp256k1_fe_get_b32(want,&c);
        ok=blst_mpi_secp_multiply(got,ab,bb)&&!memcmp(got,want,32);
    }
    blst_hw_release();return ok;
#else
    (void)count;return 1;
#endif
}

/* Verification-only public DLEQ scalars. R1=sG-eA and R2=sB-eC share
 * doublings through the upstream Strauss engine. Return -1 on allocation
 * failure so the caller can use the ordinary separate calculations. */
int secp256k1_nucula_dleq_points(const secp256k1_context *ctx,secp256k1_pubkey out[2],
 const secp256k1_pubkey *A,const secp256k1_pubkey *B,const secp256k1_pubkey *C,
 const unsigned char e32[32],const unsigned char s32[32]) {
    if(!ctx||!out||!A||!B||!C||!e32||!s32)return 0;
    secp256k1_scalar e,s;int overflow;
    secp256k1_scalar_set_b32(&e,e32,&overflow);if(overflow||secp256k1_scalar_is_zero(&e))return 0;
    secp256k1_scalar_set_b32(&s,s32,&overflow);if(overflow||secp256k1_scalar_is_zero(&s))return 0;
    secp256k1_scalar_negate(&e,&e);
    nucula_batch_term terms[2];secp256k1_ge a,affine;secp256k1_gej result;
    if(!secp256k1_pubkey_load(ctx,&a,A)||!secp256k1_pubkey_load(ctx,&terms[0].point,B)||!secp256k1_pubkey_load(ctx,&terms[1].point,C))return 0;
    size_t bytes=secp256k1_strauss_scratch_size(2)+16*ALIGNMENT;void *memory=malloc(bytes);if(!memory)return -1;
    secp256k1_gej_set_ge(&result,&a);secp256k1_ecmult(&result,&result,&e,&s);
    int ok=!secp256k1_gej_is_infinity(&result);
    if(ok){secp256k1_ge_set_gej_var(&affine,&result);secp256k1_pubkey_save(&out[0],&affine);}
    terms[0].scalar=s;terms[1].scalar=e;
    secp256k1_scratch scratch;memset(&scratch,0,sizeof(scratch));memcpy(scratch.magic,"scratch",8);
    scratch.data=memory;scratch.max_size=bytes;
    ok=ok&&secp256k1_ecmult_multi_var(&ctx->error_callback,&scratch,&result,NULL,nucula_batch_callback,terms,2)&&!secp256k1_gej_is_infinity(&result);
    if(ok){secp256k1_ge_set_gej_var(&affine,&result);secp256k1_pubkey_save(&out[1],&affine);}
    free(memory);return ok;
}
/* Unlike the public tweak multiplication API, this path treats its scalar
 * as secret. Used for the wallet's legacy unblinding factor. */
int secp256k1_nucula_secret_multiply(const secp256k1_context *ctx,secp256k1_pubkey *out,
 const secp256k1_pubkey *point,const unsigned char scalar32[32]) {
    if(!ctx||!out||!point||!scalar32)return 0;
    secp256k1_scalar scalar;int overflow;secp256k1_ge affine;secp256k1_gej result;
    secp256k1_scalar_set_b32(&scalar,scalar32,&overflow);
    if(overflow||secp256k1_scalar_is_zero(&scalar)||!secp256k1_pubkey_load(ctx,&affine,point)) {
        secp256k1_scalar_clear(&scalar);return 0;
    }
    secp256k1_ecmult_const(&result,&affine,&scalar);secp256k1_ge_set_gej(&affine,&result);
    secp256k1_pubkey_save(out,&affine);secp256k1_scalar_clear(&scalar);
    secp256k1_memclear_explicit(&result,sizeof(result));secp256k1_memclear_explicit(&affine,sizeof(affine));return 1;
}
