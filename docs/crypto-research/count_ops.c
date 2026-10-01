/* Arithmetic probe only: 32-bit blst limbs on a host, no MCU timings.
 * Fixtures use small test mint keys and opaque 33-byte BLS messages; this is
 * not a Nutroot secret-validation/conformance test. Batch weights below use
 * the production Cashu transcript and rejection-sampling implementation. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <blst.h>
#include <blst_aux.h>
#include "crypto_bls.c"

/* The probe exercises no KDF; fail loudly if that changes. */
int cashu_nut13_hmac(const unsigned char *seed, size_t seed_len,
    const char *kid, uint32_t counter, unsigned char type,
    const unsigned char *suffix, size_t suffix_len, unsigned char out[32]) {
    abort();
}

extern unsigned long long research_fp_ops;
static const unsigned char dst[] = "CASHU_BLS12_381_G1_XMD:SHA-256_SSWU_RO_";
static void row(const char *name) {
    printf("%s,%llu\n", name, research_fp_ops);
    research_fp_ops = 0;
}
static void mult(blst_p1 *out, const blst_p1 *in, const blst_scalar *s) {
    unsigned char le[32]; blst_lendian_from_scalar(le, s);
    blst_p1_mult(out, in, le, 256);
}
static void small(blst_scalar *s, unsigned v) {
    unsigned char be[32] = {0}; be[31] = v;
    blst_scalar_from_bendian(s, be);
}
int main(void) {
    enum { N=10 };
    blst_p1 y[N], c[N], wy[N], wc[N], sumc;
    blst_p1_affine ca[N], ps[N+1];
    blst_p2_affine qs[N+1];
    blst_scalar w[N]; unsigned char sle[N][32];
    const unsigned char *sps[N];
    const blst_p1_affine *cap[N], *pp[N+1];
    const blst_p2_affine *qp[N+1];
    unsigned char compressed[N][48];
    for(int i=0;i<N;i++) {
        unsigned char sec[33] = {2}, hash[32], be[32]; sec[32]=i;
        blst_hash_to_g1(&y[i],sec,33,dst,sizeof(dst)-1,NULL,0);
        blst_scalar a; small(&a,i+2); mult(&c[i],&y[i],&a);
        blst_p2 k; blst_p2_mult(&k,blst_p2_generator(),a.b,256);
        blst_p2_to_affine(&qs[i],&k);
        blst_p1_to_affine(&ca[i],&c[i]);cap[i]=&ca[i];
        blst_p1_compress(compressed[i],&c[i]);
        blst_sha256(hash,sec,33);memcpy(be,hash,32);be[0] &= 0x3f;
        blst_scalar_from_bendian(&w[i],be);blst_lendian_from_scalar(sle[i],&w[i]);sps[i]=sle[i];
        mult(&wy[i],&y[i],&w[i]);mult(&wc[i],&c[i],&w[i]);
        if(i==0)sumc=wc[i];else blst_p1_add(&sumc,&sumc,&wc[i]);
        blst_p1_to_affine(&ps[i],&wy[i]);qp[i]=&qs[i];pp[i]=&ps[i];
    }
    unsigned char transcript[BATCH_DST_LEN+N*(48+96+4+33)],challenge[32];
    size_t off=0;memcpy(transcript,BATCH_DST,BATCH_DST_LEN);off+=BATCH_DST_LEN;
    for(int i=0;i<N;i++) {
        memcpy(transcript+off,compressed[i],48);off+=48;
        blst_p2_affine_compress(transcript+off,&qs[i]);off+=96;
        transcript[off++]=0;transcript[off++]=0;transcript[off++]=0;transcript[off++]=33;
        memset(transcript+off,0,33);transcript[off]=2;transcript[off+32]=i;off+=33;
    }
    blst_sha256(challenge,transcript,off);
    for(int i=0;i<N;i++) {
        derive_batch_weight(&w[i],challenge,i);
        blst_lendian_from_scalar(sle[i],&w[i]);
        mult(&wy[i],&y[i],&w[i]);mult(&wc[i],&c[i],&w[i]);
        if(i==0)sumc=wc[i];else blst_p1_add(&sumc,&sumc,&wc[i]);
        blst_p1_to_affine(&ps[i],&wy[i]);
    }
    blst_p1_cneg(&sumc,1);blst_p1_to_affine(&ps[N],&sumc);
    qs[N]=*blst_p2_affine_generator();qp[N]=&qs[N];pp[N]=&ps[N];
    research_fp_ops=0;puts("operation,fp_montgomery_calls");
    blst_p1 temp;
    unsigned char msg[33]={2};
    blst_hash_to_g1(&temp,msg,33,dst,sizeof(dst)-1,NULL,0);row("hash_to_g1");
    blst_p1_affine va;blst_p2_affine vk;unsigned char kc[96];
    blst_p2_affine_compress(kc,&qs[0]);research_fp_ops=0;
    if(blst_p1_uncompress(&va,compressed[0]) || !blst_p1_affine_in_g1(&va))return 1;
    row("validate_g1");
    if(blst_p2_uncompress(&vk,kc) || !blst_p2_affine_in_g2(&vk))return 2;
    row("validate_g2");
    mult(&temp,&y[0],&w[0]);row("g1_scalar_mul");
    blst_p1_affine aa;blst_p1_to_affine(&aa,&temp);row("to_affine_one");
    const blst_p1 *wps[N];for(int i=0;i<N;i++)wps[i]=&wy[i];
    blst_p1_affine affs[N];blst_p1s_to_affine(affs,wps,N);row("to_affine_batch10");
    blst_p1 seq,res;
    for(int i=0;i<N;i++) {mult(&temp,&c[i],&w[i]);if(i==0)seq=temp;else blst_p1_add(&seq,&seq,&temp);}
    row("sum_C_sequential10");
    size_t scratch_bytes=blst_p1s_mult_pippenger_scratch_sizeof(N);
    void *scratch=calloc(1,scratch_bytes);
    blst_p1s_mult_pippenger(&res,cap,N,sps,256,scratch);
    row("sum_C_msm_api10");
    if(!blst_p1_is_equal(&res,&seq))return 3;
    fprintf(stderr,"pippenger10_scratch_bytes=%zu\n",scratch_bytes);free(scratch);
    for(int chunk=1;chunk<=11;chunk++) {
        if(chunk!=1&&chunk!=4&&chunk!=8&&chunk!=11)continue;
        blst_fp12 acc=*blst_fp12_one(),ml,gt;
        for(int j=0;j<N+1;j+=chunk) {
            size_t n=N+1-j;if(n>(size_t)chunk)n=chunk;
            blst_miller_loop_n(&ml,qp+j,pp+j,n);blst_fp12_mul(&acc,&acc,&ml);
        }
        char name[64];snprintf(name,sizeof(name),"miller_11pairs_chunk%d",chunk);row(name);
        blst_final_exp(&gt,&acc);row("final_exp_valid_batch");
        if(!blst_fp12_is_one(&gt))return 4;
    }
    blst_fp6 lines[68];blst_fp12 ml,ref;
    blst_precompute_lines(lines,&qs[0]);row("precompute_one_G2_lines");
    blst_miller_loop_lines(&ml,lines,&ps[0]);row("miller_one_prepared");
    blst_miller_loop(&ref,&qs[0],&ps[0]);row("miller_one_unprepared");
    if(!blst_fp12_is_equal(&ml,&ref))return 5;
    unsigned char keys[N*96], cs[N*48], secrets[N][33];
    const unsigned char *sp[N];size_t sl[N];
    for(int i=0;i<N;i++) {
        blst_p2_affine_compress(keys+i*96,&qs[i]);
        memcpy(cs+i*48,compressed[i],48);memset(secrets[i],0,33);
        secrets[i][0]=2;secrets[i][32]=i;sp[i]=secrets[i];sl[i]=33;
    }
    research_fp_ops=0;
    if(!cashu_suite_bls.verify_proofs(NULL,N,keys,cs,sp,sl))return 6;
    row("production_verify_distinct10");
    secrets[0][2]^=1;
    if(cashu_suite_bls.verify_proofs(NULL,N,keys,cs,sp,sl))return 7;
    research_fp_ops=0;
    fprintf(stderr,"prepared_lines_bytes=%zu; all comparisons passed\n",sizeof(lines));
    return 0;
}
