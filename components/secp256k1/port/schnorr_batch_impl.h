/* Local bounded-memory BIP-340 batch equation, using upstream point/scalar,
 * SHA256/HMAC-DRBG and MSM implementations. Public data throughout. */
typedef struct {
    secp256k1_scalar scalar;
    secp256k1_ge point;
} nucula_batch_term;
static int nucula_batch_callback(secp256k1_scalar *scalar, secp256k1_ge *point,
                                 size_t index, void *data) {
    const nucula_batch_term *terms=data;
    *scalar=terms[index].scalar;*point=terms[index].point;return 1;
}
size_t secp256k1_nucula_batch_scratch_size(size_t n,unsigned algorithm) {
    size_t msm;
    if (!n || n>32 || algorithm>1) return 0;
    msm=algorithm?secp256k1_pippenger_scratch_size(2*n,secp256k1_pippenger_bucket_window(2*n)):
                  secp256k1_strauss_scratch_size(2*n);
    return ROUND_TO_ALIGN(2*n*sizeof(nucula_batch_term))+msm+16*ALIGNMENT;
}
int secp256k1_nucula_verify_batch(const secp256k1_context *ctx,size_t n,
                                  const unsigned char *signatures,
                                  const unsigned char *messages,
                                  const unsigned char *public_keys,
                                  void *memory,size_t size,unsigned algorithm) {
    secp256k1_sha256 sha;
    secp256k1_rfc6979_hmac_sha256 rng;
    secp256k1_scalar generator=secp256k1_scalar_zero;
    secp256k1_gej result;
    nucula_batch_term *terms=memory;
    unsigned char seed[32],bytes[32],count[4];
    static const unsigned char domain[]="Nucula/BIP340/batch/v1";
    secp256k1_scratch scratch;
    size_t required=secp256k1_nucula_batch_scratch_size(n,algorithm),i;
    if (!n) return 1;
    if (!ctx || !required || !memory || size<required || !signatures || !messages || !public_keys) return 0;
    count[0]=count[1]=count[2]=0;count[3]=(unsigned char)n;
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha,domain,sizeof(domain)-1);
    secp256k1_sha256_write(&sha,count,4);
    secp256k1_sha256_write(&sha,public_keys,32*n);
    secp256k1_sha256_write(&sha,messages,32*n);
    secp256k1_sha256_write(&sha,signatures,64*n);
    secp256k1_sha256_finalize(&sha,seed);
    secp256k1_rfc6979_hmac_sha256_initialize(&rng,seed,32);
    for(i=0;i<n;i++) {
        secp256k1_scalar a,s,e,product;
        secp256k1_fe x;
        int overflow;
        if (!secp256k1_fe_set_b32_limit(&x,public_keys+32*i) ||
            !secp256k1_ge_set_xo_var(&terms[2*i+1].point,&x,0) ||
            !secp256k1_fe_set_b32_limit(&x,signatures+64*i) ||
            !secp256k1_ge_set_xo_var(&terms[2*i].point,&x,0)) return 0;
        secp256k1_scalar_set_b32(&s,signatures+64*i+32,&overflow);
        if (overflow) return 0;
        if (!i) secp256k1_scalar_set_int(&a,1);
        else do {
            secp256k1_rfc6979_hmac_sha256_generate(&rng,bytes,32);
            secp256k1_scalar_set_b32(&a,bytes,&overflow);
        } while (overflow || secp256k1_scalar_is_zero(&a));
        secp256k1_schnorrsig_challenge(&e,signatures+64*i, messages+32*i,32,public_keys+32*i);
        terms[2*i].scalar=a;
        secp256k1_scalar_mul(&terms[2*i+1].scalar,&a,&e);
        secp256k1_scalar_mul(&product,&a,&s);
        secp256k1_scalar_add(&generator,&generator,&product);
    }
    secp256k1_rfc6979_hmac_sha256_finalize(&rng);
    secp256k1_scalar_negate(&generator,&generator);
    memset(&scratch,0,sizeof(scratch));memcpy(scratch.magic,"scratch",8);
    scratch.data=(unsigned char *)memory+ROUND_TO_ALIGN(2*n*sizeof(*terms));
    scratch.max_size=size-ROUND_TO_ALIGN(2*n*sizeof(*terms));
    if (algorithm) {
        if (!secp256k1_ecmult_pippenger_batch_single(&ctx->error_callback,&scratch,&result,&generator,nucula_batch_callback,terms,2*n)) return 0;
    } else if (!secp256k1_ecmult_multi_var(&ctx->error_callback,&scratch,&result,&generator,nucula_batch_callback,terms,2*n)) return 0;
    return secp256k1_gej_is_infinity(&result);
}
