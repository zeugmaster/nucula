/* Experimental public commitment batch: P_i = K_i + t_i G.
 * Normalize the differences together, then verify one full-width weighted
 * equation. This never batches secret scalar multiplications. */
size_t secp256k1_nucula_tweak_scratch_size(size_t n) {
    if(!n||n>32)return 0;
    size_t temporary=n*(sizeof(secp256k1_gej)+sizeof(secp256k1_ge));
    size_t msm=secp256k1_strauss_scratch_size(n)+16*ALIGNMENT;
    return ROUND_TO_ALIGN(n*sizeof(nucula_batch_term))+(temporary>msm?temporary:msm);
}
int secp256k1_nucula_verify_tweaks(const secp256k1_context *ctx,size_t n,
 const unsigned char *P,const unsigned char *K,const unsigned char *t,void *memory,size_t size) {
    if(!n)return 1;
    size_t required=secp256k1_nucula_tweak_scratch_size(n);
    if(!ctx||!P||!K||!t||!memory||!required||size<required)return 0;
    nucula_batch_term *terms=memory;
    size_t offset=ROUND_TO_ALIGN(n*sizeof(*terms));
    secp256k1_gej *difference=(void *)((unsigned char *)memory+offset);
    secp256k1_ge *affine=(void *)(difference+n);
    secp256k1_sha256 sha;secp256k1_rfc6979_hmac_sha256 rng;
    unsigned char seed[32],bytes[32],count[4]={0,0,0,(unsigned char)n};
    static const unsigned char domain[]="Nucula/Nutroot/commitments/v1";
    secp256k1_sha256_initialize(&sha);secp256k1_sha256_write(&sha,domain,sizeof(domain)-1);
    secp256k1_sha256_write(&sha,count,4);secp256k1_sha256_write(&sha,P,33*n);
    secp256k1_sha256_write(&sha,K,33*n);secp256k1_sha256_write(&sha,t,32*n);
    secp256k1_sha256_finalize(&sha,seed);secp256k1_rfc6979_hmac_sha256_initialize(&rng,seed,32);
    secp256k1_scalar generator=secp256k1_scalar_zero;
    for(size_t i=0;i<n;i++) {
        secp256k1_ge point,key;secp256k1_scalar tweak,weight,product;int overflow;
        if(!secp256k1_eckey_pubkey_parse(&point,P+33*i,33)||!secp256k1_eckey_pubkey_parse(&key,K+33*i,33))return 0;
        secp256k1_ge_neg(&key,&key);secp256k1_gej_set_ge(&difference[i],&point);
        secp256k1_gej_add_ge_var(&difference[i],&difference[i],&key,NULL);
        secp256k1_scalar_set_b32(&tweak,t+32*i,&overflow);if(overflow)return 0;
        if(!i)secp256k1_scalar_set_int(&weight,1);
        else do {secp256k1_rfc6979_hmac_sha256_generate(&rng,bytes,32);secp256k1_scalar_set_b32(&weight,bytes,&overflow);}
            while(overflow||secp256k1_scalar_is_zero(&weight));
        terms[i].scalar=weight;secp256k1_scalar_mul(&product,&weight,&tweak);
        secp256k1_scalar_add(&generator,&generator,&product);
    }
    secp256k1_rfc6979_hmac_sha256_finalize(&rng);
    secp256k1_ge_set_all_gej_var(affine,difference,n);
    for(size_t i=0;i<n;i++)terms[i].point=affine[i];
    secp256k1_scalar_negate(&generator,&generator);
    secp256k1_scratch scratch;memset(&scratch,0,sizeof(scratch));memcpy(scratch.magic,"scratch",8);
    scratch.data=(unsigned char *)memory+offset;scratch.max_size=size-offset;
    secp256k1_gej result;
    return secp256k1_ecmult_multi_var(&ctx->error_callback,&scratch,&result,&generator,nucula_batch_callback,terms,n)&&secp256k1_gej_is_infinity(&result);
}
