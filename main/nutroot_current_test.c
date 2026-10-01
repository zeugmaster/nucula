/* Current proposal, pinned to nuts#421 a3f04b97154b (2026-09-10).
 * Public examples from tests/10-tests.md and tests/28-tests.md. */
#include "nutroot_current_test.h"
#include "nutroot.h"
#include "nutroot_prepare.h"
#include "hex.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_nucula.h>
#ifdef ESP_PLATFORM
#include <esp_log.h>
#define REPORT(...) ESP_LOGI("nutroot_current", __VA_ARGS__)
#else
#define REPORT(...) do { printf(__VA_ARGS__); puts(""); } while (0)
#endif
#define CHECK(e) do { if (!(e)) { REPORT("FAILED at line %d: %s", __LINE__, #e); return 0; } } while (0)
static int equal_hex(const unsigned char *bytes, size_t n, const char *hex) {
    unsigned char expected[96];
    return n <= sizeof(expected) && hex_to_bytes(hex, expected, n) && !memcmp(bytes,expected,n);
}
static int public_key(const secp256k1_context *ctx, const unsigned char sk[32], unsigned char out[33]) {
    secp256k1_pubkey p; size_t n=33;
    return secp256k1_ec_pubkey_create(ctx,&p,sk) && secp256k1_ec_pubkey_serialize(ctx,out,&n,&p,SECP256K1_EC_COMPRESSED);
}
int nutroot_current_run_tests(const secp256k1_context *ctx) {
    unsigned char id[33], secrets[2][33], signature[48], blind[48], txhash[32], digest[32];
    CHECK(hex_to_bytes("02b7e077d020fabed456a6be138a8e20e9ef40b44d873fa12c005b656eb0cf99f6",id,33));
    CHECK(hex_to_bytes("02e6e7cfa7b82d4b3b449fa6466c893469a727d0214d48db4956a6054b8022a29b",secrets[0],33));
    CHECK(hex_to_bytes("03a882e17eb79f4f87313b299e208f9109734d0211a8df307b1570dbad2cdf74bf",secrets[1],33));
    CHECK(hex_to_bytes("84d1b7291ae5737f3c851aa33cafe0f7afeb5ccb4da086c482bb85b7525e61547f1b5a6d1a01b1fed1f960d1a9d03327",signature,48));
    CHECK(hex_to_bytes("b42a0bcc39598db1dca617aeea6bc367f2566636826dc961a54faae15b3b8d10afc1cb0206e70ab3b0e12c2b9478cd55",blind,48));
    nutroot_input_t inputs[2]={
        {.amount=8,.keyset_id=id,.keyset_id_len=33,.secret=secrets[0],.secret_len=33,.C=signature,.C_len=48},
        {.amount=4,.keyset_id=id,.keyset_id_len=33,.secret=secrets[1],.secret_len=33,.C=signature,.C_len=48}};
    nutroot_output_t outputs[2]={
        {.amount=4,.keyset_id=id,.keyset_id_len=33,.B_=blind,.B_len=48},
        {.amount=4,.keyset_id=id,.keyset_id_len=33,.B_=blind,.B_len=48}};
    nutroot_tx_t tx={.proof_inputs=inputs,.n_proof_inputs=1,.blinded_outputs=outputs,.n_blinded_outputs=2};
    CHECK(nutroot_tx_digest(&tx,txhash));
    CHECK(equal_hex(txhash,32,"5985ee7a424a7d9ce66441eacac3165d0d933c4c31315c7cb2dacdb9579d01bb"));
    CHECK(nutroot_input_digest(txhash,&inputs[0],digest));
    CHECK(equal_hex(digest,32,"d988bdcfa1d7699324894fc5dba3a70e7bca534e644b257c9700debb424b4ec8"));
    inputs[0].witness="{\"signatures\":[\"678c1e71b29552ad86069bcc6d1965028b31df1e4dedf69fe5274ffefcad8c77593e474f581e7b43d9e5f8815c0babb607b17f22536ef5f2354889f088da3979\"]}";
    CHECK(nutroot_verify_transaction(ctx,&tx,2000000000));
    outputs[0].amount++;CHECK(!nutroot_verify_transaction(ctx,&tx,2000000000));outputs[0].amount--;
    tx.n_proof_inputs=2;outputs[0].amount=8;
    CHECK(nutroot_tx_digest(&tx,txhash));
    CHECK(equal_hex(txhash,32,"1544d76f577b7d567f429b482c1c081796f68f201edb3cafa75f68619d018a88"));
    static const char *digests[]={"0054406a4cf6bbfc11fed28e7c896310f43d1f8eea4d0f2f015541d5c4e86756","bdef95d2bb49c0d4d6de2119bf009808eb9d87141c9f539113c0a8d546aa234b"};
    inputs[0].witness="{\"signatures\":[\"f3d44abd44e262734e40f57bf3e3c4f60ab61242f7eb9751d149729e083621387ddca3141baffdda3b902068c2dd94aec5a16ade6b1153f3cf1ef0e1c6facc49\"]}";
    inputs[1].witness="{\"signatures\":[\"d3f93b9ae50290a82374d1382985b8fcae4658ab6d4c5e9454e41ce22d344a2ca2a6e9f04cdd199b4bbfb2becf0f260b86a5cbd500734a88f138cf7226b51ad1\"]}";
    for(size_t i=0;i<2;i++) { CHECK(nutroot_input_digest(txhash,&inputs[i],digest));CHECK(equal_hex(digest,32,digests[i])); }
    CHECK(nutroot_verify_transaction(ctx,&tx,2000000000));
    const char *saved=inputs[1].witness;inputs[1].witness=inputs[0].witness;
    CHECK(!nutroot_verify_transaction(ctx,&tx,2000000000));inputs[1].witness=saved;
    /* Keyset version decides dispatch; a malformed v3 point never skips. */
    unsigned char prefix=secrets[0][0];secrets[0][0]=4;
    CHECK(!nutroot_verify_transaction(ctx,&tx,2000000000));
    id[0]=1;CHECK(nutroot_verify_transaction(ctx,&tx,2000000000));id[0]=2;secrets[0][0]=prefix;
    tx.n_blinded_outputs=0;CHECK(!nutroot_verify_transaction(ctx,&tx,2000000000));tx.n_blinded_outputs=2;
    size_t oldlen=inputs[0].secret_len;inputs[0].secret_len=SIZE_MAX;CHECK(!nutroot_tx_digest(&tx,txhash));inputs[0].secret_len=oldlen;
    nutroot_quote_t mint={8,"quote-mint-0001"};
    tx.n_proof_inputs=0;tx.mint_quote_inputs=&mint;tx.n_mint_quote_inputs=1;tx.n_blinded_outputs=1;outputs[0].amount=8;
    CHECK(nutroot_tx_digest(&tx,txhash));CHECK(equal_hex(txhash,32,"271cb7d13b3de01fe693c8f1be0adcd7855ee2bed3532840778cdc9ff8a5b783"));
    CHECK(nutroot_quote_input_digest(txhash,&mint,digest));CHECK(equal_hex(digest,32,"ca6970e6795f610be199bc1d4705dec7ef31f3939dcd08b8a1e2ea4960565f39"));
    /* Disclosure is canonical and does not alter satisfaction. */
    unsigned char leaf[514];nutroot_leaf_t parsed;
    const char *lh="00010200010104002102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f90a000101";
    size_t len=strlen(lh)/2;CHECK(hex_to_bytes(lh,leaf,len));CHECK(nutroot_leaf_parse(ctx,leaf,len,&parsed)&&parsed.disclosure==1);
    leaf[len-1]=0;CHECK(!nutroot_leaf_parse(ctx,leaf,len,&parsed));leaf[len-1]=2;CHECK(!nutroot_leaf_parse(ctx,leaf,len,&parsed));
    CHECK(!nutroot_leaf_parse(ctx,leaf,sizeof(leaf),&parsed));
    unsigned char hashes[9*32]={0},root[32];CHECK(!nutroot_merkle_root(hashes,9,root));CHECK(!nutroot_root_from_path(hashes,hashes,4,root));
    /* Raw x-coordinate ECDH and NUT-28 slot derivation. */
    unsigned char e[32],p[32],E[33],P[33],zx[32],other[32],r[32];
    CHECK(hex_to_bytes("1cedb9df0c6872188b560ace9e35fd55c2532d53e19ae65b46159073886482ca",e,32));
    CHECK(hex_to_bytes("ad37e8abd800be3e8272b14045873f4353327eedeb702b72ddcc5c5adff5129c",p,32));
    CHECK(public_key(ctx,e,E)&&public_key(ctx,p,P));CHECK(nutroot_ecdh_x(ctx,e,P,zx)&&nutroot_ecdh_x(ctx,p,E,other));CHECK(!memcmp(zx,other,32));
    CHECK(equal_hex(zx,32,"40d6ba4430a6dfa915bb441579b0f4dee032307434e9957a092bbca73151df8b"));
    CHECK(nutroot_p2bk_scalar(ctx,zx,0,r));CHECK(equal_hex(r,32,"f43cfecf4d44e109872ed601156a01211c0d9eba0460d5be254a510782a2d4aa"));
    CHECK(nutroot_p2bk_scalar(ctx,zx,10,r));CHECK(equal_hex(r,32,"9de35112d62e6343d02301d8f58fef87958e99bb68cfdfa855e04fe18b95b114"));
    CHECK(!nutroot_p2bk_scalar(ctx,zx,256,r));memset(e,0,32);CHECK(!nutroot_ecdh_x(ctx,e,P,zx));
    /* Current NUT-13: explicit length framing, full u64 counters, all
     * per-proof branches, and reference rejection-loop outputs. */
    nutroot_kdf_t kdf;
    CHECK(nutroot_kdf_init(&kdf,(const unsigned char *)"nut13 v3 test seed",sizeof("nut13 v3 test seed")-1,id,33));
    static const char *keys[]={"47196dc081150ce13fd0e478b8b71831b825be389211c9c56a8062a61af70347","659a545656334a47e08de62377e2f3128c72cd27e576908842e1ab359d395247","cee0df42cdaee25b228300b460edcbfab94be650ce2676abd77ef0697311e5e2","46c2c20d79496e1ebe19805ba4df33535474800eefefc252140e1f20d0284ffe"};
    static const char *factors[]={"156857a0bce1b2788895f1885a21c56cf000df0de1e855608c7ccb6d9e2d7728","6de008e7a6c418b76a94e48c4b71a11078173de70abb3eaeb7cc1273a6dccede","35f56bb2016802a96a2846de8635712281d68182788410735b9826a211499fd4","65724fcdbc4ccfbb2a610b1bddd14238492b81d3761584b6492fcbadfeb9355f"};
    for(unsigned i=0;i<4;i++) {
        CHECK(nutroot_kdf_derive(&kdf,i,0,0,p)&&equal_hex(p,32,keys[i]));
        CHECK(nutroot_kdf_derive(&kdf,i,1,0,r)&&equal_hex(r,32,factors[i]));
    }
    CHECK(nutroot_kdf_derive(&kdf,0,2,0,p)&&equal_hex(p,32,"4af68649f3230c5589879f0cf33fd6d9f007cd3a54a2e6ed8699a576630fc025"));
    CHECK(nutroot_kdf_derive(&kdf,0,3,2,p)&&equal_hex(p,32,"ba7a8fc52b8c77b7412e5edaae211d92f2c79980788e3e3a480eb0dccac0b33e"));
    CHECK(nutroot_kdf_derive(&kdf,UINT64_MAX,0,0,p)&&nutroot_kdf_derive(&kdf,UINT32_MAX,0,0,r)&&memcmp(p,r,32));
    CHECK(!nutroot_kdf_derive(&kdf,0,4,0,p));
    nutroot_kdf_clear(&kdf);CHECK(!nutroot_kdf_derive(&kdf,0,0,0,p));
    memset(p,0,32);p[31]=7;CHECK(nutroot_nums_key(ctx,p,P));
    CHECK(equal_hex(P,33,"028edfebd6fdea3e1d89359af20868a2e76315b36cdb1a79de497a1757ca7bd407"));
    CHECK(nutroot_nums_verify(ctx,p,P));p[31]=8;CHECK(!nutroot_nums_verify(ctx,p,P));p[31]=0;CHECK(!nutroot_nums_key(ctx,p,P));
    CHECK(secp256k1_nucula_sqrt_compare(64));
    REPORT("current proposal: transcript, per-input witnesses, routing, disclosure, caps and ECDH vectors OK");
    return 1;
}
#ifdef NUCULA_HOST_TEST_MAIN
int main(void) {
    secp256k1_context *ctx=secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    for(unsigned opt=0;opt<64;opt=opt==0?15:opt==15?31:opt==31?63:64) {
        nutroot_set_optimizations(opt);if(!nutroot_current_run_tests(ctx))return 1;
    }
    secp256k1_context_destroy(ctx);return 0;
}
#endif

#ifdef ESP_PLATFORM
#include "cashu_suite.h"
#include "crypto_bls.h"
#include "crypto_bls_test.h"
#include <blst.h>
#include <blst_aux.h>
#include <blst_mpi.h>
#include <mbedtls/sha256.h>
#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <stdlib.h>
#define CURRENT_N 10
static const unsigned char BLS_DST[]="CASHU_BLS12_381_G1_XMD:SHA-256_SSWU_RO_";
typedef struct {
    unsigned char e[32], E[33], K[33], root[32], point[33], spend_sk[32];
    unsigned char leaf[64]; size_t leaf_len;
    secp256k1_keypair spend_keypair;
    char witness[160];
} current_input;
typedef struct {
    current_input in[CURRENT_N];
    unsigned char Ks[CURRENT_N*96], C[CURRENT_N*48], B[CURRENT_N*48];
    unsigned char Cblind[CURRENT_N*48], unblinded[CURRENT_N*48], rs[CURRENT_N*32];
    unsigned char out_secrets[CURRENT_N][33], receiver_sk[32], receiver_pk[33];
    const unsigned char *secrets[CURRENT_N], *outputs[CURRENT_N];size_t lengths[CURRENT_N];
    nutroot_input_t inputs[CURRENT_N];nutroot_output_t outs[CURRENT_N];nutroot_tx_t tx;
} current_work;
static void fixture_scalar(const char *label,unsigned index,unsigned attempt,unsigned char sk[32]) {
    char message[80];int n=snprintf(message,sizeof(message),"nucula/current/%s/%u/%u",label,index,attempt);
    mbedtls_sha256((unsigned char *)message,(size_t)n,sk,0);
}
static int recover_current(const secp256k1_context *ctx,current_work *w,int retain) {
    for(size_t i=0;i<CURRENT_N;i++) {
        current_input *in=&w->in[i];unsigned char shared[32],r[32],K[33],root[32],t[32],P[33];
        nutroot_leaf_t leaf;
        memcpy(in->spend_sk,w->receiver_sk,32);
        if(!nutroot_ecdh_x(ctx,w->receiver_sk,in->E,shared)||!nutroot_p2bk_scalar(ctx,shared,0,r)||
           !secp256k1_ec_seckey_tweak_add(ctx,in->spend_sk,r)||!public_key(ctx,in->spend_sk,K)||memcmp(K,in->K,33)||
           !nutroot_leaf_parse(ctx,in->leaf,in->leaf_len,&leaf)||!nutroot_leaf_hash(in->leaf,in->leaf_len,root))return 0;
        if(retain) {
            secp256k1_pubkey point;size_t length=33;
            if(!nutroot_tweak_scalar(K,root,t)||!secp256k1_ec_seckey_tweak_add(ctx,in->spend_sk,t)||
               !secp256k1_keypair_create(ctx,&in->spend_keypair,in->spend_sk)||
               !secp256k1_keypair_pub(ctx,&point,&in->spend_keypair)||
               !secp256k1_ec_pubkey_serialize(ctx,P,&length,&point,SECP256K1_EC_COMPRESSED)||memcmp(P,in->point,33))return 0;
        } else if(!nutroot_tweak_pubkey(ctx,K,root,P)||memcmp(P,in->point,33)||!nutroot_tweak_seckey(ctx,in->spend_sk,root))return 0;
    }
    return 1;
}
static int sign_current(const secp256k1_context *ctx,current_work *w,int retain) {
    unsigned char transaction[32],digest[32],sig[64],aux[32]={0};char hex[129];
    if(!nutroot_tx_digest(&w->tx,transaction))return 0;
    for(size_t i=0;i<CURRENT_N;i++) {
        if(!nutroot_input_digest(transaction,&w->inputs[i],digest))return 0;
        int ok=retain?secp256k1_schnorrsig_sign32(ctx,sig,digest,&w->in[i].spend_keypair,aux):nutroot_sign_digest(ctx,w->in[i].spend_sk,digest,sig);
        if(!ok)return 0;
        bytes_to_hex(sig,64,hex);snprintf(w->in[i].witness,sizeof(w->in[i].witness),"{\"signatures\":[\"%s\"]}",hex);
        w->inputs[i].witness=w->in[i].witness;
    }
    return 1;
}
#define TIMED(label,reps,...) do { \
    int64_t total=0,minimum=INT64_MAX,maximum=0; \
    for(int repeat=0;repeat<(reps);repeat++) { \
        int64_t start=esp_timer_get_time(); __VA_ARGS__; int64_t elapsed=esp_timer_get_time()-start; \
        total+=elapsed;if(elapsed<minimum)minimum=elapsed;if(elapsed>maximum)maximum=elapsed;vTaskDelay(2); \
    } \
    REPORT("%-29s x%d mean %lld min %lld max %lld us",label,reps,total/(reps),minimum,maximum); \
} while(0)
void nutroot_current_benchmark(const secp256k1_context *ctx) {
    current_work *w=calloc(1,sizeof(*w));if(!w){REPORT("FAILED: fixture allocation");return;}
    int ok=1;unsigned char keyset_id[33]={2};
    fixture_scalar("receiver",0,0,w->receiver_sk);ok&=public_key(ctx,w->receiver_sk,w->receiver_pk);
    for(size_t i=0;i<CURRENT_N&&ok;i++) {
        current_input *in=&w->in[i];unsigned char shared[32],r[32],out_sk[32];
        fixture_scalar("ephemeral",i,0,in->e);ok&=public_key(ctx,in->e,in->E);
        ok&=nutroot_ecdh_x(ctx,in->e,w->receiver_pk,shared)&&nutroot_p2bk_scalar(ctx,shared,0,r);
        memcpy(in->spend_sk,w->receiver_sk,32);ok&=secp256k1_ec_seckey_tweak_add(ctx,in->spend_sk,r)&&public_key(ctx,in->spend_sk,in->K);
        in->leaf_len=sizeof(in->leaf);ok&=nutroot_leaf_build(NUTROOT_LEAF_THRESHOLD,1,w->receiver_pk,1,0,NULL,in->leaf,&in->leaf_len)&&
              nutroot_leaf_hash(in->leaf,in->leaf_len,in->root)&&nutroot_tweak_pubkey(ctx,in->K,in->root,in->point);
        fixture_scalar("output",i,0,out_sk);ok&=public_key(ctx,out_sk,w->out_secrets[i]);
        w->secrets[i]=in->point;w->outputs[i]=w->out_secrets[i];w->lengths[i]=33;
        blst_scalar scalar;unsigned attempt=0;
        do {fixture_scalar("blinding",i,attempt++,w->rs+32*i);blst_scalar_from_bendian(&scalar,w->rs+32*i);}while(!blst_sk_check(&scalar));
        hex_to_bytes(crypto_bls_bench_key_hex(i),w->Ks+96*i,96);
        w->inputs[i]=(nutroot_input_t){.amount=1ULL<<i,.keyset_id=keyset_id,.keyset_id_len=33,.secret=in->point,.secret_len=33,.C=w->C+48*i,.C_len=48};
        w->outs[i]=(nutroot_output_t){.amount=1ULL<<i,.keyset_id=keyset_id,.keyset_id_len=33,.B_=w->B+48*i,.B_len=48};
        size_t length=48;ok&=cashu_suite_bls.blind(NULL,w->outputs[i],33,w->rs+32*i,32,w->B+48*i,&length);
        blst_hw_acquire();
        blst_p1 point,signed_point;blst_p1_affine affine;unsigned char a[32]={0};a[0]=2+i;
        blst_hash_to_g1(&point,in->point,33,BLS_DST,sizeof(BLS_DST)-1,NULL,0);blst_p1_mult(&signed_point,&point,a,256);blst_p1_compress(w->C+48*i,&signed_point);
        ok&=blst_p1_uncompress(&affine,w->B+48*i)==BLST_SUCCESS;blst_p1_from_affine(&point,&affine);blst_p1_mult(&signed_point,&point,a,256);blst_p1_compress(w->Cblind+48*i,&signed_point);
        blst_hw_release();vTaskDelay(2);
    }
    w->tx=(nutroot_tx_t){.proof_inputs=w->inputs,.n_proof_inputs=CURRENT_N,.blinded_outputs=w->outs,.n_blinded_outputs=CURRENT_N};
    if(!ok){REPORT("FAILED: current fixture setup");goto done;}
    REPORT("NUT-10 a3f04b97154b; 10 distinct keys, 33B point secrets, full-width factors, fresh E per receiver-keyed output; BLS=%u Nutroot=%u",cashu_bls_options(),nutroot_optimizations());
    cashu_bls_clear_key_cache();
    TIMED("BLS verify cold n=10",1,ok&=cashu_suite_bls.verify_proofs(NULL,CURRENT_N,w->Ks,w->C,w->secrets,w->lengths));
    TIMED("BLS verify warm n=10",4,ok&=cashu_suite_bls.verify_proofs(NULL,CURRENT_N,w->Ks,w->C,w->secrets,w->lengths));
    TIMED("BLS known keys fresh Y n=10",3,cashu_bls_clear_hash_cache();ok&=cashu_suite_bls.verify_proofs(NULL,CURRENT_N,w->Ks,w->C,w->secrets,w->lengths));
    TIMED("recover+sign separate n=10",3,ok&=recover_current(ctx,w,0)&&sign_current(ctx,w,0));
    ok&=nutroot_verify_transaction(ctx,&w->tx,2000000000);
    TIMED("recover+sign retained n=10",3,ok&=recover_current(ctx,w,1)&&sign_current(ctx,w,1));
    TIMED("current witnesses n=10",3,ok&=nutroot_verify_transaction(ctx,&w->tx,2000000000));
    {
        struct {unsigned char P[33*CURRENT_N],K[33*CURRENT_N],t[32*CURRENT_N];const unsigned char *roots[CURRENT_N];} *commitments=malloc(sizeof(*commitments));
        size_t bytes=secp256k1_nucula_tweak_scratch_size(CURRENT_N);void *arena=malloc(bytes);
        if(commitments&&arena) {
            for(size_t i=0;i<CURRENT_N;i++) {
                memcpy(commitments->P+33*i,w->in[i].point,33);memcpy(commitments->K+33*i,w->in[i].K,33);
                commitments->roots[i]=w->in[i].root;
                ok&=nutroot_tweak_scalar(w->in[i].K,w->in[i].root,commitments->t+32*i);
            }
            unsigned char calculated[33];
            TIMED("commitments individual n=10",3,for(size_t i=0;i<CURRENT_N;i++)ok&=nutroot_tweak_pubkey(ctx,w->in[i].K,w->in[i].root,calculated)&&!memcmp(calculated,w->in[i].point,33));
            TIMED("commitments batch n=10",3,ok&=secp256k1_nucula_verify_tweaks(ctx,CURRENT_N,commitments->P,commitments->K,commitments->t,arena,bytes));
            free(arena);arena=NULL;
            TIMED("commitments API n=10",3,ok&=nutroot_verify_commitments(ctx,CURRENT_N,commitments->P,commitments->K,commitments->roots));
            arena=malloc(bytes);
            commitments->t[31]^=1;ok&=arena&&!secp256k1_nucula_verify_tweaks(ctx,CURRENT_N,commitments->P,commitments->K,commitments->t,arena,bytes);
        } else REPORT("commitment batch unavailable: scratch allocation (no timing reported)");
        free(arena);free(commitments);
    }
    TIMED("blind fresh secrets n=10",1,for(size_t i=0;i<CURRENT_N;i++){size_t length=48;ok&=cashu_suite_bls.blind(NULL,w->outputs[i],33,w->rs+32*i,32,w->B+48*i,&length);});
    TIMED("blind cached secrets n=10",3,for(size_t i=0;i<CURRENT_N;i++){size_t length=48;ok&=cashu_suite_bls.blind(NULL,w->outputs[i],33,w->rs+32*i,32,w->B+48*i,&length);});
    TIMED("unblind+verify separate n=10",3,
        for(size_t i=0;i<CURRENT_N;i++){size_t length=48;ok&=cashu_suite_bls.unblind(NULL,w->Cblind+48*i,48,w->rs+32*i,32,w->Ks+96*i,96,w->unblinded+48*i,&length);}
        ok&=cashu_suite_bls.verify_proofs(NULL,CURRENT_N,w->Ks,w->unblinded,w->outputs,w->lengths));
    TIMED("unblind+verify retained n=10",3,ok&=cashu_bls_unblind_verify(CURRENT_N,w->Ks,w->Cblind,w->rs,w->outputs,w->lengths,w->unblinded));
    unsigned saved_bls=cashu_bls_options();
    ok&=cashu_bls_configure(saved_bls|CASHU_BLS_BATCH_INVERSE,cashu_bls_capacity());
    TIMED("unblind+verify batch inverse",3,ok&=cashu_bls_unblind_verify(CURRENT_N,w->Ks,w->Cblind,w->rs,w->outputs,w->lengths,w->unblinded));
    ok&=cashu_bls_configure(saved_bls,cashu_bls_capacity());
    {
        nutroot_kdf_t kdf;nutroot_prepared_output_t entry,entries[10];
        static const unsigned char seed[]="synthetic preparation seed";
        ok&=nutroot_kdf_init(&kdf,seed,sizeof(seed)-1,keyset_id,33);
        unsigned char scalar[32],K[33];
        TIMED("KDF cached prefix n=10",3,for(unsigned i=0;i<10;i++)ok&=nutroot_kdf_derive(&kdf,100+i,1,0,scalar));
        TIMED("KDF new context n=10",3,for(unsigned i=0;i<10;i++) {
            nutroot_kdf_t fresh;ok&=nutroot_kdf_init(&fresh,seed,sizeof(seed)-1,keyset_id,33)&&nutroot_kdf_derive(&fresh,100+i,1,0,scalar);nutroot_kdf_clear(&fresh);
        });
        TIMED("prepare fresh outputs n=10",3,for(unsigned i=0;i<10;i++)ok&=nutroot_prepare_bare(ctx,&kdf,100+10*(unsigned)repeat+i,&entries[i]));
        TIMED("read prepared outputs n=10",3,for(unsigned i=0;i<10;i++){memcpy(&entry,&entries[i],sizeof(entry));ok&=entry.ready;});
        ok&=nutroot_kdf_derive(&kdf,100,2,0,scalar);
        TIMED("NUMS offset verify",5,ok&=nutroot_nums_key(ctx,scalar,K));
        for(unsigned i=0;i<10;i++)nutroot_prepared_clear(&entries[i]);
        nutroot_prepared_clear(&entry);nutroot_kdf_clear(&kdf);
    }
    /* Tight current cap: 8 leaves * at most 15 keys = 120 leaf slots.
     * Value matching tries candidates only up to the enumerated key count. */
    unsigned char shared[32],r[32],sk[32],target[33],candidate[33];
    ok&=nutroot_ecdh_x(ctx,w->receiver_sk,w->in[0].E,shared)&&nutroot_p2bk_scalar(ctx,shared,120,r);
    memcpy(sk,w->receiver_sk,32);ok&=secp256k1_ec_seckey_tweak_add(ctx,sk,r)&&public_key(ctx,sk,target);
    TIMED("leaf slot match at 120",2,
        int found=0;for(unsigned slot=1;slot<=120&&!found;slot++) {
            ok&=nutroot_p2bk_scalar(ctx,shared,slot,r);memcpy(sk,w->receiver_sk,32);
            ok&=secp256k1_ec_seckey_tweak_add(ctx,sk,r)&&public_key(ctx,sk,candidate);
            found=!memcmp(candidate,target,33);if((slot&7)==0)vTaskDelay(2);
        }ok&=found);
    /* Quantify the possible payoff of a different SHA backend before taking
     * additional peripheral locks in BLS's MPI critical section. */
    unsigned char sw[32],hw[32];unsigned char message[1024];memset(message,0xa5,sizeof(message));
    TIMED("blst SHA256 33B x100",3,for(unsigned i=0;i<100;i++)blst_sha256(sw,message,33));
    TIMED("IDF SHA256 33B x100",3,for(unsigned i=0;i<100;i++)ok&=mbedtls_sha256(message,33,hw,0)==0);
    ok&=!memcmp(sw,hw,32);
    TIMED("blst SHA256 1KiB x100",3,for(unsigned i=0;i<100;i++)blst_sha256(sw,message,sizeof(message)));
    TIMED("IDF SHA256 1KiB x100",3,for(unsigned i=0;i<100;i++)ok&=mbedtls_sha256(message,sizeof(message),hw,0)==0);
    ok&=!memcmp(sw,hw,32);
    {
        struct {blst_fp12 miller,gt,value;blst_fp2 a,b,result;} *profile=calloc(1,sizeof(*profile));
        if(profile) {
            uint32_t words[12]={17};blst_hw_acquire();
            blst_fp_from_uint32(&profile->a.fp[0],words);words[0]=31;blst_fp_from_uint32(&profile->a.fp[1],words);
            profile->b=profile->a;
            blst_miller_loop(&profile->miller,blst_p2_affine_generator(),blst_p1_affine_generator());
            blst_final_exp(&profile->gt,&profile->miller);
            TIMED("BLS Fp2 multiply x100",3,for(unsigned j=0;j<100;j++)blst_fp2_mul(&profile->result,&profile->a,&profile->b));
            TIMED("BLS Fp2 square x100",3,for(unsigned j=0;j<100;j++)blst_fp2_sqr(&profile->result,&profile->a));
            TIMED("BLS Fp2 inverse x100",3,for(unsigned j=0;j<100;j++)blst_fp2_inverse(&profile->result,&profile->a));
            TIMED("BLS cyclotomic square x100",3,for(unsigned j=0;j<100;j++)blst_fp12_cyclotomic_sqr(&profile->value,&profile->gt));
            TIMED("BLS final exponent",5,blst_final_exp(&profile->value,&profile->miller));
            ok&=blst_fp12_is_equal(&profile->value,&profile->gt);
            blst_hw_release();free(profile);
        } else REPORT("BLS arithmetic profile unavailable: allocation");
    }
    ok&=secp256k1_nucula_hwfield_compare(2000);
    TIMED("secp field mul x1000",3,secp256k1_nucula_field_chain(sw,1000,0));
    TIMED("secp field square x1000",3,secp256k1_nucula_field_chain(sw,1000,1));
    TIMED("MPI secp field mul x1000",3,ok&=secp256k1_nucula_hwfield_chain(hw,1000,0));
    secp256k1_nucula_field_chain(sw,1000,0);ok&=!memcmp(hw,sw,32);
    TIMED("MPI secp field square x1000",3,ok&=secp256k1_nucula_hwfield_chain(hw,1000,1));
    secp256k1_nucula_field_chain(sw,1000,1);ok&=!memcmp(hw,sw,32);
    TIMED("secp scalar mul x1000",3,secp256k1_nucula_field_chain(sw,1000,2));
    uint32_t a[48],b[48],product[96],reference[96];
    for (unsigned i=0;i<48;i++) { a[i]=0xfedcba98u-321u*i; b[i]=0x89abcdefu-751u*i; }
    static const unsigned widths[]={8,12,24,36,48};
    for(unsigned i=0;i<5;i++) {
        unsigned words=widths[i];memset(reference,0,sizeof(reference));
        for(unsigned j=0;j<words;j++) {
            uint64_t carry=0;
            for(unsigned k=0;k<words;k++) { uint64_t v=(uint64_t)a[j]*b[k]+reference[j+k]+carry;reference[j+k]=(uint32_t)v;carry=v>>32; }
            reference[j+words]=(uint32_t)carry;
        }
        blst_hw_acquire();ok&=blst_mpi_raw_multiply(product,a,b,words);blst_hw_release();
        ok&=!memcmp(product,reference,2*words*sizeof(uint32_t));
        char label[48];snprintf(label,sizeof(label),"MPI raw %u-bit x1000",32*words);
        TIMED(label,3,blst_hw_acquire();for(unsigned j=0;j<1000;j++)ok&=blst_mpi_raw_multiply(product,a,b,words);blst_hw_release());
    }
    REPORT("current benchmark correctness: %s",ok?"OK":"FAILED");
done:
    /* Fixtures are public deterministic data, but follow the ownership rule
     * used for real ephemeral keys and retained signing keypairs. */
    volatile unsigned char *wipe=(volatile unsigned char *)w;
    for(size_t i=0;i<sizeof(*w);i++)wipe[i]=0;
    free(w);
}
#endif
