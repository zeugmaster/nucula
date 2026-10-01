/* Nutroot secrets (v3 keysets) core: tagged hashes, leaf TLV, merkle fold,
 * tweak math, transaction transcript, and witness verification per NUT-10
 * (cashubtc/nuts#421), byte-mirroring nutshell's
 * bench/nutroot-witness-verification branch. See nutroot.h.
 *
 * ESP-free on purpose: secp256k1 + mbedtls + cJSON + libc only, so the host
 * harness compiles this file verbatim. No logging — integer returns only. */

#include "nutroot.h"
#include "hex.h"

#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_nucula.h>
#include <mbedtls/sha256.h>
#include <cJSON.h>
#include <stdlib.h>
#include <string.h>

static const char LEAF_TAG[]   = "Cashu_NutrootLeaf";
static const char BRANCH_TAG[] = "Cashu_NutrootBranch";
static const char TWEAK_TAG[]  = "Cashu_NutrootTweak";
static unsigned optimization_flags = 95;
static const char TX_TAG[]     = "Cashu_Transaction_v1";

/* Leaf body field types. Allocated types are even; odd types are reserved.
 * Unknown fails closed either way. */
#define FIELD_N    0x02
#define FIELD_KEYS 0x04
#define FIELD_TIME 0x06
#define FIELD_HASH 0x08
#define FIELD_DISCLOSURE 0x0a

/* Transcript container types. */
#define CONTAINER_PROOF_INPUT      0x01
#define CONTAINER_MINT_QUOTE_IN    0x02
#define CONTAINER_BLINDED_OUTPUT   0x03
#define CONTAINER_MELT_QUOTE_OUT   0x04

/* secp256k1 group order, big-endian. */
static const unsigned char ORDER_BE[32] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
};

static void (*yield_hook)(void) = NULL;
unsigned long nutroot_stat_sig_verifies = 0;
unsigned long nutroot_stat_batch_verifies = 0;

void nutroot_set_yield_hook(void (*hook)(void))
{
    yield_hook = hook;
}

static void maybe_yield(void)
{
    if (yield_hook)
        yield_hook();
}

/* --------------------------------------------------------------- hashing */

static const struct { const char *tag; unsigned char hash[32]; } tag_hashes[] = {
    {"Cashu_NutrootLeaf", {0xe1,0x9b,0xa8,0x0c,0x5d,0x67,0x98,0x39,0x9e,0xfd,0x68,0xb1,0xd3,0xb0,0xe7,0xad,0x57,0xe7,0x9a,0x27,0x77,0x31,0x0a,0x9e,0x63,0x34,0x93,0x4e,0xe7,0xa0,0xb5,0x2b}},
    {"Cashu_NutrootBranch", {0xf5,0x41,0x94,0xfd,0x19,0xda,0xbb,0xcc,0xa1,0x47,0x4f,0x32,0x9f,0xe5,0xec,0x06,0x5f,0xc5,0x4d,0x94,0x06,0x3d,0x14,0xae,0x82,0x07,0x88,0xba,0x5b,0xd8,0xe5,0x5e}},
    {"Cashu_NutrootTweak", {0xcc,0x14,0xd6,0x87,0x2e,0x6d,0x0b,0xc7,0x9a,0x3d,0xad,0xb4,0xc4,0x3f,0x93,0x62,0x91,0x6b,0xb6,0xdf,0x51,0x21,0x26,0xdd,0xa1,0x39,0xe6,0x5b,0x81,0x2f,0xac,0xd1}},
    {"Cashu_TransactionInput", {0x49,0x96,0xfe,0xe5,0x85,0xf6,0x25,0xe6,0xa3,0x38,0x65,0xce,0x97,0x5e,0xfc,0x32,0xc4,0x2d,0x2b,0x1b,0x95,0x32,0x83,0x85,0xce,0x45,0xf5,0x20,0x9a,0x16,0xe9,0xec}},
};

/* tagged_hash over up to two message parts (m2 may be NULL). */
static int tagged_hash2(const char *tag,
                        const unsigned char *m1, size_t l1,
                        const unsigned char *m2, size_t l2,
                        unsigned char out[32])
{
    unsigned char tag_hash[32];
    int found = 0;
    if (optimization_flags & 8)
        for (size_t i = 0; i < sizeof(tag_hashes)/sizeof(tag_hashes[0]); i++)
            if (!strcmp(tag, tag_hashes[i].tag)) { memcpy(tag_hash, tag_hashes[i].hash, 32); found = 1; break; }
    if (!found && mbedtls_sha256((const unsigned char *)tag, strlen(tag), tag_hash, 0) != 0) return 0;
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    int ok = mbedtls_sha256_starts(&sha, 0) == 0 &&
             mbedtls_sha256_update(&sha, tag_hash, 32) == 0 &&
             mbedtls_sha256_update(&sha, tag_hash, 32) == 0 &&
             mbedtls_sha256_update(&sha, m1, l1) == 0 &&
             (m2 == NULL || mbedtls_sha256_update(&sha, m2, l2) == 0) &&
             mbedtls_sha256_finish(&sha, out) == 0;
    mbedtls_sha256_free(&sha);
    return ok;
}

int nutroot_tagged_hash(const char *tag,
                        const unsigned char *msg, size_t len,
                        unsigned char out[32])
{
    return tagged_hash2(tag, msg, len, NULL, 0, out);
}

int nutroot_leaf_hash(const unsigned char *leaf, size_t len,
                      unsigned char out[32])
{
    return tagged_hash2(LEAF_TAG, leaf, len, NULL, 0, out);
}

/* Branch of two child hashes: sorted pair, no left/right flags. */
static int branch_hash(const unsigned char a[32], const unsigned char b[32],
                       unsigned char out[32])
{
    if (memcmp(a, b, 32) <= 0)
        return tagged_hash2(BRANCH_TAG, a, 32, b, 32, out);
    return tagged_hash2(BRANCH_TAG, b, 32, a, 32, out);
}

/* ---------------------------------------------------------------- leaves */

/* One TLV record header into out (3 bytes). */
static void tlv_header(unsigned char hdr[3], uint8_t type, size_t len)
{
    hdr[0] = type;
    hdr[1] = (unsigned char)(len >> 8);
    hdr[2] = (unsigned char)(len & 0xff);
}

/* Minimal big-endian encoding; zero encodes to zero bytes. Returns length. */
static size_t minimal_be(uint64_t value, unsigned char out[8])
{
    size_t len = 0;
    unsigned char tmp[8];
    while (value > 0) {
        tmp[len++] = (unsigned char)(value & 0xff);
        value >>= 8;
    }
    for (size_t i = 0; i < len; i++)
        out[i] = tmp[len - 1 - i];
    return len;
}

/* Decode a minimal big-endian integer; rejects leading zeros and > 8 bytes. */
static int read_minimal_be(const unsigned char *data, size_t len, uint64_t *out)
{
    if (len > 0 && data[0] == 0)
        return 0;
    if (len > 8)
        return 0;
    uint64_t v = 0;
    for (size_t i = 0; i < len; i++)
        v = (v << 8) | data[i];
    *out = v;
    return 1;
}

/* No two keys may share an x coordinate: signatures verify against the
 * x-only key, so parity twins are one signer wearing two hats. */
static int keys_distinct_x(const unsigned char *keys, uint8_t num_keys)
{
    for (uint8_t i = 0; i < num_keys; i++)
        for (uint8_t j = (uint8_t)(i + 1); j < num_keys; j++)
            if (memcmp(keys + i * 33 + 1, keys + j * 33 + 1, 32) == 0)
                return 0;
    return 1;
}

int nutroot_leaf_build(uint8_t type, uint8_t n,
                       const unsigned char *keys, uint8_t num_keys,
                       int64_t time, const unsigned char *hash32,
                       unsigned char *out, size_t *out_len)
{
    if (type < NUTROOT_LEAF_THRESHOLD || type > NUTROOT_LEAF_HASHLOCK)
        return 0;
    if (n < 1 || num_keys < 1 || n > num_keys || !keys)
        return 0;
    if (!keys_distinct_x(keys, num_keys))
        return 0;
    if (type == NUTROOT_LEAF_AFTER &&
        (time < 0 || time > NUTROOT_MAX_LEAF_TIME))
        return 0;
    if (type == NUTROOT_LEAF_HASHLOCK && !hash32)
        return 0;

    unsigned char amt[8];
    size_t time_len = (type == NUTROOT_LEAF_AFTER)
                          ? minimal_be((uint64_t)time, amt) : 0;
    size_t need = 2 + 3 + 1 + 3 + (size_t)num_keys * 33;
    if (type == NUTROOT_LEAF_AFTER)
        need += 3 + time_len;
    if (type == NUTROOT_LEAF_HASHLOCK)
        need += 3 + 32;
    if (need - 1 > NUTROOT_MAX_LEAF_BODY || need > *out_len)
        return 0;

    unsigned char *p = out;
    *p++ = NUTROOT_LEAF_VERSION;
    *p++ = type;
    tlv_header(p, FIELD_N, 1); p += 3;
    *p++ = n;
    tlv_header(p, FIELD_KEYS, (size_t)num_keys * 33); p += 3;
    memcpy(p, keys, (size_t)num_keys * 33); p += (size_t)num_keys * 33;
    if (type == NUTROOT_LEAF_AFTER) {
        tlv_header(p, FIELD_TIME, time_len); p += 3;
        memcpy(p, amt, time_len); p += time_len;
    }
    if (type == NUTROOT_LEAF_HASHLOCK) {
        tlv_header(p, FIELD_HASH, 32); p += 3;
        memcpy(p, hash32, 32); p += 32;
    }
    *out_len = (size_t)(p - out);
    return 1;
}

static int leaf_parse(const secp256k1_context *ctx,
                       const unsigned char *leaf, size_t len,
                       nutroot_leaf_t *out, secp256k1_xonly_pubkey *parsed_keys)
{
    if (!leaf || len < 2 || len - 1 > NUTROOT_MAX_LEAF_BODY)
        return 0;
    if (leaf[0] != NUTROOT_LEAF_VERSION)
        return 0;
    uint8_t type = leaf[1];
    if (type < NUTROOT_LEAF_THRESHOLD || type > NUTROOT_LEAF_HASHLOCK)
        return 0;

    memset(out, 0, sizeof(*out));
    out->type = type;
    int have_n = 0, have_keys = 0, have_time = 0, have_hash = 0;

    /* Field TLV stream: strictly ascending types, which also forces
     * uniqueness. Unknown fields (either parity) fail closed. */
    size_t off = 2;
    int prev_type = -1;
    while (off < len) {
        if (len - off < 3)
            return 0;
        int rtype = leaf[off];
        size_t rlen = ((size_t)leaf[off + 1] << 8) | leaf[off + 2];
        off += 3;
        if (len - off < rlen)
            return 0;
        if (rtype <= prev_type)
            return 0;
        prev_type = rtype;
        const unsigned char *val = leaf + off;
        off += rlen;

        switch (rtype) {
        case FIELD_N:
            if (rlen != 1 || val[0] == 0)
                return 0;
            out->n = val[0];
            have_n = 1;
            break;
        case FIELD_KEYS: {
            if (rlen == 0 || rlen % 33 != 0 || rlen / 33 > 0xff)
                return 0;
            uint8_t nk = (uint8_t)(rlen / 33);
            for (uint8_t i = 0; i < nk; i++) {
                secp256k1_pubkey pk;
                if (!secp256k1_ec_pubkey_parse(ctx, &pk, val + i * 33, 33)) return 0;
                if (parsed_keys && !secp256k1_xonly_pubkey_from_pubkey(ctx, &parsed_keys[i], NULL, &pk)) return 0;
            }
            if (!keys_distinct_x(val, nk))
                return 0;
            out->keys = val;
            out->num_keys = nk;
            have_keys = 1;
            break;
        }
        case FIELD_TIME: {
            uint64_t t;
            if (!read_minimal_be(val, rlen, &t) || t > (uint64_t)NUTROOT_MAX_LEAF_TIME)
                return 0;
            out->time = (int64_t)t;
            have_time = 1;
            break;
        }
        case FIELD_DISCLOSURE:
            if (rlen != 1 || val[0] != 1) return 0;
            out->disclosure = 1;
            break;
        case FIELD_HASH:
            if (rlen != 32)
                return 0;
            out->hash = val;
            have_hash = 1;
            break;
        default:
            return 0;
        }
    }

    if (!have_n || !have_keys || out->n > out->num_keys)
        return 0;
    /* Each type carries exactly the fields its evaluation rule reads. */
    if ((type == NUTROOT_LEAF_AFTER) != have_time)
        return 0;
    if ((type == NUTROOT_LEAF_HASHLOCK) != have_hash)
        return 0;
    return 1;
}

int nutroot_leaf_parse(const secp256k1_context *ctx, const unsigned char *leaf,
                       size_t len, nutroot_leaf_t *out)
{ return leaf_parse(ctx, leaf, len, out, NULL); }

/* ---------------------------------------------------------------- merkle */

static int cmp_hash32(const void *a, const void *b)
{
    return memcmp(a, b, 32);
}

/* One fold level in place: pairs into slots 0..p-1, odd last promoted.
 * Returns the new level length. */
static size_t fold_level(unsigned char *hashes, size_t n, int *ok)
{
    size_t p = n / 2;
    for (size_t i = 0; i < p; i++) {
        unsigned char tmp[32];
        if (!branch_hash(hashes + 2 * i * 32, hashes + (2 * i + 1) * 32, tmp))
            *ok = 0;
        memcpy(hashes + i * 32, tmp, 32);
    }
    if (n % 2 == 1) {
        memmove(hashes + p * 32, hashes + (n - 1) * 32, 32);
        return p + 1;
    }
    return p;
}

int nutroot_merkle_root(unsigned char *hashes, size_t n, unsigned char root[32])
{
    if (!hashes || n == 0 || n > ((size_t)1 << NUTROOT_MAX_TREE_DEPTH))
        return 0;
    qsort(hashes, n, 32, cmp_hash32);
    int ok = 1;
    while (n > 1)
        n = fold_level(hashes, n, &ok);
    memcpy(root, hashes, 32);
    return ok;
}

int nutroot_merkle_path(unsigned char *hashes, size_t n, size_t index,
                        unsigned char *path, size_t *path_len)
{
    if (!hashes || n == 0 || n > ((size_t)1 << NUTROOT_MAX_TREE_DEPTH) ||
        index >= n)
        return 0;
    unsigned char target[32];
    memcpy(target, hashes + index * 32, 32);
    qsort(hashes, n, 32, cmp_hash32);
    /* Equal hashes are interchangeable under sorted-pair hashing, so the
     * first match is enough. */
    size_t pos = n;
    for (size_t i = 0; i < n; i++) {
        if (memcmp(hashes + i * 32, target, 32) == 0) {
            pos = i;
            break;
        }
    }
    if (pos == n)
        return 0;
    size_t plen = 0;
    int ok = 1;
    while (n > 1) {
        int odd = (n % 2) == 1;
        if (odd && pos == n - 1) {
            /* Promoted unpaired: no sibling at this level. */
            pos = n / 2;
        } else {
            const unsigned char *sib = (pos % 2 == 0)
                                           ? hashes + (pos + 1) * 32
                                           : hashes + (pos - 1) * 32;
            memcpy(path + plen * 32, sib, 32);
            plen++;
            pos /= 2;
        }
        n = fold_level(hashes, n, &ok);
    }
    *path_len = plen;
    return ok;
}

int nutroot_root_from_path(const unsigned char leaf_hash[32],
                           const unsigned char *path, size_t path_len,
                           unsigned char root[32])
{
    if (path_len > NUTROOT_MAX_TREE_DEPTH)
        return 0;
    unsigned char acc[32];
    memcpy(acc, leaf_hash, 32);
    for (size_t i = 0; i < path_len; i++) {
        if (!branch_hash(acc, path + i * 32, acc))
            return 0;
    }
    memcpy(root, acc, 32);
    return 1;
}

/* ----------------------------------------------------------------- tweak */

int nutroot_tweak_scalar(const unsigned char K33[33],
                         const unsigned char *root, unsigned char t32[32])
{
    if (!tagged_hash2(TWEAK_TAG, K33, 33, root, root ? 32 : 0, t32))
        return 0;
    /* Reduce mod the group order, never rejected: any 256-bit value is
     * below 2*order, so one conditional subtraction suffices. */
    if (memcmp(t32, ORDER_BE, 32) >= 0) {
        int borrow = 0;
        for (int i = 31; i >= 0; i--) {
            int d = (int)t32[i] - (int)ORDER_BE[i] - borrow;
            borrow = d < 0;
            t32[i] = (unsigned char)(d & 0xff);
        }
    }
    return 1;
}

static int is_zero32(const unsigned char b[32])
{
    unsigned char acc = 0;
    for (int i = 0; i < 32; i++)
        acc |= b[i];
    return acc == 0;
}

int nutroot_verify_commitments(const secp256k1_context *ctx,size_t n,
 const unsigned char *points,const unsigned char *keys,const unsigned char *const *roots) {
    if(!n)return 1;
    if(!ctx||!points||!keys||!roots||n>SIZE_MAX/33)return 0;
    for(size_t offset=0;offset<n;) {
        size_t count=n-offset<32?n-offset:32;
        size_t scratch_bytes=secp256k1_nucula_tweak_scratch_size(count);
        unsigned char *memory=count>=3?malloc(32*count+scratch_bytes):NULL;
        int ok=1;
        if(memory) {
            for(size_t i=0;i<count&&ok;i++)ok=nutroot_tweak_scalar(keys+33*(offset+i),roots[offset+i],memory+32*i);
            ok=ok&&secp256k1_nucula_verify_tweaks(ctx,count,points+33*offset,keys+33*offset,memory,memory+32*count,scratch_bytes);
            free(memory);
        } else {
            for(size_t i=0;i<count&&ok;i++) {
                unsigned char expected[33];
                ok=nutroot_tweak_pubkey(ctx,keys+33*(offset+i),roots[offset+i],expected)&&!memcmp(expected,points+33*(offset+i),33);
                if((i&3)==3)maybe_yield();
            }
        }
        if(!ok)return 0;
        offset+=count;maybe_yield();
    }
    return 1;
}

int nutroot_tweak_pubkey(const secp256k1_context *ctx,
                         const unsigned char K33[33],
                         const unsigned char *root, unsigned char P33[33])
{
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(ctx, &pk, K33, 33))
        return 0;
    unsigned char t[32];
    if (!nutroot_tweak_scalar(K33, root, t))
        return 0;
    /* A zero tweak names the internal key itself rather than failing on a
     * zero scalar. */
    if (is_zero32(t)) {
        memcpy(P33, K33, 33);
        return 1;
    }
    if (!secp256k1_ec_pubkey_tweak_add((secp256k1_context *)ctx, &pk, t))
        return 0;
    size_t len = 33;
    return secp256k1_ec_pubkey_serialize(ctx, P33, &len, &pk,
                                         SECP256K1_EC_COMPRESSED) && len == 33;
}

int nutroot_tweak_seckey(const secp256k1_context *ctx,
                         unsigned char sk32[32], const unsigned char *root)
{
    secp256k1_pubkey pk;
    unsigned char K33[33];
    size_t len = 33;
    if (!secp256k1_ec_pubkey_create((secp256k1_context *)ctx, &pk, sk32) ||
        !secp256k1_ec_pubkey_serialize(ctx, K33, &len, &pk,
                                       SECP256K1_EC_COMPRESSED))
        return 0;
    unsigned char t[32];
    if (!nutroot_tweak_scalar(K33, root, t))
        return 0;
    if (is_zero32(t))
        return 1;
    return secp256k1_ec_seckey_tweak_add((secp256k1_context *)ctx, sk32, t);
}

/* ---------------------------------------------- transaction transcript */

static int sha_update(mbedtls_sha256_context *sha,
                      const unsigned char *data, size_t len)
{
    return mbedtls_sha256_update(sha, data, len) == 0;
}

static int sha_tlv(mbedtls_sha256_context *sha, uint8_t type,
                   const unsigned char *value, size_t len)
{
    unsigned char hdr[3];
    if (len > 0xffff)
        return 0;
    tlv_header(hdr, type, len);
    return sha_update(sha, hdr, 3) && (len == 0 || sha_update(sha, value, len));
}

/* Field lengths of a container's value, for the outer TLV header. */
static size_t amount_record_len(uint64_t amount)
{
    unsigned char tmp[8];
    return 3 + minimal_be(amount, tmp);
}

static int sha_amount(mbedtls_sha256_context *sha, uint64_t amount)
{
    unsigned char amt[8];
    size_t alen = minimal_be(amount, amt);
    return sha_tlv(sha, 0x01, amt, alen);
}

static int sha_proof_input(mbedtls_sha256_context *sha, const nutroot_input_t *p)
{
    if (!p || !p->keyset_id || !p->secret || !p->C || !p->secret_len ||
        p->keyset_id_len > 0xffff || p->secret_len > 0xffff || p->C_len > 0xffff) return 0;
    size_t len = amount_record_len(p->amount) + 9 + p->keyset_id_len + p->secret_len + p->C_len;
    if (len > 0xffff) return 0;
    unsigned char hdr[3]; tlv_header(hdr, CONTAINER_PROOF_INPUT, len);
    return sha_update(sha, hdr, 3) && sha_amount(sha, p->amount) &&
           sha_tlv(sha, 0x02, p->keyset_id, p->keyset_id_len) &&
           sha_tlv(sha, 0x03, p->secret, p->secret_len) && sha_tlv(sha, 0x04, p->C, p->C_len);
}

static int tx_digest(const nutroot_tx_t *tx, unsigned char digest[32], int legacy)

{
    if (!tx || (tx->n_proof_inputs && !tx->proof_inputs) ||
        (tx->n_blinded_outputs && !tx->blinded_outputs) ||
        (tx->n_mint_quote_inputs && !tx->mint_quote_inputs) ||
        (tx->n_melt_quote_outputs && !tx->melt_quote_outputs)) return 0;
    if (tx->n_proof_inputs == 0 && tx->n_mint_quote_inputs == 0)
        return 0;
    if (tx->n_blinded_outputs == 0 && tx->n_melt_quote_outputs == 0)
        return 0;

    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    int ok = mbedtls_sha256_starts(&sha, 0) == 0 &&
             (!legacy || sha_update(&sha, (const unsigned char *)TX_TAG, strlen(TX_TAG)));

    for (size_t i = 0; ok && i < tx->n_proof_inputs; i++)
        ok = sha_proof_input(&sha, &tx->proof_inputs[i]);
    for (size_t i = 0; ok && i < tx->n_mint_quote_inputs; i++) {
        const nutroot_quote_t *q = &tx->mint_quote_inputs[i];
        size_t qlen = q->quote_id ? strlen(q->quote_id) : 0;
        if (qlen == 0 || qlen > 0xffff) {
            ok = 0;
            break;
        }
        size_t vlen = amount_record_len(q->amount) + 3 + qlen;
        unsigned char hdr[3];
        tlv_header(hdr, CONTAINER_MINT_QUOTE_IN, vlen);
        ok = vlen <= 0xffff && sha_update(&sha, hdr, 3) &&
             sha_amount(&sha, q->amount) &&
             sha_tlv(&sha, 0x02, (const unsigned char *)q->quote_id, qlen);
    }
    for (size_t i = 0; ok && i < tx->n_blinded_outputs; i++) {
        const nutroot_output_t *o = &tx->blinded_outputs[i];
        if (o->keyset_id_len > 0xffff || o->B_len > 0xffff || !o->keyset_id || !o->B_) { ok = 0; break; }
        size_t vlen = amount_record_len(o->amount) + 3 + o->keyset_id_len +
                      3 + o->B_len;
        unsigned char hdr[3];
        if (vlen > 0xffff) {
            ok = 0;
            break;
        }
        tlv_header(hdr, CONTAINER_BLINDED_OUTPUT, vlen);
        ok = sha_update(&sha, hdr, 3) &&
             sha_amount(&sha, o->amount) &&
             sha_tlv(&sha, 0x02, o->keyset_id, o->keyset_id_len) &&
             sha_tlv(&sha, 0x03, o->B_, o->B_len);
    }
    for (size_t i = 0; ok && i < tx->n_melt_quote_outputs; i++) {
        const nutroot_quote_t *q = &tx->melt_quote_outputs[i];
        size_t qlen = q->quote_id ? strlen(q->quote_id) : 0;
        if (qlen == 0 || qlen > 0xffff) {
            ok = 0;
            break;
        }
        size_t vlen = amount_record_len(q->amount) + 3 + qlen;
        unsigned char hdr[3];
        tlv_header(hdr, CONTAINER_MELT_QUOTE_OUT, vlen);
        ok = vlen <= 0xffff && sha_update(&sha, hdr, 3) &&
             sha_amount(&sha, q->amount) &&
             sha_tlv(&sha, 0x02, (const unsigned char *)q->quote_id, qlen);
    }

    ok = ok && mbedtls_sha256_finish(&sha, digest) == 0;
    mbedtls_sha256_free(&sha);
    return ok;
}

int nutroot_tx_digest(const nutroot_tx_t *tx, unsigned char digest[32])
{ return tx_digest(tx, digest, 0); }
int nutroot_legacy_tx_digest(const nutroot_tx_t *tx, unsigned char digest[32])
{ return tx_digest(tx, digest, 1); }

int nutroot_input_digest(const unsigned char transaction[32], const nutroot_input_t *input,
                         unsigned char digest[32])
{
    unsigned char id[32];
    mbedtls_sha256_context sha; mbedtls_sha256_init(&sha);
    int ok = mbedtls_sha256_starts(&sha, 0) == 0 && sha_proof_input(&sha, input) &&
             mbedtls_sha256_finish(&sha, id) == 0;
    mbedtls_sha256_free(&sha);
    return ok && tagged_hash2("Cashu_TransactionInput", transaction, 32, id, 32, digest);
}
int nutroot_quote_input_digest(const unsigned char transaction[32], const nutroot_quote_t *input,
                               unsigned char digest[32])
{
    if (!input || !input->quote_id) return 0;
    size_t len = strlen(input->quote_id), size = amount_record_len(input->amount) + 3;
    if (!len || len > 0xffff-size) return 0;
    unsigned char hdr[3], id[32]; tlv_header(hdr, CONTAINER_MINT_QUOTE_IN, size+len);
    mbedtls_sha256_context sha; mbedtls_sha256_init(&sha);
    int ok = mbedtls_sha256_starts(&sha, 0) == 0 && sha_update(&sha, hdr, 3) &&
             sha_amount(&sha, input->amount) && sha_tlv(&sha, 2, (const unsigned char *)input->quote_id, len) &&
             mbedtls_sha256_finish(&sha, id) == 0;
    mbedtls_sha256_free(&sha);
    return ok && tagged_hash2("Cashu_TransactionInput", transaction, 32, id, 32, digest);
}

/* --------------------------------------------------------- verification */

/* A v3 point secret: a keyset id versioned >= 0x02 and a secret that is a
 * valid 33-byte compressed point. keyset ids arrive as raw bytes (hex ids
 * decoded by the caller), matching nutshell's is_nutroot_point_secret. */
static int is_point_secret(const secp256k1_context *ctx,
                           const nutroot_input_t *in)
{
    if (in->keyset_id_len == 0 || in->keyset_id[0] < 0x02)
        return 0;
    if (in->secret_len != NUTROOT_POINT_LEN ||
        (in->secret[0] != 0x02 && in->secret[0] != 0x03))
        return 0;
    secp256k1_pubkey pk;
    return secp256k1_ec_pubkey_parse(ctx, &pk, in->secret, 33);
}

/* Hex string of arbitrary even length into a bounded buffer. */
static int hex_field(const char *hex, unsigned char *out, size_t max_len,
                     size_t *out_len)
{
    if (!hex)
        return 0;
    size_t hlen = strlen(hex);
    if (hlen == 0 || hlen % 2 != 0 || hlen / 2 > max_len)
        return 0;
    if (!hex_to_bytes(hex, out, hlen / 2))
        return 0;
    *out_len = hlen / 2;
    return 1;
}

static const char *json_string(const cJSON *obj, const char *key)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!item || !cJSON_IsString(item))
        return NULL;
    return item->valuestring;
}

/* Verify one BIP-340 signature hex against an x-only key; malformed hex is
 * a non-match, not an abort (mirrors nutshell's try/continue). */
void nutroot_set_optimizations(unsigned flags) { optimization_flags = flags & 127; }
unsigned nutroot_optimizations(void) { return optimization_flags; }

static int sig_matches(const secp256k1_context *ctx,
                       const secp256k1_xonly_pubkey *xonly,
                       const char *sig_hex, const unsigned char digest[32])
{
    unsigned char sig[64];
    if (!sig_hex || strlen(sig_hex) != 128 || !hex_to_bytes(sig_hex, sig, 64))
        return 0;
    nutroot_stat_sig_verifies++;
    return secp256k1_schnorrsig_verify(ctx, sig, digest, 32, xonly);
}

/* -1 asks the caller to use individual verification (not enough memory or
 * too few signatures); 0/1 are a completed cryptographic decision. */
static int signature_batch(const secp256k1_context *ctx, size_t n,
                            const unsigned char *sigs, const unsigned char *messages,
                            const unsigned char *keys)
{
    if (n < 2 || ((optimization_flags & 64) && n < 3)) return -1;
    unsigned algorithm = (optimization_flags & 32) ? 1 : 0;
    int adaptive=!!(optimization_flags & 64);
    if(!adaptive&&n>32)return -1;
    for(size_t done=0;done<n;) {
        size_t count=n-done<32?n-done:32,bytes=0;void *scratch=NULL;
        while(count>=2 && !(adaptive&&count<3)) {
            bytes=secp256k1_nucula_batch_scratch_size(count,algorithm);
            if(bytes)scratch=malloc(bytes);
            if(scratch||!adaptive)break;
            count=(count+1)/2;
        }
        if(scratch) {
            nutroot_stat_batch_verifies++;
            int ok=secp256k1_nucula_verify_batch(ctx,count,sigs+64*done,messages+32*done,keys+32*done,scratch,bytes,algorithm);
            free(scratch);if(!ok)return 0;done+=count;
        } else {
            if(!adaptive)return -1;
            secp256k1_xonly_pubkey key;
            nutroot_stat_sig_verifies++;
            if(!secp256k1_xonly_pubkey_parse(ctx,&key,keys+32*done)||
               !secp256k1_schnorrsig_verify(ctx,sigs+64*done,messages+32*done,32,&key))return 0;
            done++;
        }
        maybe_yield();
    }
    return 1;
}

static int satisfy_threshold(const secp256k1_context *ctx, const nutroot_leaf_t *leaf,
                             const cJSON *sigs, const unsigned char digest[32],
                             const secp256k1_xonly_pubkey *parsed_keys)
{
    int n = cJSON_GetArraySize(sigs);
    struct decoded_signature { unsigned char bytes[64]; int usable; };
    struct decoded_signature *decoded = calloc((size_t)n, sizeof(*decoded));
    if (!decoded) return 0;
    int ok = 0, satisfied = 0, attempts = 0;
    /* Validate all mandatory JSON types before an early success. Invalid hex
     * remains a non-matching signature, as in the historical implementation. */
    const cJSON *entry = sigs->child;
    for (int i = 0; i < n; i++, entry = entry->next) {
        if (!cJSON_IsString(entry)) goto done;
        decoded[i].usable = strlen(entry->valuestring) == 128 &&
                             hex_to_bytes(entry->valuestring, decoded[i].bytes, 64);
        for (int j = 0; j < i && decoded[i].usable; j++)
            if (decoded[j].usable && !memcmp(decoded[j].bytes, decoded[i].bytes, 64))
                decoded[i].usable = 0;
    }
    if ((optimization_flags & 16) && leaf->n > 1 && n >= leaf->n) {
        size_t count = leaf->n;
        unsigned char *candidate = malloc(count * 128);
        if (candidate) {
            int complete = 1;
            for (size_t i = 0; i < count; i++) {
                complete &= decoded[i].usable;
                memcpy(candidate+64*i, decoded[i].bytes, 64);
                memcpy(candidate+64*count+32*i, digest, 32);
                memcpy(candidate+96*count+32*i, leaf->keys+33*i+1, 32);
            }
            int matched = complete ? signature_batch(ctx, count, candidate,
                                  candidate+64*count, candidate+96*count) : -1;
            free(candidate);
            if (matched == 1) { ok = 1; goto done; }
        }
    }
    for (int k = 0; k < leaf->num_keys; k++) {
        secp256k1_xonly_pubkey key;
        if (parsed_keys) key = parsed_keys[k];
        else if (!secp256k1_xonly_pubkey_parse(ctx, &key, leaf->keys + 33*k + 1)) goto done;
        int preferred = (optimization_flags & 2) && k < n ? k : -1;
        for (int attempt = -1; attempt < n; attempt++) {
            int index = attempt < 0 ? preferred : attempt;
            if (index < 0 || (attempt >= 0 && index == preferred) || !decoded[index].usable)
                continue;
            if (++attempts % 4 == 0) maybe_yield();
            nutroot_stat_sig_verifies++;
            if (secp256k1_schnorrsig_verify(ctx, decoded[index].bytes, digest, 32, &key)) {
                if (++satisfied >= leaf->n) { ok = 1; goto done; }
                break;
            }
        }
        if (satisfied + leaf->num_keys - k - 1 < leaf->n) goto done;
    }
done:
    free(decoded);
    return ok;
}

/* Script path: commitment (leaf -> root -> tweak -> P), then evaluate the
 * revealed leaf. Check order mirrors nutshell's verify_script_path_spend. */
static int verify_script_path(const secp256k1_context *ctx,
                              const nutroot_input_t *in,
                              const cJSON *witness,
                              const unsigned char digest[32], int64_t now)
{
    const char *leaf_hex = json_string(witness, "leaf");
    const cJSON *control = cJSON_GetObjectItemCaseSensitive(witness, "control");
    const cJSON *sigs = cJSON_GetObjectItemCaseSensitive(witness, "signatures");
    if (!leaf_hex || !control || !cJSON_IsObject(control) ||
        !sigs || !cJSON_IsArray(sigs) || cJSON_GetArraySize(sigs) < 1)
        return 0;

    /* Control block: internal key and up to depth-many 32-byte siblings. */
    unsigned char K33[33];
    size_t klen;
    if (!hex_field(json_string(control, "K"), K33, 33, &klen) || klen != 33)
        return 0;
    const cJSON *path_arr = cJSON_GetObjectItemCaseSensitive(control, "path");
    unsigned char path[NUTROOT_MAX_TREE_DEPTH * 32];
    size_t path_len = 0;
    if (path_arr) {
        if (!cJSON_IsArray(path_arr) ||
            cJSON_GetArraySize(path_arr) > NUTROOT_MAX_TREE_DEPTH)
            return 0;
        const cJSON *el;
        cJSON_ArrayForEach(el, path_arr) {
            size_t plen;
            if (!cJSON_IsString(el) ||
                !hex_field(el->valuestring, path + path_len * 32, 32, &plen) ||
                plen != 32)
                return 0;
            path_len++;
        }
    }

    size_t leaf_hex_len = strlen(leaf_hex);
    if (leaf_hex_len % 2 != 0 || leaf_hex_len / 2 > 1 + NUTROOT_MAX_LEAF_BODY ||
        leaf_hex_len == 0)
        return 0;
    size_t leaf_len = leaf_hex_len / 2;
    unsigned char *leaf = malloc(leaf_len);
    if (!leaf || !hex_to_bytes(leaf_hex, leaf, leaf_len)) {
        free(leaf);
        return 0;
    }

    int ok = 0;
    unsigned char lh[32], root[32], P33[33];
    nutroot_leaf_t parsed;
    secp256k1_xonly_pubkey parsed_keys[15];
    secp256k1_xonly_pubkey *retained = (optimization_flags & 4) ? parsed_keys : NULL;
    if (!nutroot_leaf_hash(leaf, leaf_len, lh) ||
        !nutroot_root_from_path(lh, path, path_len, root) ||
        !nutroot_tweak_pubkey(ctx, K33, root, P33) ||
        memcmp(P33, in->secret, 33) != 0)
        goto out;
    if (!leaf_parse(ctx, leaf, leaf_len, &parsed, retained))
        goto out;

    if (parsed.type == NUTROOT_LEAF_AFTER && now < parsed.time)
        goto out;
    if (parsed.type == NUTROOT_LEAF_HASHLOCK) {
        unsigned char preimage[32], ph[32];
        size_t pre_len;
        if (!hex_field(json_string(witness, "preimage"), preimage, 32,
                       &pre_len))
            goto out;
        if (mbedtls_sha256(preimage, pre_len, ph, 0) != 0 ||
            memcmp(ph, parsed.hash, 32) != 0)
            goto out;
    }

    /* Thresholds count satisfied keys, so signatures beyond the leaf's key
     * count can never verify and reject outright. */
    int n_sigs = cJSON_GetArraySize(sigs);
    if (n_sigs > parsed.num_keys)
        goto out;
    if (optimization_flags & 1) {
        ok = satisfy_threshold(ctx, &parsed, sigs, digest, retained);
        goto out;
    }
    /* Every leaf key is tried (no early exit at n satisfied), matching
     * nutshell's loop exactly so schnorr-verify counts — and thus bench
     * numbers — compare 1:1. */
    int satisfied = 0, verifies = 0;
    for (uint8_t k = 0; k < parsed.num_keys; k++) {
        secp256k1_xonly_pubkey xonly;
        if (!secp256k1_xonly_pubkey_parse(ctx, &xonly, parsed.keys + k * 33 + 1))
            goto out;
        for (int s = 0; s < n_sigs; s++) {
            const cJSON *sig = cJSON_GetArrayItem(sigs, s);
            if (!cJSON_IsString(sig))
                goto out;
            /* Exact duplicates count once (nutshell dedups the list). */
            int dup = 0;
            for (int t = 0; t < s && !dup; t++) {
                const cJSON *prev = cJSON_GetArrayItem(sigs, t);
                dup = cJSON_IsString(prev) &&
                      strcmp(prev->valuestring, sig->valuestring) == 0;
            }
            if (dup)
                continue;
            if (++verifies % 4 == 0)
                maybe_yield();
            if (sig_matches(ctx, &xonly, sig->valuestring, digest)) {
                satisfied++;
                break;
            }
        }
    }
    ok = satisfied >= parsed.n;
out:
    free(leaf);
    return ok;
}

static int keypath_batch(const secp256k1_context *ctx, const nutroot_tx_t *tx,
                         const unsigned char transaction[32], int legacy)
{
    if (tx->n_proof_inputs < 2 || tx->n_proof_inputs > ((optimization_flags & 64)?128u:16u)) return -1;
    size_t capacity = tx->n_proof_inputs, used = 0;
    unsigned char *data = malloc(capacity*128);
    if (!data) return -1;
    unsigned char *sigs = data, *messages = data+64*capacity, *keys = data+96*capacity;
    int result = -1;
    for (size_t i = 0; i < capacity; i++) {
        const nutroot_input_t *in = &tx->proof_inputs[i];
        if (legacy ? !is_point_secret(ctx, in) : in->keyset_id[0] < 2) continue;
        if (in->secret_len != 33 || (in->secret[0] != 2 && in->secret[0] != 3) ||
            !in->witness || strlen(in->witness) > NUTROOT_MAX_WITNESS_LEN) { result = 0; goto done; }
        cJSON *witness = cJSON_ParseWithOpts(in->witness, NULL, 1);
        if (!witness || !cJSON_IsObject(witness)) { cJSON_Delete(witness); result = 0; goto done; }
        if (cJSON_GetObjectItemCaseSensitive(witness, "leaf") ||
            cJSON_GetObjectItemCaseSensitive(witness, "control")) { cJSON_Delete(witness); goto done; }
        const cJSON *array = cJSON_GetObjectItemCaseSensitive(witness, "signatures");
        const cJSON *sig = cJSON_GetArrayItem(array, 0);
        int ok = cJSON_IsArray(array) && cJSON_GetArraySize(array) == 1 &&
                 cJSON_IsString(sig) && strlen(sig->valuestring) == 128 &&
                 hex_to_bytes(sig->valuestring, sigs+64*used, 64);
        cJSON_Delete(witness);
        if (!ok) { result = 0; goto done; }
        memcpy(keys+32*used, in->secret+1, 32);
        if (legacy) memcpy(messages+32*used, transaction, 32);
        else if (!nutroot_input_digest(transaction, in, messages+32*used)) { result = 0; goto done; }
        used++;
    }
    result = signature_batch(ctx, used, sigs, messages, keys);
done:
    free(data);
    return result;
}

static int verify_transaction(const secp256k1_context *ctx,
                               const nutroot_tx_t *tx, int64_t now, int legacy)
{
    if (!tx || (tx->n_proof_inputs && !tx->proof_inputs)) return 0;
    if (!tx->n_proof_inputs) return 1;
    int any_point = 0;
    for (size_t i = 0; i < tx->n_proof_inputs; i++) {
        const nutroot_input_t *in = &tx->proof_inputs[i];
        if (!in->keyset_id || !in->keyset_id_len) return 0;
        any_point |= legacy ? is_point_secret(ctx, in) : in->keyset_id[0] >= 2;
    }
    if (!any_point) return 1;
    if (legacy && !tx->n_blinded_outputs && !tx->n_melt_quote_outputs) return 1;
    unsigned char transaction[32], digest[32];
    if (!tx_digest(tx, transaction, legacy)) return 0;
    if (optimization_flags & 16) {
        int batched = keypath_batch(ctx, tx, transaction, legacy);
        if (batched >= 0) return batched;
    }
    for (size_t i = 0; i < tx->n_proof_inputs; i++) {
        const nutroot_input_t *in = &tx->proof_inputs[i];
        if (legacy ? !is_point_secret(ctx, in) : in->keyset_id[0] < 2) continue;
        secp256k1_pubkey point;
        if (!in->secret || in->secret_len != 33 ||
            (in->secret[0] != 2 && in->secret[0] != 3) ||
            !secp256k1_ec_pubkey_parse(ctx, &point, in->secret, 33)) return 0;
        if (legacy) memcpy(digest, transaction, 32);
        else if (!nutroot_input_digest(transaction, in, digest)) return 0;
        /* Inputs sign (NUT-10): every legitimate spender of a point secret
         * can sign, so a missing witness rejects. */
        if (!in->witness || strlen(in->witness) > NUTROOT_MAX_WITNESS_LEN)
            return 0;

        cJSON *witness = cJSON_ParseWithOpts(in->witness, NULL, 1);
        if (!witness || !cJSON_IsObject(witness)) { cJSON_Delete(witness); return 0; }
        int ok;
        const cJSON *leaf = cJSON_GetObjectItemCaseSensitive(witness, "leaf");
        const cJSON *control =
            cJSON_GetObjectItemCaseSensitive(witness, "control");
        if (leaf || control) {
            /* leaf and control must be provided together. */
            ok = leaf && control &&
                 verify_script_path(ctx, in, witness, digest, now);
        } else {
            /* Key path: exactly one BIP-340 signature by the secret's key;
             * anything more is rejected, not skipped. */
            const cJSON *sigs =
                cJSON_GetObjectItemCaseSensitive(witness, "signatures");
            const cJSON *sig0 = sigs ? cJSON_GetArrayItem(sigs, 0) : NULL;
            secp256k1_xonly_pubkey xonly;
            ok = sigs && cJSON_IsArray(sigs) && cJSON_GetArraySize(sigs) == 1 &&
                 sig0 && cJSON_IsString(sig0) &&
                 secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly, NULL, &point) &&
                 sig_matches(ctx, &xonly, sig0->valuestring, digest);
        }
        cJSON_Delete(witness);
        if (!ok)
            return 0;
        maybe_yield();
    }
    return 1;
}

int nutroot_verify_transaction(const secp256k1_context *ctx, const nutroot_tx_t *tx, int64_t now)
{ return verify_transaction(ctx, tx, now, 0); }
int nutroot_legacy_verify_transaction(const secp256k1_context *ctx, const nutroot_tx_t *tx, int64_t now)
{ return verify_transaction(ctx, tx, now, 1); }

static int ecdh_raw_x(unsigned char *out, const unsigned char *x, const unsigned char *y, void *data)
{ (void)y; (void)data; memcpy(out, x, 32); return 1; }
int nutroot_ecdh_x(const secp256k1_context *ctx, const unsigned char sk[32],
                   const unsigned char peer[33], unsigned char shared_x[32])
{
    secp256k1_pubkey point;
    if (!sk || !peer || (peer[0] != 2 && peer[0] != 3) ||
        !secp256k1_ec_pubkey_parse(ctx, &point, peer, 33)) return 0;
    return secp256k1_ecdh(ctx, shared_x, &point, sk, ecdh_raw_x, NULL);
}
int nutroot_p2bk_scalar(const secp256k1_context *ctx, const unsigned char shared_x[32],
                        unsigned slot, unsigned char scalar[32])
{
    static const char dst[] = "Cashu_P2BK_v1";
    unsigned char message[sizeof(dst)-1+32+2];
    if (slot > 255) return 0;
    memcpy(message, dst, sizeof(dst)-1);
    memcpy(message+sizeof(dst)-1, shared_x, 32);
    message[sizeof(message)-2] = (unsigned char)slot;
    message[sizeof(message)-1] = 0xff;
    int ok = mbedtls_sha256(message, sizeof(message)-1, scalar, 0) == 0;
    if (ok && !secp256k1_ec_seckey_verify(ctx, scalar))
        ok = mbedtls_sha256(message, sizeof(message), scalar, 0) == 0 && secp256k1_ec_seckey_verify(ctx, scalar);
    volatile unsigned char *wipe = message;
    for (size_t i = 0; i < sizeof(message); i++) wipe[i] = 0;
    return ok;
}

int nutroot_sign_digest(const secp256k1_context *ctx,
                        const unsigned char priv32[32],
                        const unsigned char digest[32],
                        unsigned char sig64[64])
{
    /* Zero aux randomness: deterministic, matching the shared vectors
     * (nutshell signs with aux = 32 zero bytes). */
    static const unsigned char aux[32] = {0};
    secp256k1_keypair kp;
    if (!secp256k1_keypair_create((secp256k1_context *)ctx, &kp, priv32))
        return 0;
    int ok = secp256k1_schnorrsig_sign32((secp256k1_context *)ctx, sig64, digest, &kp, aux);
    volatile unsigned char *wipe = (volatile unsigned char *)&kp;
    for (size_t i = 0; i < sizeof(kp); i++) wipe[i] = 0;
    return ok;
}
