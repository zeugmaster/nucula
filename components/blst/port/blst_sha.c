/* SHA compression adapter. Only the compression function changes; blst's
 * padding, XMD expansion and protocol domain separation are untouched. */
#include "blst_mpi.h"
#if defined(ESP_PLATFORM)
#include <stdbool.h>
#include <string.h>
#include "sha/sha_core.h"
int blst_esp_sha256_compress(unsigned int h[8],const void *input,size_t blocks)
{
    uint32_t state[8],block[16];
    const unsigned char *bytes=input;
    for(unsigned i=0;i<8;i++)state[i]=__builtin_bswap32(h[i]);
    /* SHA and MPI have separate locks. SHA operations here never call MPI,
     * allocate, yield, or invoke another crypto callback. */
    esp_sha_acquire_hardware();esp_sha_set_mode(SHA2_256);
    esp_sha_write_digest_state(SHA2_256,state);
    for(size_t i=0;i<blocks;i++) {
        memcpy(block,bytes+64*i,64); /* Supports unaligned messages. */
        esp_sha_block(SHA2_256,block,false);
    }
    esp_sha_read_digest_state(SHA2_256,state);esp_sha_release_hardware();
    for(unsigned i=0;i<8;i++)h[i]=__builtin_bswap32(state[i]);
    return 1;
}
#else
int blst_esp_sha256_compress(unsigned int h[8],const void *input,size_t blocks)
{(void)h;(void)input;(void)blocks;return 0;}
#endif

int blst_esp_sha256_blocks(unsigned int h[8],const void *input,size_t blocks)
{
    if (!(blst_mpi_options() & BLST_MPI_SHA256)) return 0;
    return blst_esp_sha256_compress(h,input,blocks);
}
