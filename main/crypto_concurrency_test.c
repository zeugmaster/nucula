/* Synthetic accelerator interoperability test. Never opens network sockets,
 * accesses NVS, or uses wallet keys. A second task uses the actual mbedTLS
 * MPI/SHA APIs while the console runs Cashu proof verification. */
#include "crypto_bls_test.h"
#include "crypto_bls.h"
#include "hex.h"
#include <mbedtls/bignum.h>
#include <mbedtls/sha256.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/semphr.h>
#include <esp_timer.h>
#include <esp_log.h>
#include <stdlib.h>
#include <string.h>
typedef struct {
    SemaphoreHandle_t done;
    volatile int stop;
    int ok;
    unsigned operations,stack_min;
    int64_t maximum_wait;
    int64_t maximum_completion_gap;
} contention_state;
static void other_crypto(void *argument) {
    contention_state *state=argument;
    mbedtls_mpi a,e,p,result;mbedtls_mpi_init(&a);mbedtls_mpi_init(&e);mbedtls_mpi_init(&p);mbedtls_mpi_init(&result);
    unsigned char expected[48],actual[48],sha[32],expected_sha[32];
    state->ok=hex_to_bytes("09f6d702f7a4d01c7eeda42b6a54955b83619dd5dd1468929dee478c4209f71dc37f295a59e4ba7e25944714aa90651d",expected,48)&&
        hex_to_bytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",expected_sha,32)&&
        !mbedtls_mpi_lset(&a,17)&&!mbedtls_mpi_lset(&e,65537)&&
        !mbedtls_mpi_read_string(&p,16,"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab");
    int64_t last_completion=esp_timer_get_time();
    while(!state->stop&&state->ok) {
        int64_t start=esp_timer_get_time();
        state->ok=!mbedtls_mpi_exp_mod(&result,&a,&e,&p,NULL)&&!mbedtls_mpi_write_binary(&result,actual,48)&&!memcmp(actual,expected,48);
        int64_t wait=esp_timer_get_time()-start;
        if(wait>state->maximum_wait)state->maximum_wait=wait;
        state->ok=state->ok&&!mbedtls_sha256((const unsigned char *)"abc",3,sha,0)&&!memcmp(sha,expected_sha,32);
        int64_t completed=esp_timer_get_time(),gap=completed-last_completion;
        if(gap>state->maximum_completion_gap)state->maximum_completion_gap=gap;
        last_completion=completed;
        state->operations++;vTaskDelay(5);
    }
    mbedtls_mpi_free(&result);mbedtls_mpi_free(&p);mbedtls_mpi_free(&e);mbedtls_mpi_free(&a);
    state->stack_min=uxTaskGetStackHighWaterMark(NULL);
    xSemaphoreGive(state->done);vTaskDelete(NULL);
}
void crypto_bls_run_contention(unsigned flags) {
    contention_state *state=calloc(1,sizeof(*state));
    if(!state){ESP_LOGE("bls_test","FAILED: contention allocation");return;}
    state->done=xSemaphoreCreateBinary();
    if(!state->done||xTaskCreate(other_crypto,"crypto_peer",8192,state,4,NULL)!=pdPASS) {
        if(state->done)vSemaphoreDelete(state->done);
        free(state);
        ESP_LOGE("bls_test","FAILED: contention task creation");return;
    }
    crypto_bls_run_scaling(flags,11,32,10,2);
    state->stop=1;xSemaphoreTake(state->done,portMAX_DELAY);
    ESP_LOGI("bls_test","contention flags=%u peer_ops=%u max_MPI_wait=%lld us peer_stack_min=%u result=%s",
             flags,state->operations,state->maximum_wait,state->stack_min,state->ok&&state->operations?"OK":"FAILED");
    ESP_LOGI("bls_test","contention max_completion_gap=%lld us (includes CPU scheduling delay)",state->maximum_completion_gap);
    vSemaphoreDelete(state->done);free(state);vTaskDelay(2);
}
