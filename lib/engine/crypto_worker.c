#include "crypto_worker.h"
#include "ring.h"
#include "pool.h"
#include "packet_parse.h"
#include "session_enc.h"
#include "seq_check.h"
#include "monitor.h"
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <stdio.h>

static spsc_ring_t g_crypto_ring;
static spsc_ring_t g_result_ring;
static pthread_t g_crypto_thread;
static volatile int g_crypto_running = 0;

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static void* crypto_loop(void* arg)
{
    (void)arg;
    while (g_crypto_running) {
        crypto_job_t* job = (crypto_job_t*)ring_pop(&g_crypto_ring);
        if (!job) {
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };
            nanosleep(&ts, NULL);
            continue;
        }

        monitor_mark_alive("crypto");

        if (job->type == CRYPTO_JOB_DECRYPT || job->type == CRYPTO_JOB_FEC_DECRYPT) {
            packet_view_t view = { 0 };
            if (packet_parse(job->p, &view) == 0 && view.encrypted) {
                if (session_enc_check(&view, job->sess) == 0) {
                    ring_push(&g_result_ring, job->p);
                } else {
                    pool_return(job->p);
                }
            } else {
                pool_return(job->p);
            }
        } else if (job->type == CRYPTO_JOB_ENCRYPT) {
            packet_view_t view = { 0 };
            if (packet_parse(job->p, &view) == 0) {
                session_enc_apply(job->p, &view, job->sess);
            }
            ring_push(&g_result_ring, job->p);
        }

        free(job);
    }
    return NULL;
}

int crypto_worker_start(void)
{
    if (g_crypto_running) return 0;
    ring_init(&g_crypto_ring);
    ring_init(&g_result_ring);
    g_crypto_running = 1;

    if (pthread_create(&g_crypto_thread, NULL, crypto_loop, NULL) != 0) {
        g_crypto_running = 0;
        return -1;
    }
    return 0;
}

void crypto_worker_stop(void)
{
    g_crypto_running = 0;
}

int crypto_worker_push(crypto_job_t* job)
{
    if (!job) return -1;
    return ring_push(&g_crypto_ring, job);
}

int crypto_worker_pop_result(packet_buf_t** p)
{
    if (!p) return -1;
    *p = (packet_buf_t*)ring_pop(&g_result_ring);
    return *p ? 1 : 0;
}
