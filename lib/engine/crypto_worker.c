#include "crypto_worker.h"
#include "ring.h"
#include "pool.h"
#include "packet_parse.h"
#include "session_enc.h"
#include "seq_check.h"
#include "monitor.h"
#include "platform.h"
#include <stdlib.h>
#include <stdio.h>

static spsc_ring_t g_crypto_ring;
static spsc_ring_t g_result_ring;

#ifdef _WIN32
static HANDLE g_crypto_thread;
#else
static pthread_t g_crypto_thread;
#endif

static volatile int g_crypto_running = 0;

#ifdef _WIN32
static DWORD WINAPI crypto_loop(LPVOID arg)
#else
static void* crypto_loop(void* arg)
#endif
{
    (void)arg;
    while (g_crypto_running) {
        crypto_job_t* job = (crypto_job_t*)ring_pop(&g_crypto_ring);
        if (!job) {
            platform_sleep_ms(1);
            continue;
        }

        monitor_mark_alive("crypto");

        if (job->type == CRYPTO_JOB_DECRYPT || job->type == CRYPTO_JOB_FEC_DECRYPT) {
            packet_view_t view = { 0 };
            if (packet_parse(job->p, &view) == 0 && view.encrypted) {
                session_lock_keys(job->sess);
                int ret = session_enc_check(&view, job->sess);
                session_unlock_keys(job->sess);
                if (ret == 0) {
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
                session_lock_keys(job->sess);
                session_enc_apply(job->p, &view, job->sess);
                session_unlock_keys(job->sess);
            }
            ring_push(&g_result_ring, job->p);
        }

        free(job);
    }
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

int crypto_worker_start(void)
{
    if (g_crypto_running) return 0;
    ring_init(&g_crypto_ring);
    ring_init(&g_result_ring);
    g_crypto_running = 1;

#ifdef _WIN32
    g_crypto_thread = CreateThread(NULL, 0, crypto_loop, NULL, 0, NULL);
    if (!g_crypto_thread) {
        g_crypto_running = 0;
        return -1;
    }
#else
    if (pthread_create(&g_crypto_thread, NULL, crypto_loop, NULL) != 0) {
        g_crypto_running = 0;
        return -1;
    }
#endif
    return 0;
}

void crypto_worker_stop(void)
{
    g_crypto_running = 0;
#ifdef _WIN32
    if (g_crypto_thread) {
        WaitForSingleObject(g_crypto_thread, 1000);
        CloseHandle(g_crypto_thread);
        g_crypto_thread = NULL;
    }
#else
    pthread_join(g_crypto_thread, NULL);
#endif
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
