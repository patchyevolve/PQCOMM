#include "tx_thread.h"
#include "pool.h"
#ifndef _WIN32
#include <pthread.h>
#include <unistd.h>
#endif

#ifdef _WIN32
#include "io_poll.h"

static DWORD WINAPI tx_thread_fn(LPVOID arg)
{
    tx_thread_t* ctx = (tx_thread_t*) arg;

    io_poll_t poll;
    io_event_t events[64];

    io_poll_init(&poll);
    io_poll_add(&poll, ctx->sock, IO_EVENT_WRITE);

    while (ctx->running)
    {
        packet_buf_t* p;

        while ((p = scheduler_next(ctx->queues)) != NULL)
        {
            udp_socket_send(ctx->sock,
                            p->data,
                            p->len,
                            p->addr,
                            p->addr_len);
            pool_return(p);
        }

        Sleep(1);
    }

    io_poll_destroy(&poll);
    return 0;
}
#else
static void* tx_thread_fn(void* arg)
{
    tx_thread_t* ctx = (tx_thread_t*) arg;

    while (ctx->running)
    {
        packet_buf_t* p;

        while ((p = scheduler_next(ctx->queues)) != NULL)
        {
            udp_socket_send(ctx->sock,
                            p->data,
                            p->len,
                            p->addr,
                            p->addr_len);
            pool_return(p);
        }

        usleep(1000);
    }

    return NULL;
}
#endif

int tx_thread_start(tx_thread_t* ctx, udp_socket_t* sock, tx_queues_t* ring)
{
    ctx->sock = sock;
    ctx->queues = ring;
    ctx->running = 1;

#ifdef _WIN32
    ctx->thread = CreateThread(NULL, 0, tx_thread_fn, ctx, 0, NULL);
    if (!ctx->thread)
    {
        return -1;
    }
#else
    if (pthread_create(&ctx->thread, NULL, tx_thread_fn, ctx) != 0) {
        return -1;
    }
#endif

    return 0;
}

void tx_thread_stop(tx_thread_t* ctx)
{
    ctx->running = 0;

#ifdef _WIN32
    WaitForSingleObject(ctx->thread, INFINITE);
    CloseHandle(ctx->thread);
#else
    pthread_join(ctx->thread, NULL);
#endif
}
