#include "rx_thread.h"
#include "io_poll.h"

//thread function
#ifdef _WIN32
static DWORD WINAPI rx_thread_fn(LPVOID arg)
{
    rx_thread_t* ctx = (rx_thread_t*) arg;

    io_poll_t poll;
    io_event_t events[64];

    io_poll_init(&poll);

    io_poll_add(&poll, ctx->sock, IO_EVENT_READ);

    while (ctx->running)
    {
        int n = io_poll_wait(&poll, events, 64, 1000);

        if (n <= 0)
            continue;

        for (int i = 0; i < n; i++)
        {
            if (events[i].revents & IO_EVENT_READ)
            {
                while (udp_rx_once(ctx->sock, ctx->rx_ring) == 0)
                {
                    // drain all packets
                }
            }
        }
    }

    io_poll_destroy(&poll);
    return 0;
}
#endif

int rx_thread_start(rx_thread_t* ctx, udp_socket_t* sock, spsc_ring_t* ring)
{
    ctx->sock = sock;
    ctx->rx_ring = ring;
    ctx->running = 1;

#ifdef _WIN32
    ctx->thread = CreateThread(NULL, 0, rx_thread_fn, ctx, 0, NULL);
    if(!ctx->running){
        return -1;
    }
#endif

    return 0;
}

void rx_thread_stop(rx_thread_t* ctx){
    ctx->running = 0;

#ifdef _WIN32
    WaitForSingleObject(ctx->thread, INFINITE);
    CloseHandle(ctx->thread);
#endif
}

