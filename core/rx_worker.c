#include "rx_worker.h"
#include "pool.h"

#ifdef _WIN32
#include <windows.h>

static DWORD WINAPI rx_worker_thread(LPVOID arg)
{
    rx_worker_t* w = (rx_worker_t*)arg;

    while (w->running)
    {
        packet_buf_t* p = (packet_buf_t*)ring_pop(w->ring);

        if (p)
        {
            w->handler(p, w->ctx);
            pool_return(p);
        }
        Sleep(1);
    }
    return 0;
}

int rx_worker_start(rx_worker_t* w,
                    spsc_ring_t* ring,
                    rx_handler_fn handler,
                    void* ctx)
{
    w->ring = ring;
    w->handler = handler;
    w->ctx = ctx;
    w->running = 1;

    w->thread = CreateThread(NULL, 0,
                             rx_worker_thread,
                             w, 0, NULL);

    return (w->thread != NULL) ? 0 : -1;
}

void rx_worker_stop(rx_worker_t* w)
{
    w->running = 0;
    WaitForSingleObject(w->thread, INFINITE);
    CloseHandle(w->thread);
}

#endif